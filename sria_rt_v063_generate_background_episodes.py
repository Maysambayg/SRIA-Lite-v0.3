#!/usr/bin/env python3
"""
sria_rt_v063_generate_background_episodes.py

SRIA RT v0.6.3 - Background SRIA Candidate/Episode Generation

Purpose:
- Run the existing SRIA RT candidate/episode generation logic over the extracted
  Tier B negative-background windows from v0.6.2.
- Process each bg_###_auth.txt file independently first, preserving window and
  early/middle/late band attribution.
- Produce accepted episode JSONL files, suppressed episode JSONL files, and a
  per-window generation summary.

Boundary:
- No model loading.
- No learned-ranker scoring.
- No retraining.
- No threshold tuning.
- No redteam validation.
- No auth.txt full scan.

Typical CMD use from F:\SRIA\SRIA_RT_v01:

  py sria_rt_v063_generate_background_episodes.py --input-dir v062_background_extract_tierB --windows-summary v062_background_extract_tierB\v062_background_extract_summary.csv --out-dir v063_background_episodes_tierB --detector-module sria_rt_v033

Notes:
- This script imports the existing SRIA detector module, default sria_rt_v033.
- If a later branch is preferred, pass --detector-module sria_rt_v035, assuming
  that module exists in the same working directory.
- The first v0.6.3 pass is intentionally window-local: each background window is
  processed independently to preserve attribution and diagnose queue inflation.
"""

from __future__ import annotations

import argparse
import csv
import importlib
import json
import sys
import time
from collections import Counter
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


VERSION = "v063"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v0.6.3 background episode generation")
    p.add_argument("--input-dir", required=True, help="Directory containing bg_###_auth.txt files from v0.6.2")
    p.add_argument("--windows-summary", required=True, help="v062_background_extract_summary.csv")
    p.add_argument("--out-dir", required=True, help="Output directory for v0.6.3 episode files")
    p.add_argument("--detector-module", default="sria_rt_v033", help="Existing SRIA detector module to import, default sria_rt_v033")
    p.add_argument("--pattern", default="bg_*_auth.txt", help="Input file glob inside --input-dir")
    p.add_argument("--progress-every-lines", type=int, default=250000, help="Progress print interval per window")
    p.add_argument("--flush-every-lines", type=int, default=250000, help="Drain completed/suppressed buffers every N parsed events")
    p.add_argument("--sample-limit-lines", type=int, default=0, help="Optional per-file line limit for smoke testing; 0 means no limit")
    p.add_argument("--quiet", action="store_true", help="Reduce progress output")
    return p.parse_args()


def load_detector_api(module_name: str):
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        print(f"ERROR: failed to import detector module {module_name!r}: {exc}")
        print("Run this script from the SRIA project directory containing the detector module.")
        sys.exit(2)

    if not hasattr(module, "Config"):
        print(f"ERROR: detector module {module_name!r} does not expose Config.")
        sys.exit(2)
    if not hasattr(module, "parse_auth_line"):
        print(f"ERROR: detector module {module_name!r} does not expose parse_auth_line.")
        sys.exit(2)
    if not hasattr(module, "episode_to_dict"):
        print(f"ERROR: detector module {module_name!r} does not expose episode_to_dict.")
        sys.exit(2)

    detector_cls = None
    preferred = ["PrecisionDetectorV036", "PrecisionDetectorV035", "PrecisionDetectorV034", "PrecisionDetectorV033"]
    for name in preferred:
        if hasattr(module, name):
            detector_cls = getattr(module, name)
            break
    if detector_cls is None:
        for name in dir(module):
            if name.startswith("PrecisionDetector"):
                detector_cls = getattr(module, name)
                break
    if detector_cls is None:
        print(f"ERROR: detector module {module_name!r} does not expose a PrecisionDetector class.")
        sys.exit(2)

    summarize_episodes = getattr(module, "summarize_episodes", None)
    return module, module.Config, detector_cls, module.parse_auth_line, module.episode_to_dict, summarize_episodes


def load_windows_summary(path: Path) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            wid = row.get("window_id", "").strip()
            if not wid:
                continue
            rows[wid] = row
    if not rows:
        raise SystemExit(f"ERROR: no windows loaded from {path}")
    return rows


def int_field(row: Dict[str, Any], name: str, default: int = 0) -> int:
    try:
        v = row.get(name, default)
        if v is None or v == "":
            return default
        return int(float(v))
    except Exception:
        return default


def make_config(ConfigCls: Any):
    cfg = ConfigCls()
    # Preserve existing thresholds. Only force ranked_limit to zero if the field exists,
    # because generation should not truncate accepted episodes.
    if hasattr(cfg, "ranked_limit"):
        try:
            setattr(cfg, "ranked_limit", 0)
        except Exception:
            pass
    return cfg


def counter_to_json(c: Counter) -> str:
    return json.dumps(dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))), sort_keys=False)


def annotate_episode(ep_dict: Dict[str, Any], window_meta: Dict[str, Any]) -> Dict[str, Any]:
    wid = window_meta["window_id"]
    original_id = ep_dict.get("id")
    annotated = dict(ep_dict)
    annotated["window_id"] = wid
    annotated["tier"] = window_meta.get("tier", "")
    annotated["band"] = window_meta.get("band", "")
    annotated["window_start_time"] = window_meta.get("start_time", "")
    annotated["window_end_time"] = window_meta.get("end_time", "")
    annotated["original_episode_id"] = original_id
    annotated["background_episode_id"] = f"{wid}_{original_id}"
    annotated["generation_scope"] = "window_local_independent"
    return annotated


def drain_detector_buffers(
    detector: Any,
    episode_to_dict: Any,
    accepted_fh,
    suppressed_fh,
    window_meta: Dict[str, Any],
    totals: Dict[str, Any],
) -> None:
    completed = list(getattr(detector, "completed", []) or [])
    suppressed = list(getattr(detector, "suppressed", []) or [])

    for ep in completed:
        ep_dict = annotate_episode(episode_to_dict(ep), window_meta)
        accepted_fh.write(json.dumps(ep_dict, sort_keys=False) + "\n")
        totals["accepted_episodes"] += 1
        totals["accepted_gate_counts"][str(ep_dict.get("candidate_gate", ""))] += 1
        for sig in ep_dict.get("signals", []) or []:
            totals["accepted_signal_counts"][str(sig)] += 1

    for ep in suppressed:
        ep_dict = annotate_episode(episode_to_dict(ep), window_meta)
        suppressed_fh.write(json.dumps(ep_dict, sort_keys=False) + "\n")
        totals["suppressed_episodes"] += 1
        totals["suppressed_gate_counts"][str(ep_dict.get("candidate_gate", ""))] += 1
        reason = str(ep_dict.get("suppression_reason", ""))
        if reason:
            totals["suppression_reason_counts"][reason] += 1
        for sig in ep_dict.get("signals", []) or []:
            totals["suppressed_signal_counts"][str(sig)] += 1

    # Clear buffers so long windows do not accumulate unbounded episode objects.
    if hasattr(detector, "completed"):
        detector.completed.clear()
    if hasattr(detector, "suppressed"):
        detector.suppressed.clear()


def process_window(
    input_file: Path,
    out_dir: Path,
    window_meta: Dict[str, Any],
    ConfigCls: Any,
    DetectorCls: Any,
    parse_auth_line: Any,
    episode_to_dict: Any,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    wid = window_meta["window_id"]
    cfg = make_config(ConfigCls)
    detector = DetectorCls(cfg)

    accepted_path = out_dir / f"{wid}_episodes.jsonl"
    suppressed_path = out_dir / f"{wid}_suppressed.jsonl"
    progress_path = out_dir / f"{wid}_progress.log"

    totals: Dict[str, Any] = {
        "accepted_episodes": 0,
        "suppressed_episodes": 0,
        "accepted_gate_counts": Counter(),
        "suppressed_gate_counts": Counter(),
        "accepted_signal_counts": Counter(),
        "suppressed_signal_counts": Counter(),
        "suppression_reason_counts": Counter(),
    }

    raw_lines = 0
    parsed_events = 0
    ignored_lines = 0
    bad_lines = 0
    first_seen_time: Optional[int] = None
    last_seen_time: Optional[int] = None
    start = time.time()
    next_progress = args.progress_every_lines
    next_flush = args.flush_every_lines

    with open(input_file, "r", encoding="utf-8", errors="replace") as in_fh, \
         open(accepted_path, "w", encoding="utf-8") as accepted_fh, \
         open(suppressed_path, "w", encoding="utf-8") as suppressed_fh, \
         open(progress_path, "w", encoding="utf-8") as progress_fh:

        for line in in_fh:
            raw_lines += 1
            if args.sample_limit_lines and raw_lines > args.sample_limit_lines:
                break
            try:
                event = parse_auth_line(line)
            except Exception:
                event = None
                bad_lines += 1
            if not event:
                ignored_lines += 1
                continue

            parsed_events += 1
            ts = int(event["time"])
            first_seen_time = ts if first_seen_time is None else min(first_seen_time, ts)
            last_seen_time = ts if last_seen_time is None else max(last_seen_time, ts)
            detector.process(event)

            if args.flush_every_lines and parsed_events >= next_flush:
                drain_detector_buffers(detector, episode_to_dict, accepted_fh, suppressed_fh, window_meta, totals)
                next_flush += args.flush_every_lines

            if args.progress_every_lines and raw_lines >= next_progress:
                elapsed = max(0.001, time.time() - start)
                msg = (
                    f"[{wid}] raw_lines={raw_lines:,} parsed_events={parsed_events:,} "
                    f"accepted={totals['accepted_episodes']:,} suppressed={totals['suppressed_episodes']:,} "
                    f"time={ts} rate={raw_lines / elapsed:,.0f} lines/sec elapsed={elapsed:,.1f}s"
                )
                if not args.quiet:
                    print(msg)
                progress_fh.write(msg + "\n")
                progress_fh.flush()
                next_progress += args.progress_every_lines

        # Finalize active episodes and drain all buffers.
        try:
            detector.finish()
        except Exception as exc:
            raise RuntimeError(f"Detector finish failed for {wid}: {exc}") from exc
        drain_detector_buffers(detector, episode_to_dict, accepted_fh, suppressed_fh, window_meta, totals)

    elapsed = max(0.001, time.time() - start)
    expected = int_field(window_meta, "extracted_lines", int_field(window_meta, "expected_auth_line_count", 0))

    return {
        "window_id": wid,
        "tier": window_meta.get("tier", ""),
        "band": window_meta.get("band", ""),
        "input_file": input_file.name,
        "accepted_file": accepted_path.name,
        "suppressed_file": suppressed_path.name,
        "expected_input_lines": expected,
        "raw_lines_read": raw_lines,
        "input_delta": raw_lines - expected if expected else "",
        "parsed_success_events": parsed_events,
        "ignored_or_filtered_lines": ignored_lines,
        "bad_lines": bad_lines,
        "first_seen_time": first_seen_time if first_seen_time is not None else "",
        "last_seen_time": last_seen_time if last_seen_time is not None else "",
        "accepted_episodes": totals["accepted_episodes"],
        "suppressed_episodes": totals["suppressed_episodes"],
        "total_finalized_episodes": totals["accepted_episodes"] + totals["suppressed_episodes"],
        "accepted_per_million_parsed_events": round((totals["accepted_episodes"] / parsed_events) * 1_000_000, 6) if parsed_events else 0.0,
        "elapsed_seconds": round(elapsed, 2),
        "lines_per_second": round(raw_lines / elapsed),
        "nearest_redteam_distance": window_meta.get("nearest_redteam_distance", ""),
        "accepted_gate_counts": counter_to_json(totals["accepted_gate_counts"]),
        "suppressed_gate_counts": counter_to_json(totals["suppressed_gate_counts"]),
        "accepted_signal_counts": counter_to_json(totals["accepted_signal_counts"]),
        "suppressed_signal_counts": counter_to_json(totals["suppressed_signal_counts"]),
        "suppression_reason_counts": counter_to_json(totals["suppression_reason_counts"]),
        "generation_scope": "window_local_independent",
    }


def write_summary_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = [
        "window_id", "tier", "band", "input_file", "accepted_file", "suppressed_file",
        "expected_input_lines", "raw_lines_read", "input_delta", "parsed_success_events",
        "ignored_or_filtered_lines", "bad_lines", "first_seen_time", "last_seen_time",
        "accepted_episodes", "suppressed_episodes", "total_finalized_episodes",
        "accepted_per_million_parsed_events", "elapsed_seconds", "lines_per_second",
        "nearest_redteam_distance", "generation_scope", "accepted_gate_counts",
        "suppressed_gate_counts", "suppression_reason_counts", "accepted_signal_counts", "suppressed_signal_counts",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_report(path: Path, rows: List[Dict[str, Any]], args: argparse.Namespace, detector_module: str, started: float) -> None:
    elapsed = max(0.001, time.time() - started)
    total_raw = sum(int(r.get("raw_lines_read", 0) or 0) for r in rows)
    total_parsed = sum(int(r.get("parsed_success_events", 0) or 0) for r in rows)
    total_accepted = sum(int(r.get("accepted_episodes", 0) or 0) for r in rows)
    total_suppressed = sum(int(r.get("suppressed_episodes", 0) or 0) for r in rows)
    total_bad = sum(int(r.get("bad_lines", 0) or 0) for r in rows)

    lines: List[str] = []
    lines.append("SRIA RT v0.6.3 Background SRIA Candidate/Episode Generation")
    lines.append("=" * 80)
    lines.append(f"input_dir: {args.input_dir}")
    lines.append(f"windows_summary: {args.windows_summary}")
    lines.append(f"out_dir: {args.out_dir}")
    lines.append(f"detector_module: {detector_module}")
    lines.append("analysis_scope: existing SRIA episode generation only; no model loading, no learned ranking, no retraining")
    lines.append("generation_scope: window_local_independent")
    lines.append("caution: window-local processing preserves attribution but does not import pre-window global memory")
    lines.append("")
    lines.append("Run summary:")
    lines.append(f"  windows_processed: {len(rows):,}")
    lines.append(f"  total_raw_lines_read: {total_raw:,}")
    lines.append(f"  total_parsed_success_events: {total_parsed:,}")
    lines.append(f"  total_bad_lines: {total_bad:,}")
    lines.append(f"  total_accepted_episodes: {total_accepted:,}")
    lines.append(f"  total_suppressed_episodes: {total_suppressed:,}")
    lines.append(f"  total_finalized_episodes: {total_accepted + total_suppressed:,}")
    lines.append(f"  elapsed_seconds: {elapsed:,.2f}")
    lines.append(f"  raw_lines_per_second: {total_raw / elapsed:,.0f}")
    lines.append("")
    lines.append("Per-window summary:")
    for r in rows:
        lines.append(
            f"  {r['window_id']}: band={r['band']} raw={int(r['raw_lines_read']):,} "
            f"parsed={int(r['parsed_success_events']):,} accepted={int(r['accepted_episodes']):,} "
            f"suppressed={int(r['suppressed_episodes']):,} bad={int(r['bad_lines']):,} "
            f"nearest_redteam_distance={r.get('nearest_redteam_distance', '')}"
        )
    lines.append("")
    lines.append("Outputs:")
    lines.append("  bg_###_episodes.jsonl")
    lines.append("  bg_###_suppressed.jsonl")
    lines.append("  bg_###_progress.log")
    lines.append("  v063_background_generation_summary.csv")
    lines.append("  v063_background_generation_report.txt")
    lines.append("  v063_manifest.json")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    started = time.time()
    input_dir = Path(args.input_dir)
    windows_summary = Path(args.windows_summary)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SRIA RT v0.6.3 - Background SRIA Candidate/Episode Generation")
    print("=" * 80)
    print(f"Input dir: {input_dir}")
    print(f"Windows summary: {windows_summary}")
    print(f"Output dir: {out_dir}")
    print(f"Detector module: {args.detector_module}")
    print("NOTE: Existing SRIA episode generation only.")
    print("NOTE: No model loading, no learned ranking, no retraining, no redteam validation.")
    print("NOTE: Each bg window is processed independently for first-pass attribution.")
    print("=" * 80)

    module, ConfigCls, DetectorCls, parse_auth_line, episode_to_dict, summarize_episodes = load_detector_api(args.detector_module)
    meta_by_id = load_windows_summary(windows_summary)

    input_files = sorted(input_dir.glob(args.pattern))
    if not input_files:
        raise SystemExit(f"ERROR: no input files matching {args.pattern!r} in {input_dir}")

    rows: List[Dict[str, Any]] = []
    for input_file in input_files:
        wid = input_file.name.replace("_auth.txt", "")
        if wid not in meta_by_id:
            print(f"WARNING: skipping {input_file.name}; no matching window_id in summary")
            continue
        meta = dict(meta_by_id[wid])
        meta["window_id"] = wid
        print(f"[window] {wid}: {input_file.name}")
        row = process_window(input_file, out_dir, meta, ConfigCls, DetectorCls, parse_auth_line, episode_to_dict, args)
        rows.append(row)
        print(
            f"[done] {wid}: raw={int(row['raw_lines_read']):,} parsed={int(row['parsed_success_events']):,} "
            f"accepted={int(row['accepted_episodes']):,} suppressed={int(row['suppressed_episodes']):,} "
            f"bad={int(row['bad_lines']):,}"
        )

    if not rows:
        raise SystemExit("ERROR: no windows processed")

    summary_path = out_dir / "v063_background_generation_summary.csv"
    report_path = out_dir / "v063_background_generation_report.txt"
    manifest_path = out_dir / "v063_manifest.json"

    write_summary_csv(summary_path, rows)
    write_report(report_path, rows, args, args.detector_module, started)

    cfg_for_manifest = make_config(ConfigCls)
    cfg_dict: Dict[str, Any]
    if is_dataclass(cfg_for_manifest):
        cfg_dict = asdict(cfg_for_manifest)
    else:
        cfg_dict = dict(getattr(cfg_for_manifest, "__dict__", {}))

    manifest = {
        "version": VERSION,
        "input_dir": str(input_dir),
        "windows_summary": str(windows_summary),
        "out_dir": str(out_dir),
        "detector_module": args.detector_module,
        "detector_class": DetectorCls.__name__,
        "config": cfg_dict,
        "generation_scope": "window_local_independent",
        "boundaries": {
            "model_loading": False,
            "learned_ranking": False,
            "retraining": False,
            "threshold_tuning": False,
            "redteam_validation": False,
            "auth_full_scan": False,
        },
        "windows_processed": len(rows),
        "total_raw_lines_read": sum(int(r.get("raw_lines_read", 0) or 0) for r in rows),
        "total_parsed_success_events": sum(int(r.get("parsed_success_events", 0) or 0) for r in rows),
        "total_accepted_episodes": sum(int(r.get("accepted_episodes", 0) or 0) for r in rows),
        "total_suppressed_episodes": sum(int(r.get("suppressed_episodes", 0) or 0) for r in rows),
        "summary_csv": str(summary_path),
        "report": str(report_path),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("=" * 80)
    print("SRIA RT v0.6.3 Background Generation Complete")
    print("=" * 80)
    print(f"Windows processed: {len(rows):,}")
    print(f"Total raw lines read: {manifest['total_raw_lines_read']:,}")
    print(f"Total parsed success events: {manifest['total_parsed_success_events']:,}")
    print(f"Total accepted episodes: {manifest['total_accepted_episodes']:,}")
    print(f"Total suppressed episodes: {manifest['total_suppressed_episodes']:,}")
    print(f"Wrote summary: {summary_path}")
    print(f"Wrote report: {report_path}")
    print(f"Wrote manifest: {manifest_path}")


if __name__ == "__main__":
    main()
