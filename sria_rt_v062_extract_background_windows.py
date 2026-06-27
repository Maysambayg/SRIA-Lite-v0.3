#!/usr/bin/env python3
"""
SRIA RT v0.6.2 - Extract Selected Background Windows

Purpose:
  Extract only selected negative-background authentication windows from auth.txt.

Typical CMD use from F:\\SRIA\\SRIA_RT_v01:
  py sria_rt_v062_extract_background_windows.py --auth-file auth.txt --windows-csv v061b_background_windows_tierB\\v061b_background_windows.csv --out-dir v062_background_extract_tierB --progress-every-lines 1000000 --checkpoint-every-lines 1000000

Boundary:
  - Scans auth.txt sequentially once.
  - Writes only auth lines whose timestamp falls inside selected windows.
  - Stops after the last selected window end time when auth.txt is timestamp-sorted.
  - Does not run SRIA detection.
  - Does not load models.
  - Does not score episodes.
  - Does not modify v0.5/v0.6.1 artifacts.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, TextIO, Tuple


@dataclass
class WindowSpec:
    window_id: str
    tier: str
    band: str
    start_time: int
    end_time: int
    duration: int
    expected_auth_line_count: int
    nearest_redteam_distance: Optional[int]
    selection_reason: str
    profile_source: str
    status: str


@dataclass
class WindowRuntime:
    spec: WindowSpec
    output_file: str
    extracted_lines: int = 0
    first_seen_time: Optional[int] = None
    last_seen_time: Optional[int] = None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract selected SRIA RT background auth windows from auth.txt."
    )
    p.add_argument("--auth-file", required=True, help="Path to LANL auth.txt")
    p.add_argument("--windows-csv", required=True, help="v061b_background_windows.csv")
    p.add_argument("--out-dir", required=True, help="Output directory for extracted windows")
    p.add_argument(
        "--progress-every-lines",
        type=int,
        default=1_000_000,
        help="Print/write progress every N scanned auth lines",
    )
    p.add_argument(
        "--checkpoint-every-lines",
        type=int,
        default=1_000_000,
        help="Write checkpoint every N scanned auth lines",
    )
    p.add_argument(
        "--sample-limit-lines",
        type=int,
        default=None,
        help="Optional smoke-test limit on scanned auth lines",
    )
    p.add_argument(
        "--max-runtime-seconds",
        type=float,
        default=None,
        help="Optional wall-clock runtime limit for controlled partial extraction",
    )
    p.add_argument(
        "--encoding",
        default="utf-8",
        help="Text encoding for input/output files; default utf-8",
    )
    p.add_argument(
        "--no-assume-sorted",
        action="store_true",
        help="Do not stop early after final window end time. Use only if auth.txt is not timestamp-sorted.",
    )
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting an existing non-empty output directory.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress printing; report files are still written.",
    )
    return p.parse_args()


def safe_int(value: object, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    s = str(value).strip().replace(",", "")
    if s == "" or s.lower() in {"none", "null", "nan"}:
        return default
    try:
        return int(float(s))
    except ValueError:
        return default


def load_windows(path: Path) -> List[WindowSpec]:
    windows: List[WindowSpec] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        required = {"window_id", "start_time", "end_time", "duration", "auth_line_count"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"windows CSV missing required columns: {sorted(missing)}")
        for row in reader:
            window_id = str(row.get("window_id", "")).strip()
            if not window_id:
                continue
            start_time = safe_int(row.get("start_time"))
            end_time = safe_int(row.get("end_time"))
            duration = safe_int(row.get("duration"), 0)
            expected = safe_int(row.get("auth_line_count"), 0)
            if start_time is None or end_time is None:
                raise ValueError(f"bad start/end time for window {window_id}")
            if end_time <= start_time:
                raise ValueError(f"window {window_id} has end_time <= start_time")
            windows.append(
                WindowSpec(
                    window_id=window_id,
                    tier=str(row.get("tier", "")).strip(),
                    band=str(row.get("band", "")).strip(),
                    start_time=start_time,
                    end_time=end_time,
                    duration=duration or (end_time - start_time),
                    expected_auth_line_count=expected or 0,
                    nearest_redteam_distance=safe_int(row.get("nearest_redteam_distance")),
                    selection_reason=str(row.get("selection_reason", "")).strip(),
                    profile_source=str(row.get("profile_source", "")).strip(),
                    status=str(row.get("status", "")).strip(),
                )
            )
    windows.sort(key=lambda w: (w.start_time, w.end_time, w.window_id))
    if not windows:
        raise ValueError("no windows loaded from windows CSV")
    for prev, cur in zip(windows, windows[1:]):
        if cur.start_time < prev.end_time:
            raise ValueError(
                f"overlapping windows are not supported in this extractor: {prev.window_id} and {cur.window_id}"
            )
    return windows


def parse_auth_time(line: str) -> Optional[int]:
    # LANL auth lines are comma-separated with time as the first field.
    if not line:
        return None
    comma = line.find(",")
    token = line if comma < 0 else line[:comma]
    token = token.strip()
    if not token:
        return None
    try:
        return int(token)
    except ValueError:
        return None


def ensure_out_dir(out_dir: Path, overwrite: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    existing = [p for p in out_dir.iterdir() if p.name not in {".", ".."}]
    if existing and not overwrite:
        raise FileExistsError(
            f"output directory is not empty: {out_dir}. Use --overwrite or choose a new output directory."
        )


def write_json(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def write_checkpoint(
    path: Path,
    args: argparse.Namespace,
    windows: List[WindowRuntime],
    scanned_lines: int,
    bad_lines: int,
    matched_lines: int,
    current_time_value: Optional[int],
    stop_reason: str,
    started_at: float,
) -> None:
    payload = {
        "script": "sria_rt_v062_extract_background_windows.py",
        "version": "0.6.2",
        "auth_file": args.auth_file,
        "windows_csv": args.windows_csv,
        "out_dir": args.out_dir,
        "scanned_lines": scanned_lines,
        "bad_lines": bad_lines,
        "matched_lines": matched_lines,
        "current_auth_time": current_time_value,
        "stop_reason": stop_reason,
        "elapsed_seconds": round(time.time() - started_at, 3),
        "assume_sorted": not args.no_assume_sorted,
        "windows": [
            {
                **asdict(w.spec),
                "output_file": w.output_file,
                "extracted_lines": w.extracted_lines,
                "first_seen_time": w.first_seen_time,
                "last_seen_time": w.last_seen_time,
            }
            for w in windows
        ],
    }
    write_json(path, payload)


def write_summary_csv(path: Path, windows: List[WindowRuntime]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "window_id",
            "tier",
            "band",
            "start_time",
            "end_time",
            "duration",
            "expected_auth_line_count",
            "extracted_lines",
            "extraction_delta",
            "first_seen_time",
            "last_seen_time",
            "nearest_redteam_distance",
            "output_file",
            "selection_reason",
            "profile_source",
            "status",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for w in windows:
            expected = w.spec.expected_auth_line_count
            writer.writerow(
                {
                    "window_id": w.spec.window_id,
                    "tier": w.spec.tier,
                    "band": w.spec.band,
                    "start_time": w.spec.start_time,
                    "end_time": w.spec.end_time,
                    "duration": w.spec.duration,
                    "expected_auth_line_count": expected,
                    "extracted_lines": w.extracted_lines,
                    "extraction_delta": w.extracted_lines - expected,
                    "first_seen_time": w.first_seen_time if w.first_seen_time is not None else "",
                    "last_seen_time": w.last_seen_time if w.last_seen_time is not None else "",
                    "nearest_redteam_distance": w.spec.nearest_redteam_distance if w.spec.nearest_redteam_distance is not None else "",
                    "output_file": w.output_file,
                    "selection_reason": w.spec.selection_reason,
                    "profile_source": w.spec.profile_source,
                    "status": w.spec.status,
                }
            )


def format_int(n: Optional[int]) -> str:
    if n is None:
        return "none"
    return f"{n:,}"


def write_report(
    path: Path,
    args: argparse.Namespace,
    windows: List[WindowRuntime],
    scanned_lines: int,
    bad_lines: int,
    matched_lines: int,
    first_auth_time: Optional[int],
    last_auth_time: Optional[int],
    stop_reason: str,
    elapsed: float,
) -> None:
    lines: List[str] = []
    lines.append("SRIA RT v0.6.2 Background Window Extraction")
    lines.append("=" * 80)
    lines.append(f"auth_file: {args.auth_file}")
    lines.append(f"windows_csv: {args.windows_csv}")
    lines.append(f"out_dir: {args.out_dir}")
    lines.append(f"assume_sorted: {not args.no_assume_sorted}")
    lines.append("analysis_scope: extraction only; no SRIA detection, no model loading, no scoring")
    lines.append("")
    lines.append("Run summary:")
    lines.append(f"  scanned_lines: {format_int(scanned_lines)}")
    lines.append(f"  bad_lines: {format_int(bad_lines)}")
    lines.append(f"  matched_lines: {format_int(matched_lines)}")
    lines.append(f"  auth_time_seen: {format_int(first_auth_time)} to {format_int(last_auth_time)}")
    lines.append(f"  stop_reason: {stop_reason}")
    lines.append(f"  elapsed_seconds: {elapsed:,.2f}")
    rate = scanned_lines / elapsed if elapsed > 0 else 0.0
    lines.append(f"  lines_per_second: {rate:,.0f}")
    lines.append("")
    lines.append("Selected/extracted windows:")
    for w in windows:
        delta = w.extracted_lines - w.spec.expected_auth_line_count
        caveat = ""
        if w.spec.nearest_redteam_distance is not None and w.spec.nearest_redteam_distance < 10800:
            caveat = " ; caveat=valid_outside_margin_but_near_redteam_neighborhood"
        lines.append(
            f"  {w.spec.window_id}: tier={w.spec.tier} band={w.spec.band} "
            f"{w.spec.start_time}-{w.spec.end_time} "
            f"expected={format_int(w.spec.expected_auth_line_count)} "
            f"extracted={format_int(w.extracted_lines)} delta={format_int(delta)} "
            f"nearest_redteam_distance={format_int(w.spec.nearest_redteam_distance)}"
            f"{caveat}"
        )
    lines.append("")
    lines.append("Outputs:")
    lines.append("  bg_###_auth.txt files")
    lines.append("  v062_background_extract_summary.csv")
    lines.append("  v062_background_extract_manifest.json")
    lines.append("  v062_background_extract_checkpoint.json")
    lines.append("  v062_background_extract_progress.log")
    lines.append("  v062_background_extract_report.txt")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    auth_file = Path(args.auth_file)
    windows_csv = Path(args.windows_csv)
    out_dir = Path(args.out_dir)

    if not auth_file.exists():
        print(f"ERROR: auth file not found: {auth_file}", file=sys.stderr)
        return 2
    if not windows_csv.exists():
        print(f"ERROR: windows CSV not found: {windows_csv}", file=sys.stderr)
        return 2

    try:
        ensure_out_dir(out_dir, args.overwrite)
        specs = load_windows(windows_csv)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    runtimes: List[WindowRuntime] = []
    handles: Dict[str, TextIO] = {}
    for spec in specs:
        output_name = f"{spec.window_id}_auth.txt"
        output_path = out_dir / output_name
        runtimes.append(WindowRuntime(spec=spec, output_file=output_name))
        handles[spec.window_id] = output_path.open("w", encoding=args.encoding, errors="replace", newline="")

    progress_path = out_dir / "v062_background_extract_progress.log"
    checkpoint_path = out_dir / "v062_background_extract_checkpoint.json"
    manifest_path = out_dir / "v062_background_extract_manifest.json"
    summary_path = out_dir / "v062_background_extract_summary.csv"
    report_path = out_dir / "v062_background_extract_report.txt"

    min_start = min(w.spec.start_time for w in runtimes)
    max_end = max(w.spec.end_time for w in runtimes)
    assume_sorted = not args.no_assume_sorted

    print("=" * 80)
    print("SRIA RT v0.6.2 - Extract Selected Background Windows")
    print("=" * 80)
    print(f"Auth file: {auth_file}")
    print(f"Windows CSV: {windows_csv}")
    print(f"Output dir: {out_dir}")
    print(f"Windows loaded: {len(runtimes)}")
    print(f"Extraction time range: {min_start} to {max_end}")
    print(f"Assume sorted: {assume_sorted}")
    print("NOTE: This script extracts selected windows only.")
    print("NOTE: It does not run SRIA detection, load models, or score episodes.")
    print("=" * 80)

    started_at = time.time()
    scanned_lines = 0
    bad_lines = 0
    matched_lines = 0
    first_auth_time: Optional[int] = None
    last_auth_time: Optional[int] = None
    stop_reason = "eof"
    active_index = 0

    try:
        with progress_path.open("w", encoding="utf-8") as progress, auth_file.open(
            "r", encoding=args.encoding, errors="replace", newline=""
        ) as f:
            for line in f:
                scanned_lines += 1
                t = parse_auth_time(line)
                if t is None:
                    bad_lines += 1
                else:
                    if first_auth_time is None:
                        first_auth_time = t
                    last_auth_time = t

                    if assume_sorted and t >= max_end:
                        stop_reason = "past_last_window_end"
                        break

                    if t >= min_start:
                        # Move active pointer past windows that ended before current time.
                        while active_index < len(runtimes) and t >= runtimes[active_index].spec.end_time:
                            active_index += 1

                        # Windows are non-overlapping, so at most one match.
                        if active_index < len(runtimes):
                            w = runtimes[active_index]
                            if w.spec.start_time <= t < w.spec.end_time:
                                handles[w.spec.window_id].write(line)
                                w.extracted_lines += 1
                                matched_lines += 1
                                if w.first_seen_time is None:
                                    w.first_seen_time = t
                                w.last_seen_time = t

                elapsed = time.time() - started_at
                if args.sample_limit_lines is not None and scanned_lines >= args.sample_limit_lines:
                    stop_reason = "sample_limit_lines"
                    break
                if args.max_runtime_seconds is not None and elapsed >= args.max_runtime_seconds:
                    stop_reason = "max_runtime_seconds"
                    break

                if args.progress_every_lines > 0 and scanned_lines % args.progress_every_lines == 0:
                    msg = (
                        f"[progress] scanned={scanned_lines:,} matched={matched_lines:,} "
                        f"bad={bad_lines:,} time={last_auth_time} "
                        f"rate={(scanned_lines / elapsed if elapsed > 0 else 0):,.0f} lines/sec "
                        f"elapsed={elapsed:,.1f}s"
                    )
                    progress.write(msg + "\n")
                    progress.flush()
                    if not args.quiet:
                        print(msg)

                if args.checkpoint_every_lines > 0 and scanned_lines % args.checkpoint_every_lines == 0:
                    write_checkpoint(
                        checkpoint_path,
                        args,
                        runtimes,
                        scanned_lines,
                        bad_lines,
                        matched_lines,
                        last_auth_time,
                        "running",
                        started_at,
                    )
    finally:
        for h in handles.values():
            h.close()

    elapsed = time.time() - started_at
    write_summary_csv(summary_path, runtimes)
    write_checkpoint(
        checkpoint_path,
        args,
        runtimes,
        scanned_lines,
        bad_lines,
        matched_lines,
        last_auth_time,
        stop_reason,
        started_at,
    )
    manifest = {
        "script": "sria_rt_v062_extract_background_windows.py",
        "version": "0.6.2",
        "auth_file": str(auth_file),
        "windows_csv": str(windows_csv),
        "out_dir": str(out_dir),
        "assume_sorted": assume_sorted,
        "window_count": len(runtimes),
        "min_window_start": min_start,
        "max_window_end": max_end,
        "scanned_lines": scanned_lines,
        "bad_lines": bad_lines,
        "matched_lines": matched_lines,
        "auth_time_seen_min": first_auth_time,
        "auth_time_seen_max": last_auth_time,
        "stop_reason": stop_reason,
        "elapsed_seconds": round(elapsed, 3),
        "lines_per_second": round(scanned_lines / elapsed, 3) if elapsed > 0 else None,
        "outputs": {
            "summary_csv": summary_path.name,
            "report": report_path.name,
            "checkpoint": checkpoint_path.name,
            "progress_log": progress_path.name,
            "window_files": [w.output_file for w in runtimes],
        },
    }
    write_json(manifest_path, manifest)
    write_report(
        report_path,
        args,
        runtimes,
        scanned_lines,
        bad_lines,
        matched_lines,
        first_auth_time,
        last_auth_time,
        stop_reason,
        elapsed,
    )

    print("=" * 80)
    print("SRIA RT v0.6.2 Background Window Extraction")
    print("=" * 80)
    print(f"scanned_lines: {scanned_lines:,}")
    print(f"bad_lines: {bad_lines:,}")
    print(f"matched_lines: {matched_lines:,}")
    print(f"auth_time_seen: {format_int(first_auth_time)} to {format_int(last_auth_time)}")
    print(f"stop_reason: {stop_reason}")
    print(f"elapsed_seconds: {elapsed:,.2f}")
    print(f"lines_per_second: {(scanned_lines / elapsed if elapsed > 0 else 0):,.0f}")
    for w in runtimes:
        delta = w.extracted_lines - w.spec.expected_auth_line_count
        print(
            f"  {w.spec.window_id}: extracted={w.extracted_lines:,} "
            f"expected={w.spec.expected_auth_line_count:,} delta={delta:,}"
        )
    print(f"Wrote summary: {summary_path}")
    print(f"Wrote manifest: {manifest_path}")
    print(f"Wrote checkpoint: {checkpoint_path}")
    print(f"Wrote report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
