#!/usr/bin/env python3
"""
sria_rt_v053_source_diversified_queue_policy.py

SRIA RT v0.5.3 - Source-Diversified Queue Policy Simulation

Purpose:
- Simulate per-source caps over v0.5.1 research/debug ranked queues.
- Measure whether analyst coverage improves without destroying known validation signal.
- Do NOT rescore episodes.
- Do NOT load models.
- Do NOT read auth.txt, accepted JSONL, redteam.txt, or separate validation files.
- Uses only v0.5.1 research/debug queue CSVs that already contain validation/debug columns.

Typical CMD use from F:\SRIA\SRIA_RT_v01:

  py sria_rt_v053_source_diversified_queue_policy.py --queue-dir v051_deployment_rf_depth10 --out-dir v053_source_caps_rf_depth10

Optional:

  py sria_rt_v053_source_diversified_queue_policy.py --queue-dir v051_deployment_rf_depth10 --out-dir v053_source_caps_rf_depth10 --base-size 5000 --target-sizes 100,500,1000,5000 --source-caps 3,5,10,20 --focus-source C17693

Inputs expected:
  research_debug_queue_top5000.csv    default base ranked list

Outputs:
  source_cap_policy_report.txt
  source_cap_policy_summary.csv
  source_cap_policy_summary.json
  source_cap_queue_cap*_top*.csv       research/debug queues with validation fields retained
  deployment_cap_queue_cap*_top*.csv   clean deployment-style capped queues with validation fields removed
  source_distribution_cap*_top*.csv
  v053_manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "v053"
DEFAULT_TARGET_SIZES = [100, 500, 1000, 5000]
DEFAULT_SOURCE_CAPS = [3, 5, 10, 20]
DEFAULT_BASE_SIZE = 5000
DEFAULT_FOCUS_SOURCE = "C17693"

VALIDATION_FIELDS = {"label", "redteam_count", "exact_start_count", "redteam_indices"}

NUMERIC_METRICS = [
    "sria_rt_model_score",
    "duration",
    "destination_count",
    "events_count",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "first_time_signal_hits",
    "first_time_event_count",
    "new_destination_event_count",
]


def safe_float(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    try:
        x = float(str(v).strip())
        if math.isnan(x) or math.isinf(x):
            return default
        return x
    except Exception:
        return default


def safe_int(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    try:
        return int(float(str(v).strip()))
    except Exception:
        return default


def parse_csv_list_int(text: str) -> List[int]:
    out: List[int] = []
    for part in str(text).split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return out


def parse_redteam_indices(value: Any) -> List[int]:
    s = str(value or "").strip()
    if not s:
        return []
    # v0.5.1 may write semicolon-separated indices; tolerate commas/spaces too.
    parts: List[str] = []
    if ";" in s:
        parts = s.split(";")
    elif "," in s:
        parts = s.split(",")
    else:
        parts = s.split()
    indices: List[int] = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        try:
            indices.append(int(float(p)))
        except Exception:
            continue
    return indices


def split_signals(value: Any) -> List[str]:
    s = str(value or "").strip()
    if not s:
        return []
    if ";" in s:
        return [x.strip() for x in s.split(";") if x.strip()]
    if "," in s:
        return [x.strip() for x in s.split(",") if x.strip()]
    return [s]


def read_csv_rows(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        fields = list(reader.fieldnames or [])
        rows = [dict(r) for r in reader]
    return rows, fields


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})


def row_is_positive(row: Dict[str, Any]) -> bool:
    if safe_int(row.get("label"), 0) == 1:
        return True
    if safe_int(row.get("redteam_count"), 0) > 0:
        return True
    if parse_redteam_indices(row.get("redteam_indices")):
        return True
    return False


def unique_redteam_indices(rows: Sequence[Dict[str, Any]]) -> set[int]:
    indices: set[int] = set()
    for row in rows:
        indices.update(parse_redteam_indices(row.get("redteam_indices")))
    return indices


def source_counts(rows: Sequence[Dict[str, Any]]) -> Counter:
    c: Counter = Counter()
    for row in rows:
        src = str(row.get("source") or "").strip() or "<missing>"
        c[src] += 1
    return c


def user_counts(rows: Sequence[Dict[str, Any]]) -> Counter:
    c: Counter = Counter()
    for row in rows:
        user = str(row.get("user") or "").strip() or "<missing>"
        c[user] += 1
    return c


def median_numeric(rows: Sequence[Dict[str, Any]], field: str) -> float:
    vals = [safe_float(r.get(field), 0.0) for r in rows if str(r.get(field, "")).strip() != ""]
    if not vals:
        return 0.0
    return float(statistics.median(vals))


def select_with_source_cap(rows: Sequence[Dict[str, Any]], target_size: int, source_cap: int) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    counts: Counter = Counter()
    for row in rows:
        src = str(row.get("source") or "").strip() or "<missing>"
        if counts[src] >= source_cap:
            continue
        new_row = dict(row)
        new_row["policy_rank"] = len(selected) + 1
        new_row["source_cap"] = source_cap
        new_row["target_queue_size"] = target_size
        selected.append(new_row)
        counts[src] += 1
        if len(selected) >= target_size:
            break
    return selected


def summarize_queue(
    selected: Sequence[Dict[str, Any]],
    *,
    target_size: int,
    source_cap: int,
    focus_source: str,
    total_represented_redteam: int,
) -> Dict[str, Any]:
    rows = len(selected)
    sc = source_counts(selected)
    uc = user_counts(selected)
    rt_indices = unique_redteam_indices(selected)
    pos_eps = sum(1 for r in selected if row_is_positive(r))
    exact_start = sum(safe_int(r.get("exact_start_count"), 0) for r in selected)
    top_source, top_source_count = (sc.most_common(1)[0] if sc else ("", 0))
    top_user, top_user_count = (uc.most_common(1)[0] if uc else ("", 0))
    top5_sources = sum(v for _, v in sc.most_common(5))
    top10_sources = sum(v for _, v in sc.most_common(10))
    focus_count = sc.get(focus_source, 0)
    gate_counts = Counter(str(r.get("candidate_gate") or "<missing>") for r in selected)
    severity_counts = Counter(str(r.get("severity") or "<missing>") for r in selected)
    dominant_gate, dominant_gate_count = (gate_counts.most_common(1)[0] if gate_counts else ("", 0))
    dominant_severity, dominant_severity_count = (severity_counts.most_common(1)[0] if severity_counts else ("", 0))

    return {
        "target_queue_size": target_size,
        "source_cap": source_cap,
        "rows_selected": rows,
        "filled_target": int(rows >= target_size),
        "positive_episodes": pos_eps,
        "episode_precision": round(pos_eps / rows, 8) if rows else 0.0,
        "represented_redteam_events": len(rt_indices),
        "represented_redteam_recall": round(len(rt_indices) / total_represented_redteam, 8) if total_represented_redteam else 0.0,
        "exact_start_count": exact_start,
        "unique_sources": len(sc),
        "unique_users": len(uc),
        "top_source": top_source,
        "top_source_count": top_source_count,
        "top_source_share": round(top_source_count / rows, 8) if rows else 0.0,
        "focus_source": focus_source,
        "focus_source_count": focus_count,
        "focus_source_share": round(focus_count / rows, 8) if rows else 0.0,
        "top_5_sources_share": round(top5_sources / rows, 8) if rows else 0.0,
        "top_10_sources_share": round(top10_sources / rows, 8) if rows else 0.0,
        "top_user": top_user,
        "top_user_count": top_user_count,
        "top_user_share": round(top_user_count / rows, 8) if rows else 0.0,
        "median_score": round(median_numeric(selected, "sria_rt_model_score"), 8),
        "median_duration": round(median_numeric(selected, "duration"), 3),
        "median_destination_count": round(median_numeric(selected, "destination_count"), 3),
        "median_events_count": round(median_numeric(selected, "events_count"), 3),
        "dominant_gate": dominant_gate,
        "dominant_gate_share": round(dominant_gate_count / rows, 8) if rows else 0.0,
        "dominant_severity": dominant_severity,
        "dominant_severity_share": round(dominant_severity_count / rows, 8) if rows else 0.0,
    }


def write_source_distribution(path: Path, rows: Sequence[Dict[str, Any]], total_rows: int) -> None:
    sc = source_counts(rows)
    out: List[Dict[str, Any]] = []
    for rank, (src, count) in enumerate(sc.most_common(), 1):
        out.append({
            "source_rank": rank,
            "source": src,
            "count": count,
            "share": round(count / total_rows, 8) if total_rows else 0.0,
        })
    write_csv(path, out, ["source_rank", "source", "count", "share"])


def clean_deployment_fields(fields: Sequence[str]) -> List[str]:
    return [f for f in fields if f not in VALIDATION_FIELDS]


def clean_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if k not in VALIDATION_FIELDS}


def build_report(
    *,
    queue_dir: Path,
    out_dir: Path,
    base_path: Path,
    base_rows: Sequence[Dict[str, Any]],
    summaries: Sequence[Dict[str, Any]],
    total_represented_redteam: int,
    focus_source: str,
) -> str:
    lines: List[str] = []
    lines.append("SRIA RT v0.5.3 Source-Diversified Queue Policy Simulation")
    lines.append("=" * 80)
    lines.append(f"queue_dir: {queue_dir}")
    lines.append(f"out_dir: {out_dir}")
    lines.append(f"base_queue: {base_path}")
    lines.append(f"base_rows_loaded: {len(base_rows):,}")
    lines.append(f"focus_source: {focus_source}")
    lines.append("analysis_scope: v0.5.1 research/debug ranked queue only")
    lines.append("exclusions: no model loading, no redteam.txt, no validation file, no auth.txt, no accepted JSONL")
    lines.append(f"represented_redteam_denominator_from_base_queue: {total_represented_redteam}")
    lines.append("")
    lines.append("Policy summary:")
    for s in summaries:
        lines.append(
            "  "
            f"top{int(s['target_queue_size'])} cap{int(s['source_cap'])}: "
            f"rows={int(s['rows_selected']):,} "
            f"pos_eps={int(s['positive_episodes'])} "
            f"rt_events={int(s['represented_redteam_events'])} "
            f"rt_recall={float(s['represented_redteam_recall']):.2%} "
            f"unique_sources={int(s['unique_sources']):,} "
            f"unique_users={int(s['unique_users']):,} "
            f"top_source={s['top_source']} "
            f"top_source_share={float(s['top_source_share']):.2%} "
            f"{focus_source}_share={float(s['focus_source_share']):.2%}"
        )
    lines.append("")
    lines.append("Interpretation guide:")
    lines.append("  - Higher caps preserve ranked-model purity but allow source concentration.")
    lines.append("  - Lower caps increase source diversity but may push validated episodes out of small queues.")
    lines.append("  - The preferred operating point is the smallest cap that preserves most represented red-team recall while improving source breadth.")
    lines.append("")
    lines.append("Generated files:")
    lines.append("  source_cap_policy_summary.csv")
    lines.append("  source_cap_policy_summary.json")
    lines.append("  source_cap_queue_cap*_top*.csv")
    lines.append("  deployment_cap_queue_cap*_top*.csv")
    lines.append("  source_distribution_cap*_top*.csv")
    lines.append("  v053_manifest.json")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v0.5.3 source-diversified queue policy simulation")
    p.add_argument("--queue-dir", required=True, help="Directory containing v0.5.1 research_debug_queue_top*.csv files")
    p.add_argument("--out-dir", required=True, help="Output directory for v0.5.3 policy simulation files")
    p.add_argument("--base-size", type=int, default=DEFAULT_BASE_SIZE, help="Base research/debug queue size to read, default 5000")
    p.add_argument("--target-sizes", default=",".join(str(x) for x in DEFAULT_TARGET_SIZES), help="Comma-separated target queue sizes")
    p.add_argument("--source-caps", default=",".join(str(x) for x in DEFAULT_SOURCE_CAPS), help="Comma-separated max episodes per source")
    p.add_argument("--focus-source", default=DEFAULT_FOCUS_SOURCE, help="Source to track explicitly, default C17693")
    p.add_argument("--total-redteam-events", type=int, default=0, help="Optional denominator override for represented red-team recall")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    queue_dir = Path(args.queue_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_size = int(args.base_size)
    target_sizes = parse_csv_list_int(args.target_sizes)
    source_caps = parse_csv_list_int(args.source_caps)
    focus_source = str(args.focus_source)

    base_path = queue_dir / f"research_debug_queue_top{base_size}.csv"

    print("=" * 80)
    print("SRIA RT v0.5.3 - Source-Diversified Queue Policy Simulation")
    print("=" * 80)
    print(f"Queue dir: {queue_dir}")
    print(f"Output dir: {out_dir}")
    print(f"Base queue: {base_path}")
    print(f"Target sizes: {target_sizes}")
    print(f"Source caps: {source_caps}")
    print(f"Focus source: {focus_source}")
    print("NOTE: This script reads only v0.5.1 research/debug queue CSVs.")
    print("NOTE: No model, redteam.txt, validation file, auth.txt, or accepted JSONL inputs are used.")
    print("=" * 80)

    if not base_path.exists():
        raise SystemExit(f"ERROR: Base research/debug queue not found: {base_path}")

    base_rows, base_fields = read_csv_rows(base_path)
    base_rows.sort(key=lambda r: safe_int(r.get("rank"), 10**12))
    print(f"[load] base rows: {len(base_rows):,} from {base_path}")

    total_represented_redteam = int(args.total_redteam_events) if int(args.total_redteam_events) > 0 else len(unique_redteam_indices(base_rows))
    print(f"[validation denominator] represented redteam events in base queue: {total_represented_redteam}")

    summary_rows: List[Dict[str, Any]] = []
    research_fields = list(dict.fromkeys(["policy_rank", "source_cap", "target_queue_size"] + base_fields))
    deployment_fields = clean_deployment_fields(research_fields)

    for target_size in target_sizes:
        for cap in source_caps:
            selected = select_with_source_cap(base_rows, target_size, cap)
            summary = summarize_queue(
                selected,
                target_size=target_size,
                source_cap=cap,
                focus_source=focus_source,
                total_represented_redteam=total_represented_redteam,
            )
            summary_rows.append(summary)

            cap_tag = f"cap{cap}_top{target_size}"
            write_csv(out_dir / f"source_cap_queue_{cap_tag}.csv", selected, research_fields)
            write_csv(out_dir / f"deployment_cap_queue_{cap_tag}.csv", [clean_row(r) for r in selected], deployment_fields)
            write_source_distribution(out_dir / f"source_distribution_{cap_tag}.csv", selected, len(selected))

            print(
                f"[policy] top{target_size} cap{cap}: "
                f"rows={len(selected):,} "
                f"rt_recall={float(summary['represented_redteam_recall']):.2%} "
                f"unique_sources={int(summary['unique_sources']):,} "
                f"focus_share={float(summary['focus_source_share']):.2%}"
            )

    summary_fields = [
        "target_queue_size", "source_cap", "rows_selected", "filled_target",
        "positive_episodes", "episode_precision", "represented_redteam_events", "represented_redteam_recall",
        "exact_start_count", "unique_sources", "unique_users",
        "top_source", "top_source_count", "top_source_share",
        "focus_source", "focus_source_count", "focus_source_share",
        "top_5_sources_share", "top_10_sources_share",
        "top_user", "top_user_count", "top_user_share",
        "median_score", "median_duration", "median_destination_count", "median_events_count",
        "dominant_gate", "dominant_gate_share", "dominant_severity", "dominant_severity_share",
    ]
    write_csv(out_dir / "source_cap_policy_summary.csv", summary_rows, summary_fields)
    (out_dir / "source_cap_policy_summary.json").write_text(json.dumps(summary_rows, indent=2), encoding="utf-8")

    manifest = {
        "version": "v0.5.3",
        "purpose": "source_diversified_queue_policy_simulation",
        "queue_dir": str(queue_dir),
        "out_dir": str(out_dir),
        "base_queue": str(base_path),
        "base_rows_loaded": len(base_rows),
        "target_sizes": target_sizes,
        "source_caps": source_caps,
        "focus_source": focus_source,
        "represented_redteam_denominator": total_represented_redteam,
        "inputs_used": [str(base_path)],
        "inputs_excluded": ["model artifacts", "redteam.txt", "validation/matches files", "auth.txt", "accepted JSONL"],
        "outputs": [
            "source_cap_policy_report.txt",
            "source_cap_policy_summary.csv",
            "source_cap_policy_summary.json",
            "source_cap_queue_cap*_top*.csv",
            "deployment_cap_queue_cap*_top*.csv",
            "source_distribution_cap*_top*.csv",
        ],
    }
    (out_dir / "v053_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    report = build_report(
        queue_dir=queue_dir,
        out_dir=out_dir,
        base_path=base_path,
        base_rows=base_rows,
        summaries=summary_rows,
        total_represented_redteam=total_represented_redteam,
        focus_source=focus_source,
    )
    (out_dir / "source_cap_policy_report.txt").write_text(report, encoding="utf-8")

    print(report)
    print(f"Wrote report: {out_dir / 'source_cap_policy_report.txt'}")
    print(f"Wrote summary: {out_dir / 'source_cap_policy_summary.csv'}")
    print(f"Wrote manifest: {out_dir / 'v053_manifest.json'}")


if __name__ == "__main__":
    main()
