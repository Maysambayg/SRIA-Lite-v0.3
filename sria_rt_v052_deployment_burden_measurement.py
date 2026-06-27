#!/usr/bin/env python3
"""
sria_rt_v052_deployment_burden_measurement.py

SRIA RT v0.5.2 - Deployment Burden Measurement

Purpose:
- Read only clean deployment queues produced by v0.5.1.
- Measure analyst burden and queue concentration.
- Do NOT load models.
- Do NOT use red-team labels, validation files, matches files, accepted JSONL, or auth.txt.
- Produce operational queue usability summaries.

Typical CMD use from F:\SRIA\SRIA_RT_v01:

  py sria_rt_v052_deployment_burden_measurement.py --queue-dir v051_deployment_rf_depth10 --out-dir v052_burden_rf_depth10

Optional:

  py sria_rt_v052_deployment_burden_measurement.py --queue-dir v051_deployment_rf_depth10 --out-dir v052_burden_rf_depth10 --queue-sizes 100,500,1000,5000 --focus-source C17693

Inputs expected:
  deployment_queue_top100.csv
  deployment_queue_top500.csv
  deployment_queue_top1000.csv
  deployment_queue_top5000.csv

Outputs:
  burden_report.txt
  burden_summary.csv
  source_concentration_top*.csv
  user_concentration_top*.csv
  gate_distribution_top*.csv
  severity_distribution_top*.csv
  review_priority_distribution_top*.csv
  score_band_distribution_top*.csv
  signal_distribution_top*.csv
  metric_distribution_top*.csv
  focus_source_episodes_top*.csv
  v052_manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "v052"
DEFAULT_QUEUE_SIZES = [100, 500, 1000, 5000]
DEFAULT_FOCUS_SOURCE = "C17693"

NUMERIC_FIELDS = [
    "sria_rt_model_score",
    "duration",
    "destination_count",
    "events_count",
    "user_count",
    "legacy_sria_score",
    "legacy_raw_score",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "first_time_signal_hits",
    "first_time_event_count",
    "new_destination_event_count",
]

DISTRIBUTION_FIELDS = [
    "candidate_gate",
    "severity",
    "review_priority",
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


def parse_queue_sizes(s: str) -> List[int]:
    out: List[int] = []
    for part in str(s).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except Exception:
            raise argparse.ArgumentTypeError(f"Invalid queue size: {part}")
        if n <= 0:
            raise argparse.ArgumentTypeError(f"Queue size must be positive: {part}")
        out.append(n)
    if not out:
        raise argparse.ArgumentTypeError("At least one queue size is required")
    return out


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        rows = [dict(r) for r in reader]
    return rows


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Optional[Sequence[str]] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys: List[str] = []
        seen = set()
        for row in rows:
            for k in row.keys():
                if k not in seen:
                    seen.add(k)
                    keys.append(k)
        fieldnames = keys
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def pct(n: float, d: float) -> float:
    if d == 0:
        return 0.0
    return float(n) / float(d)


def median(values: Sequence[float]) -> float:
    vals = [v for v in values if not math.isnan(v) and not math.isinf(v)]
    if not vals:
        return 0.0
    return float(statistics.median(vals))


def mean(values: Sequence[float]) -> float:
    vals = [v for v in values if not math.isnan(v) and not math.isinf(v)]
    if not vals:
        return 0.0
    return float(sum(vals) / len(vals))


def score_band(score: float) -> str:
    # RF probabilities are empirically low in v051 output, so use narrow bands.
    if score >= 0.30:
        return ">=0.30"
    if score >= 0.20:
        return "0.20-0.2999"
    if score >= 0.10:
        return "0.10-0.1999"
    if score >= 0.05:
        return "0.05-0.0999"
    if score >= 0.02:
        return "0.02-0.0499"
    return "<0.02"


def split_signals(s: str) -> List[str]:
    if not s:
        return []
    # v051 writes semicolon-separated signals in deployment CSV.
    parts: List[str] = []
    for chunk in str(s).replace(",", ";").split(";"):
        item = chunk.strip()
        if item:
            parts.append(item)
    return parts


def concentration_rows(counter: Counter, total: int, label_field: str, max_rows: int = 50) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    cumulative = 0
    for rank, (name, count) in enumerate(counter.most_common(max_rows), start=1):
        cumulative += count
        rows.append({
            "rank": rank,
            label_field: name,
            "count": count,
            "share": round(pct(count, total), 6),
            "cumulative_share": round(pct(cumulative, total), 6),
        })
    return rows


def distribution_rows(counter: Counter, total: int, field_name: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for value, count in counter.most_common():
        rows.append({
            field_name: value,
            "count": count,
            "share": round(pct(count, total), 6),
        })
    return rows


def metric_distribution(rows: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for field in NUMERIC_FIELDS:
        vals = [safe_float(r.get(field)) for r in rows]
        vals_sorted = sorted(vals)
        if not vals_sorted:
            continue
        def q(p: float) -> float:
            if not vals_sorted:
                return 0.0
            idx = int(round((len(vals_sorted) - 1) * p))
            return float(vals_sorted[idx])
        out.append({
            "metric": field,
            "min": round(vals_sorted[0], 6),
            "p25": round(q(0.25), 6),
            "median": round(q(0.50), 6),
            "mean": round(mean(vals), 6),
            "p75": round(q(0.75), 6),
            "max": round(vals_sorted[-1], 6),
        })
    return out


def analyze_queue(rows: List[Dict[str, str]], queue_size: int, focus_source: str, out_dir: Path) -> Dict[str, Any]:
    total = len(rows)
    if total == 0:
        return {
            "queue_size": queue_size,
            "rows": 0,
            "error": "empty_queue",
        }

    sources = [str(r.get("source", "")).strip() or "<blank>" for r in rows]
    users = [str(r.get("user", "")).strip() or "<blank>" for r in rows]
    gates = [str(r.get("candidate_gate", "")).strip() or "<blank>" for r in rows]
    severities = [str(r.get("severity", "")).strip() or "<blank>" for r in rows]
    priorities = [str(r.get("review_priority", "")).strip() or "<blank>" for r in rows]
    scores = [safe_float(r.get("sria_rt_model_score")) for r in rows]
    durations = [safe_float(r.get("duration")) for r in rows]
    dest_counts = [safe_float(r.get("destination_count")) for r in rows]
    event_counts = [safe_float(r.get("events_count")) for r in rows]

    source_counter = Counter(sources)
    user_counter = Counter(users)
    gate_counter = Counter(gates)
    severity_counter = Counter(severities)
    priority_counter = Counter(priorities)
    score_band_counter = Counter(score_band(s) for s in scores)

    signal_counter: Counter = Counter()
    for r in rows:
        signal_counter.update(split_signals(str(r.get("signals", ""))))

    top_source = source_counter.most_common(1)[0][0] if source_counter else ""
    top_source_count = source_counter.most_common(1)[0][1] if source_counter else 0
    top_user = user_counter.most_common(1)[0][0] if user_counter else ""
    top_user_count = user_counter.most_common(1)[0][1] if user_counter else 0
    focus_source_count = source_counter.get(focus_source, 0)
    top_5_sources_count = sum(c for _, c in source_counter.most_common(5))
    top_10_sources_count = sum(c for _, c in source_counter.most_common(10))
    top_5_users_count = sum(c for _, c in user_counter.most_common(5))
    top_10_users_count = sum(c for _, c in user_counter.most_common(10))

    # Per-queue detailed outputs.
    suffix = f"top{queue_size}"
    write_csv(out_dir / f"source_concentration_{suffix}.csv", concentration_rows(source_counter, total, "source"))
    write_csv(out_dir / f"user_concentration_{suffix}.csv", concentration_rows(user_counter, total, "user"))
    write_csv(out_dir / f"gate_distribution_{suffix}.csv", distribution_rows(gate_counter, total, "candidate_gate"))
    write_csv(out_dir / f"severity_distribution_{suffix}.csv", distribution_rows(severity_counter, total, "severity"))
    write_csv(out_dir / f"review_priority_distribution_{suffix}.csv", distribution_rows(priority_counter, total, "review_priority"))
    write_csv(out_dir / f"score_band_distribution_{suffix}.csv", distribution_rows(score_band_counter, total, "score_band"))
    write_csv(out_dir / f"signal_distribution_{suffix}.csv", concentration_rows(signal_counter, total, "signal", max_rows=100))
    write_csv(out_dir / f"metric_distribution_{suffix}.csv", metric_distribution(rows))

    focus_rows = [r for r in rows if str(r.get("source", "")).strip() == focus_source]
    write_csv(out_dir / f"focus_source_episodes_{suffix}.csv", focus_rows)

    return {
        "queue_size": queue_size,
        "rows": total,
        "unique_sources": len(source_counter),
        "unique_users": len(user_counter),
        "unique_gates": len(gate_counter),
        "top_source": top_source,
        "top_source_count": top_source_count,
        "top_source_share": round(pct(top_source_count, total), 6),
        "focus_source": focus_source,
        "focus_source_count": focus_source_count,
        "focus_source_share": round(pct(focus_source_count, total), 6),
        "top_5_sources_share": round(pct(top_5_sources_count, total), 6),
        "top_10_sources_share": round(pct(top_10_sources_count, total), 6),
        "top_user": top_user,
        "top_user_count": top_user_count,
        "top_user_share": round(pct(top_user_count, total), 6),
        "top_5_users_share": round(pct(top_5_users_count, total), 6),
        "top_10_users_share": round(pct(top_10_users_count, total), 6),
        "median_score": round(median(scores), 6),
        "max_score": round(max(scores), 6) if scores else 0.0,
        "min_score": round(min(scores), 6) if scores else 0.0,
        "median_duration": round(median(durations), 6),
        "median_destination_count": round(median(dest_counts), 6),
        "median_events_count": round(median(event_counts), 6),
        "dominant_gate": gate_counter.most_common(1)[0][0] if gate_counter else "",
        "dominant_gate_share": round(pct(gate_counter.most_common(1)[0][1], total), 6) if gate_counter else 0.0,
        "dominant_severity": severity_counter.most_common(1)[0][0] if severity_counter else "",
        "dominant_severity_share": round(pct(severity_counter.most_common(1)[0][1], total), 6) if severity_counter else 0.0,
        "dominant_signal": signal_counter.most_common(1)[0][0] if signal_counter else "",
        "dominant_signal_share": round(pct(signal_counter.most_common(1)[0][1], total), 6) if signal_counter else 0.0,
    }


def make_report(summary_rows: List[Dict[str, Any]], queue_dir: Path, out_dir: Path, focus_source: str) -> str:
    lines: List[str] = []
    lines.append("SRIA RT v0.5.2 Deployment Burden Measurement")
    lines.append("=" * 80)
    lines.append(f"queue_dir: {queue_dir}")
    lines.append(f"out_dir: {out_dir}")
    lines.append(f"focus_source: {focus_source}")
    lines.append("analysis_scope: deployment CSV queues only")
    lines.append("exclusions: no model loading, no redteam labels, no validation file, no auth.txt, no accepted JSONL")
    lines.append("")
    lines.append("Summary by queue size:")
    for row in summary_rows:
        if row.get("error"):
            lines.append(f"  top{row.get('queue_size')}: ERROR {row.get('error')}")
            continue
        lines.append(
            "  top{queue_size}: rows={rows:,} unique_sources={unique_sources:,} "
            "unique_users={unique_users:,} top_source={top_source} "
            "top_source_share={top_source_share:.2%} {focus_source}_share={focus_source_share:.2%} "
            "top5_sources_share={top_5_sources_share:.2%} median_score={median_score:.6f}".format(**row)
        )
    lines.append("")
    lines.append("Analyst-burden interpretation:")
    for row in summary_rows:
        if row.get("error"):
            continue
        q = row["queue_size"]
        focus_share = row["focus_source_share"]
        top5_share = row["top_5_sources_share"]
        unique_sources = row["unique_sources"]
        unique_users = row["unique_users"]
        if focus_share >= 0.50:
            concentration_note = f"top{q} is strongly {focus_source}-centered"
        elif focus_share >= 0.25:
            concentration_note = f"top{q} has meaningful {focus_source} concentration"
        else:
            concentration_note = f"top{q} is not dominated by {focus_source}"
        if top5_share >= 0.70:
            breadth_note = "source breadth is narrow"
        elif top5_share >= 0.45:
            breadth_note = "source breadth is moderate"
        else:
            breadth_note = "source breadth is broad"
        lines.append(
            f"  top{q}: {concentration_note}; {breadth_note}; "
            f"analyst sees {unique_sources} sources and {unique_users} users."
        )
    lines.append("")
    lines.append("Generated files:")
    lines.append("  burden_summary.csv")
    lines.append("  source_concentration_top*.csv")
    lines.append("  user_concentration_top*.csv")
    lines.append("  gate_distribution_top*.csv")
    lines.append("  severity_distribution_top*.csv")
    lines.append("  review_priority_distribution_top*.csv")
    lines.append("  score_band_distribution_top*.csv")
    lines.append("  signal_distribution_top*.csv")
    lines.append("  metric_distribution_top*.csv")
    lines.append("  focus_source_episodes_top*.csv")
    lines.append("  v052_manifest.json")
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SRIA RT v0.5.2 deployment burden measurement")
    p.add_argument("--queue-dir", required=True, help="Directory containing v0.5.1 deployment_queue_top*.csv files")
    p.add_argument("--out-dir", required=True, help="Output directory for v0.5.2 burden analysis")
    p.add_argument("--queue-sizes", type=parse_queue_sizes, default=DEFAULT_QUEUE_SIZES, help="Comma-separated queue sizes, default: 100,500,1000,5000")
    p.add_argument("--focus-source", default=DEFAULT_FOCUS_SOURCE, help="Source host to track explicitly, default: C17693")
    return p


def main() -> None:
    args = build_parser().parse_args()
    queue_dir = Path(args.queue_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    queue_sizes: List[int] = list(args.queue_sizes)
    focus_source = str(args.focus_source)

    print("=" * 80)
    print("SRIA RT v0.5.2 - Deployment Burden Measurement")
    print("=" * 80)
    print(f"Queue dir: {queue_dir}")
    print(f"Output dir: {out_dir}")
    print(f"Queue sizes: {queue_sizes}")
    print(f"Focus source: {focus_source}")
    print("NOTE: This script reads only clean deployment queue CSVs.")
    print("NOTE: No model, redteam, validation, auth, or accepted JSONL inputs are used.")
    print("=" * 80)

    summary_rows: List[Dict[str, Any]] = []
    input_files: Dict[str, str] = {}

    for q in queue_sizes:
        path = queue_dir / f"deployment_queue_top{q}.csv"
        input_files[f"top{q}"] = str(path)
        if not path.exists():
            print(f"[missing] {path}")
            summary_rows.append({"queue_size": q, "rows": 0, "error": "missing_input"})
            continue
        rows = read_csv_rows(path)
        print(f"[load] top{q}: {len(rows):,} rows from {path}")
        summary = analyze_queue(rows, q, focus_source, out_dir)
        summary_rows.append(summary)

    summary_fields = [
        "queue_size", "rows", "unique_sources", "unique_users", "unique_gates",
        "top_source", "top_source_count", "top_source_share",
        "focus_source", "focus_source_count", "focus_source_share",
        "top_5_sources_share", "top_10_sources_share",
        "top_user", "top_user_count", "top_user_share",
        "top_5_users_share", "top_10_users_share",
        "median_score", "max_score", "min_score",
        "median_duration", "median_destination_count", "median_events_count",
        "dominant_gate", "dominant_gate_share",
        "dominant_severity", "dominant_severity_share",
        "dominant_signal", "dominant_signal_share",
        "error",
    ]
    write_csv(out_dir / "burden_summary.csv", summary_rows, summary_fields)

    report = make_report(summary_rows, queue_dir, out_dir, focus_source)
    report_path = out_dir / "burden_report.txt"
    report_path.write_text(report, encoding="utf-8")

    manifest = {
        "version": VERSION,
        "queue_dir": str(queue_dir),
        "out_dir": str(out_dir),
        "queue_sizes": queue_sizes,
        "focus_source": focus_source,
        "input_files": input_files,
        "outputs": {
            "burden_report": "burden_report.txt",
            "burden_summary": "burden_summary.csv",
            "source_concentration": "source_concentration_top*.csv",
            "user_concentration": "user_concentration_top*.csv",
            "gate_distribution": "gate_distribution_top*.csv",
            "severity_distribution": "severity_distribution_top*.csv",
            "review_priority_distribution": "review_priority_distribution_top*.csv",
            "score_band_distribution": "score_band_distribution_top*.csv",
            "signal_distribution": "signal_distribution_top*.csv",
            "metric_distribution": "metric_distribution_top*.csv",
            "focus_source_episodes": "focus_source_episodes_top*.csv",
        },
        "discipline": {
            "model_loading": False,
            "redteam_labels": False,
            "validation_files": False,
            "auth_txt": False,
            "accepted_jsonl": False,
            "deployment_csv_only": True,
        },
        "summary": summary_rows,
    }
    manifest_path = out_dir / "v052_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(report)
    print(f"Wrote report: {report_path}")
    print(f"Wrote summary: {out_dir / 'burden_summary.csv'}")
    print(f"Wrote manifest: {manifest_path}")


if __name__ == "__main__":
    main()
