#!/usr/bin/env python3
"""
SRIA RT v0.4.3 - Queue Audit + Tie-Break Analysis

Purpose:
- Audit a v0.4.2 ranked episode queue.
- Summarize top-K composition: gates, sources, users, signals, labels.
- Compare original model ranking against safe tie-break ranking.
- Export analyst-friendly top queue CSVs.

This script does NOT rescan auth.txt.
It reads a ranked CSV from v0.4.2, usually:
  v042_train_v033_score_v036\ranked_v036_tree_depth6_cw_none.csv

Safe tie-break ranking does NOT use labels/redteam_count/exact_start_count.
Those fields are used only for validation reporting.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

TOP_K_DEFAULTS = [20, 50, 100, 500, 1000, 5000, 10000]

SAFE_TIE_FIELDS = [
    ("model_score", True),
    ("novelty_ratio", True),
    ("first_time_signal_hits", True),
    ("destination_count", True),
    ("fanout_velocity_score", True),
    ("peak_velocity_new_dests", True),
    ("compactness_score", True),
    ("duration", False),
    ("events_count", True),
]

ANALYST_FIELDS = [
    "audit_rank",
    "original_rank",
    "tie_rank",
    "rank_delta",
    "branch",
    "source_set",
    "episode_id",
    "start_time",
    "end_time",
    "duration",
    "source",
    "user",
    "candidate_gate",
    "model_score",
    "legacy_sria_score",
    "legacy_raw_score",
    "destination_count",
    "events_count",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "first_time_signal_hits",
    "first_time_event_count",
    "new_destination_event_count",
    "signals",
    # validation-only fields retained for offline analysis
    "label",
    "redteam_count",
    "exact_start_count",
    "redteam_indices",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v0.4.3 queue audit")
    p.add_argument("--input", required=True, help="Input ranked CSV from v0.4.2")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--top-k", default=",".join(map(str, TOP_K_DEFAULTS)), help="Comma-separated K values")
    p.add_argument("--prefix", default="queue", help="Output filename prefix")
    return p.parse_args()


def to_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None or x == "":
            return default
        return float(x)
    except Exception:
        return default


def to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None or x == "":
            return default
        return int(float(x))
    except Exception:
        return default


def load_rows(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=1):
            row = dict(row)
            row["original_rank"] = to_int(row.get("rank"), i)
            row["rank"] = row["original_rank"]
            rows.append(row)
    return rows


def numeric_key(row: Dict[str, Any], field: str, desc: bool) -> float:
    value = to_float(row.get(field), 0.0)
    return -value if desc else value


def safe_tie_sort(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(row: Dict[str, Any]) -> Tuple[Any, ...]:
        parts: List[Any] = []
        for field, desc in SAFE_TIE_FIELDS:
            parts.append(numeric_key(row, field, desc))
        # Stable deterministic final fallback
        parts.append(to_int(row.get("original_rank"), 0))
        return tuple(parts)

    ranked = sorted(rows, key=key)
    for i, row in enumerate(ranked, start=1):
        row["tie_rank"] = i
        row["rank_delta"] = to_int(row.get("original_rank")) - i
    return ranked


def redteam_event_set(rows: Iterable[Dict[str, Any]]) -> set:
    s = set()
    for row in rows:
        raw = str(row.get("redteam_indices", "") or "")
        for part in raw.replace(",", ";").split(";"):
            part = part.strip()
            if part:
                s.add(part)
    return s


def summarize_top(rows: List[Dict[str, Any]], k: int) -> Dict[str, Any]:
    subset = rows[: min(k, len(rows))]
    pos_eps = sum(1 for r in subset if to_int(r.get("label")) == 1)
    rt_events = redteam_event_set(subset)
    exact = sum(to_int(r.get("exact_start_count")) for r in subset)
    gate_counts = Counter(str(r.get("candidate_gate", "UNKNOWN")) for r in subset)
    source_counts = Counter(str(r.get("source", "")) for r in subset if str(r.get("source", "")))
    user_counts = Counter(str(r.get("user", "")) for r in subset if str(r.get("user", "")))
    signal_counts: Counter[str] = Counter()
    for r in subset:
        signals = str(r.get("signals", "") or "")
        for sig in signals.split(";"):
            sig = sig.strip()
            if sig:
                signal_counts[sig] += 1
    return {
        "k": k,
        "rows": len(subset),
        "positive_episodes": pos_eps,
        "episode_precision": pos_eps / len(subset) if subset else 0.0,
        "redteam_events": len(rt_events),
        "exact_start_count": exact,
        "gate_counts": gate_counts,
        "source_counts": source_counts,
        "user_counts": user_counts,
        "signal_counts": signal_counts,
    }


def all_redteam_count(rows: List[Dict[str, Any]]) -> int:
    return len(redteam_event_set(rows))


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ANALYST_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for i, row in enumerate(rows, start=1):
            out = dict(row)
            out["audit_rank"] = i
            # guarantee keys exist
            for field in ANALYST_FIELDS:
                out.setdefault(field, "")
            writer.writerow(out)


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for i, row in enumerate(rows, start=1):
            out = {field: row.get(field, "") for field in ANALYST_FIELDS}
            out["audit_rank"] = i
            f.write(json.dumps(out, sort_keys=True) + "\n")


def report_lines(title: str, rows: List[Dict[str, Any]], top_ks: List[int]) -> List[str]:
    total_rt = all_redteam_count(rows)
    out: List[str] = []
    out.append(title)
    out.append("=" * 88)
    out.append(f"rows: {len(rows):,}")
    out.append(f"positive episodes total: {sum(1 for r in rows if to_int(r.get('label')) == 1):,}")
    out.append(f"unique redteam events represented total: {total_rt:,}")
    out.append("")

    for k in top_ks:
        s = summarize_top(rows, k)
        rt_recall = s["redteam_events"] / total_rt if total_rt else 0.0
        out.append(f"Top {k:,}")
        out.append("-" * 88)
        out.append(
            f"positive_episodes={s['positive_episodes']:,} "
            f"episode_precision={s['episode_precision']:.6f} "
            f"redteam_events={s['redteam_events']:,} "
            f"redteam_recall={rt_recall:.6f} "
            f"exact_start_count={s['exact_start_count']:,}"
        )
        out.append("top gates:")
        for gate, count in s["gate_counts"].most_common(10):
            out.append(f"  {gate}: {count}")
        out.append("top sources:")
        for src, count in s["source_counts"].most_common(10):
            out.append(f"  {src}: {count}")
        out.append("top users:")
        for user, count in s["user_counts"].most_common(10):
            out.append(f"  {user}: {count}")
        out.append("top signals:")
        for sig, count in s["signal_counts"].most_common(15):
            out.append(f"  {sig}: {count}")
        out.append("")
    return out


def write_tie_comparison(path: Path, original: List[Dict[str, Any]], tied: List[Dict[str, Any]], top_ks: List[int]) -> None:
    total_rt = all_redteam_count(original)
    fieldnames = [
        "k",
        "original_pos_eps",
        "original_rt_events",
        "original_rt_recall",
        "tie_pos_eps",
        "tie_rt_events",
        "tie_rt_recall",
        "delta_rt_events",
        "delta_pos_eps",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for k in top_ks:
            o = summarize_top(original, k)
            t = summarize_top(tied, k)
            writer.writerow({
                "k": k,
                "original_pos_eps": o["positive_episodes"],
                "original_rt_events": o["redteam_events"],
                "original_rt_recall": o["redteam_events"] / total_rt if total_rt else 0.0,
                "tie_pos_eps": t["positive_episodes"],
                "tie_rt_events": t["redteam_events"],
                "tie_rt_recall": t["redteam_events"] / total_rt if total_rt else 0.0,
                "delta_rt_events": t["redteam_events"] - o["redteam_events"],
                "delta_pos_eps": t["positive_episodes"] - o["positive_episodes"],
            })


def main() -> None:
    args = parse_args()
    in_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    top_ks = [int(x.strip()) for x in args.top_k.split(",") if x.strip()]

    print(f"Loading ranked queue: {in_path}")
    rows = load_rows(in_path)
    print(f"Loaded rows: {len(rows):,}")

    # Original order is the v0.4.2 order.
    original = sorted(rows, key=lambda r: to_int(r.get("original_rank"), 0))
    tied = safe_tie_sort([dict(r) for r in rows])

    prefix = args.prefix
    report = []
    report.extend(report_lines("Original v0.4.2 Ranking Audit", original, top_ks))
    report.append("\n")
    report.extend(report_lines("Safe Tie-Break Ranking Audit", tied, top_ks))
    report.append("\nSafe tie-break fields, in order:")
    for field, desc in SAFE_TIE_FIELDS:
        report.append(f"  {'DESC' if desc else 'ASC '} {field}")
    report.append("\nNOTE: tie-break ranking does NOT use label, redteam_count, redteam_indices, or exact_start_count.")
    report.append("Those fields are validation-only diagnostics.")

    report_path = out_dir / f"{prefix}_audit_report.txt"
    report_path.write_text("\n".join(report), encoding="utf-8")

    # Export top queues.
    for k in top_ks:
        if k <= len(original):
            write_csv(out_dir / f"{prefix}_original_top{k}.csv", original[:k])
            write_csv(out_dir / f"{prefix}_tie_break_top{k}.csv", tied[:k])
        if k in {20, 100, 500, 1000}:  # compact JSONL samples
            write_jsonl(out_dir / f"{prefix}_original_top{k}.jsonl", original[: min(k, len(original))])
            write_jsonl(out_dir / f"{prefix}_tie_break_top{k}.jsonl", tied[: min(k, len(tied))])

    write_tie_comparison(out_dir / f"{prefix}_tie_break_comparison.csv", original, tied, top_ks)

    print(f"Wrote report: {report_path}")
    print(f"Wrote tie comparison: {out_dir / (prefix + '_tie_break_comparison.csv')}")
    print("Done.")


if __name__ == "__main__":
    main()
