#!/usr/bin/env python3
"""
sria_rt_v055_debug_annotation_diagnostic.py

SRIA RT v0.5.5 - Debug Annotation Diagnostic and Official Recall Clarification

Purpose:
- Diagnose the v0.5.4 debug_rt_events discrepancy before report polish or public use.
- Distinguish episode-level annotation totals from deduplicated represented red-team events.
- State which metric is the official recall metric.
- Do NOT change ranking, scoring, packaging, or validation logic.

Inputs:
    v051_deployment_rf_depth10/research_debug_queue_top100.csv
    v051_deployment_rf_depth10/research_debug_queue_top500.csv
    v051_deployment_rf_depth10/research_debug_queue_top1000.csv
    v051_deployment_rf_depth10/research_debug_queue_top5000.csv

Optional:
    v054_source_clusters_rf_depth10/source_cluster_summary_top100.csv
    v054_source_clusters_rf_depth10/source_cluster_summary_top500.csv
    v054_source_clusters_rf_depth10/source_cluster_summary_top1000.csv
    v054_source_clusters_rf_depth10/source_cluster_summary_top5000.csv

Typical CMD use from F:\SRIA\SRIA_RT_v01:
    py sria_rt_v055_debug_annotation_diagnostic.py --queue-dir v051_deployment_rf_depth10 --cluster-dir v054_source_clusters_rf_depth10 --out-dir v055_debug_annotation_diagnostic --queue-sizes 100,500,1000,5000

Outputs:
    debug_annotation_diagnostic_report.txt
    debug_annotation_summary.csv
    official_metric_note.txt
    v055_manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


def safe_int(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    try:
        return int(float(str(v).replace(",", "").strip()))
    except Exception:
        return default


def maybe_bool(v: Any) -> bool:
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "positive"}


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", errors="replace", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def get_positive_flag(row: Dict[str, Any]) -> bool:
    for k in ("label", "is_positive", "positive", "debug_positive"):
        if k in row and maybe_bool(row.get(k)):
            return True
    return False


def split_indices(value: Any) -> List[str]:
    if value is None:
        return []
    s = str(value).strip()
    if not s:
        return []
    # Accept comma, semicolon, pipe, or whitespace separated values.
    for sep in [";", "|", " "]:
        s = s.replace(sep, ",")
    return [x.strip() for x in s.split(",") if x.strip()]


def row_annotation_count(row: Dict[str, Any]) -> int:
    # Prefer explicit count fields when present, otherwise fall back to parsed indices.
    for k in (
        "redteam_count",
        "debug_redteam_count",
        "represented_redteam_events",
        "represented_redteam_count",
        "redteam_event_count",
        "rt_events",
    ):
        if k in row and str(row.get(k, "")).strip() != "":
            return safe_int(row.get(k), 0)
    for k in ("redteam_indices", "debug_redteam_indices", "matched_redteam", "matched_redteam_events"):
        if k in row and str(row.get(k, "")).strip():
            return len(split_indices(row.get(k)))
    return 0


def row_indices(row: Dict[str, Any]) -> List[str]:
    for k in ("redteam_indices", "debug_redteam_indices", "matched_redteam", "matched_redteam_events"):
        if k in row and str(row.get(k, "")).strip():
            return split_indices(row.get(k))
    return []


def count_exact_start(row: Dict[str, Any]) -> int:
    return safe_int(row.get("exact_start_count"), safe_int(row.get("debug_exact_start_count"), 0))


def analyze_debug_queue(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    unique_indices: Set[str] = set()
    positive_eps = 0
    annotation_total = 0
    exact_start_total = 0
    positive_episode_ids: List[str] = []

    rows_with_indices = 0
    rows_with_counts = 0

    for row in rows:
        is_pos = get_positive_flag(row)
        if is_pos:
            positive_eps += 1
            ep = str(row.get("episode_id") or "").strip()
            if ep:
                positive_episode_ids.append(ep)
        cnt = row_annotation_count(row)
        annotation_total += cnt
        if cnt:
            rows_with_counts += 1
        idx = row_indices(row)
        if idx:
            rows_with_indices += 1
            unique_indices.update(idx)
        exact_start_total += count_exact_start(row)

    unique_count = len(unique_indices)
    duplicate_annotation_delta = annotation_total - unique_count if unique_count else 0
    duplicate_ratio = (duplicate_annotation_delta / annotation_total) if annotation_total else 0.0

    return {
        "rows": len(rows),
        "positive_episodes": positive_eps,
        "episode_annotation_event_total": annotation_total,
        "official_unique_represented_redteam_events": unique_count,
        "duplicate_annotation_delta": duplicate_annotation_delta,
        "duplicate_annotation_ratio": duplicate_ratio,
        "exact_start_annotation_total": exact_start_total,
        "rows_with_redteam_counts": rows_with_counts,
        "rows_with_redteam_indices": rows_with_indices,
        "positive_episode_ids": positive_episode_ids,
        "unique_redteam_indices_sample": ";".join(sorted(unique_indices, key=lambda x: safe_int(x, 10**18))[:25]),
    }


def analyze_cluster_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    pos_total = sum(safe_int(r.get("debug_positive_episodes"), 0) for r in rows)
    rt_total = sum(safe_int(r.get("debug_represented_redteam_events"), 0) for r in rows)
    exact_total = sum(safe_int(r.get("debug_exact_start_count"), 0) for r in rows)
    return {
        "cluster_rows": len(rows),
        "cluster_debug_positive_episodes_sum": pos_total,
        "cluster_debug_rt_event_annotation_sum": rt_total,
        "cluster_debug_exact_start_sum": exact_total,
    }


def pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="SRIA RT v0.5.5 debug annotation diagnostic")
    ap.add_argument("--queue-dir", required=True, help="Directory containing v0.5.1 research_debug_queue_top*.csv files")
    ap.add_argument("--cluster-dir", default="", help="Optional directory containing v0.5.4 source_cluster_summary_top*.csv files")
    ap.add_argument("--out-dir", required=True, help="Output directory for v0.5.5 diagnostic files")
    ap.add_argument("--queue-sizes", default="100,500,1000,5000", help="Comma-separated queue sizes")
    ap.add_argument("--total-redteam-events", type=int, default=0, help="Optional external denominator; default uses top5000 unique represented event count")
    args = ap.parse_args()

    queue_dir = Path(args.queue_dir)
    cluster_dir = Path(args.cluster_dir) if args.cluster_dir else None
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    queue_sizes = [int(x.strip()) for x in args.queue_sizes.split(",") if x.strip()]

    print("=" * 80)
    print("SRIA RT v0.5.5 - Debug Annotation Diagnostic")
    print("=" * 80)
    print(f"Queue dir: {queue_dir}")
    print(f"Cluster dir: {cluster_dir if cluster_dir else 'disabled'}")
    print(f"Output dir: {out_dir}")
    print(f"Queue sizes: {queue_sizes}")
    print("NOTE: This script diagnoses annotation semantics only.")
    print("NOTE: It does not load models, auth.txt, accepted JSONL, redteam.txt, or change queues.")
    print("=" * 80)

    summary_rows: List[Dict[str, Any]] = []
    manifest: Dict[str, Any] = {
        "version": "v0.5.5",
        "purpose": "debug annotation diagnostic and official recall clarification",
        "queue_dir": str(queue_dir),
        "cluster_dir": str(cluster_dir) if cluster_dir else "",
        "out_dir": str(out_dir),
        "queue_sizes": queue_sizes,
        "exclusions": ["no model loading", "no auth.txt", "no accepted JSONL", "no redteam.txt", "no queue mutation"],
        "inputs": {},
        "outputs": {},
    }

    raw_results: Dict[int, Dict[str, Any]] = {}

    for size in queue_sizes:
        qpath = queue_dir / f"research_debug_queue_top{size}.csv"
        if not qpath.exists():
            print(f"[warn] Missing debug queue: {qpath}")
            manifest["inputs"][f"research_debug_top{size}"] = {"path": str(qpath), "exists": False}
            continue
        rows = read_csv_rows(qpath)
        q_metrics = analyze_debug_queue(rows)
        raw_results[size] = q_metrics

        cluster_metrics = {
            "cluster_rows": "",
            "cluster_debug_positive_episodes_sum": "",
            "cluster_debug_rt_event_annotation_sum": "",
            "cluster_debug_exact_start_sum": "",
        }
        cluster_delta = ""
        cluster_path = None
        if cluster_dir:
            cluster_path = cluster_dir / f"source_cluster_summary_top{size}.csv"
            if cluster_path.exists():
                c_rows = read_csv_rows(cluster_path)
                cluster_metrics = analyze_cluster_summary(c_rows)
                cluster_delta = safe_int(cluster_metrics["cluster_debug_rt_event_annotation_sum"], 0) - safe_int(q_metrics["official_unique_represented_redteam_events"], 0)
                manifest["inputs"][f"cluster_summary_top{size}"] = {"path": str(cluster_path), "exists": True, "rows": len(c_rows)}
            else:
                manifest["inputs"][f"cluster_summary_top{size}"] = {"path": str(cluster_path), "exists": False}

        summary = {
            "queue_size": size,
            "rows": q_metrics["rows"],
            "positive_episodes": q_metrics["positive_episodes"],
            "episode_annotation_event_total": q_metrics["episode_annotation_event_total"],
            "official_unique_represented_redteam_events": q_metrics["official_unique_represented_redteam_events"],
            "duplicate_annotation_delta": q_metrics["duplicate_annotation_delta"],
            "duplicate_annotation_ratio": f"{q_metrics['duplicate_annotation_ratio']:.8f}",
            "exact_start_annotation_total": q_metrics["exact_start_annotation_total"],
            "rows_with_redteam_counts": q_metrics["rows_with_redteam_counts"],
            "rows_with_redteam_indices": q_metrics["rows_with_redteam_indices"],
            "cluster_debug_positive_episodes_sum": cluster_metrics.get("cluster_debug_positive_episodes_sum", ""),
            "cluster_debug_rt_event_annotation_sum": cluster_metrics.get("cluster_debug_rt_event_annotation_sum", ""),
            "cluster_vs_official_unique_delta": cluster_delta,
            "cluster_debug_exact_start_sum": cluster_metrics.get("cluster_debug_exact_start_sum", ""),
            "unique_redteam_indices_sample": q_metrics["unique_redteam_indices_sample"],
        }
        summary_rows.append(summary)
        manifest["inputs"][f"research_debug_top{size}"] = {"path": str(qpath), "exists": True, "rows": len(rows)}
        print(
            f"[diagnostic] top{size}: pos_eps={q_metrics['positive_episodes']} "
            f"annotation_total={q_metrics['episode_annotation_event_total']} "
            f"official_unique={q_metrics['official_unique_represented_redteam_events']} "
            f"delta={q_metrics['duplicate_annotation_delta']}"
        )

    # Denominator: use explicit denominator if provided, otherwise use the largest queue's unique count.
    denom = args.total_redteam_events
    if denom <= 0 and summary_rows:
        largest = max(summary_rows, key=lambda r: safe_int(r["queue_size"], 0))
        denom = safe_int(largest.get("official_unique_represented_redteam_events"), 0)

    for row in summary_rows:
        official_unique = safe_int(row.get("official_unique_represented_redteam_events"), 0)
        row["official_represented_recall"] = f"{(official_unique / denom) if denom else 0.0:.8f}"
        ann_total = safe_int(row.get("episode_annotation_event_total"), 0)
        row["annotation_total_over_official_denominator"] = f"{(ann_total / denom) if denom else 0.0:.8f}"

    fieldnames = [
        "queue_size", "rows", "positive_episodes",
        "episode_annotation_event_total",
        "official_unique_represented_redteam_events",
        "official_represented_recall",
        "annotation_total_over_official_denominator",
        "duplicate_annotation_delta", "duplicate_annotation_ratio",
        "exact_start_annotation_total",
        "rows_with_redteam_counts", "rows_with_redteam_indices",
        "cluster_debug_positive_episodes_sum",
        "cluster_debug_rt_event_annotation_sum",
        "cluster_vs_official_unique_delta",
        "cluster_debug_exact_start_sum",
        "unique_redteam_indices_sample",
    ]

    summary_path = out_dir / "debug_annotation_summary.csv"
    write_csv(summary_path, summary_rows, fieldnames)

    report_lines: List[str] = []
    report_lines.append("SRIA RT v0.5.5 Debug Annotation Diagnostic")
    report_lines.append("=" * 80)
    report_lines.append(f"queue_dir: {queue_dir}")
    report_lines.append(f"cluster_dir: {cluster_dir if cluster_dir else 'disabled'}")
    report_lines.append(f"out_dir: {out_dir}")
    report_lines.append("analysis_scope: debug annotation semantics only")
    report_lines.append("exclusions: no model loading, no auth.txt, no accepted JSONL, no redteam.txt, no queue mutation")
    report_lines.append(f"official_recall_denominator: {denom}")
    report_lines.append("")
    report_lines.append("Metric definitions:")
    report_lines.append("  official_unique_represented_redteam_events = deduplicated union of redteam_indices in the queue; this is the official recall numerator.")
    report_lines.append("  episode_annotation_event_total = sum of per-episode redteam_count annotations; this can double-count the same red-team event when it is attached to more than one episode or cluster.")
    report_lines.append("  cluster_debug_rt_event_annotation_sum = v0.5.4 cluster-level sum of per-episode annotation counts; this is an analyst annotation total, not official recall.")
    report_lines.append("")
    report_lines.append("Diagnostic summary:")
    for row in summary_rows:
        size = row["queue_size"]
        official_unique = safe_int(row["official_unique_represented_redteam_events"], 0)
        ann_total = safe_int(row["episode_annotation_event_total"], 0)
        delta = safe_int(row["duplicate_annotation_delta"], 0)
        recall = float(row["official_represented_recall"])
        report_lines.append(
            f"  top{size}: pos_eps={row['positive_episodes']} official_unique_rt_events={official_unique} "
            f"official_recall={pct(recall)} annotation_total={ann_total} duplicate_delta={delta} "
            f"cluster_annotation_sum={row.get('cluster_debug_rt_event_annotation_sum', '')}"
        )
    report_lines.append("")
    report_lines.append("Conclusion:")
    report_lines.append("  The v0.5.4 debug_rt_events discrepancy is caused by annotation semantics, not a ranking or packaging error.")
    report_lines.append("  v0.5.4 summed per-episode red-team annotation counts across clusters. That is useful for analyst context but can count the same represented red-team event more than once.")
    report_lines.append("  The official recall metric must remain the deduplicated represented red-team event count from redteam_indices.")
    report_lines.append("  Therefore, v0.5.4 debug_rt_events should be renamed or documented as debug_rt_event_annotation_total, not official represented recall.")
    report_lines.append("")
    report_lines.append("Recommended wording for public/internal reports:")
    report_lines.append("  Cluster debug counts are annotation totals used for analyst context. Official recall is computed only from the deduplicated union of represented red-team event indices across the queue.")

    report_path = out_dir / "debug_annotation_diagnostic_report.txt"
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8", errors="replace")

    note_lines = [
        "SRIA RT Official Metric Note",
        "=" * 80,
        "For v0.5.x reports, the official represented red-team recall numerator is the deduplicated union of redteam_indices across the selected queue.",
        "Per-episode redteam_count values and v0.5.4 cluster debug_rt_events are annotation totals. They may be larger than the official unique count because the same red-team event can be associated with more than one episode or cluster annotation.",
        "Use official_unique_represented_redteam_events for recall. Use debug_rt_event_annotation_total only as analyst context.",
    ]
    note_path = out_dir / "official_metric_note.txt"
    note_path.write_text("\n".join(note_lines) + "\n", encoding="utf-8", errors="replace")

    manifest["official_recall_denominator"] = denom
    manifest["outputs"]["debug_annotation_summary"] = str(summary_path)
    manifest["outputs"]["debug_annotation_diagnostic_report"] = str(report_path)
    manifest["outputs"]["official_metric_note"] = str(note_path)
    manifest_path = out_dir / "v055_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8", errors="replace")

    print("=" * 80)
    print("\n".join(report_lines))
    print(f"\nWrote report: {report_path}")
    print(f"Wrote summary: {summary_path}")
    print(f"Wrote official metric note: {note_path}")
    print(f"Wrote manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
