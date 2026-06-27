#!/usr/bin/env python3
"""
sria_rt_v054_source_cluster_packaging.py

SRIA RT v0.5.4 - Source-Cluster Analyst Packaging

Purpose:
- Preserve the uncapped learned-ranker deployment queue.
- Do NOT change ranking, score, model, features, or validation logic.
- Package repeated-source episodes into analyst-readable source clusters.
- Reduce cognitive burden without discarding validated signal.

Inputs:
    v051_deployment_rf_depth10/deployment_queue_top100.csv
    v051_deployment_rf_depth10/deployment_queue_top500.csv
    v051_deployment_rf_depth10/deployment_queue_top1000.csv
    v051_deployment_rf_depth10/deployment_queue_top5000.csv

Optional:
    v051_deployment_rf_depth10/research_debug_queue_top5000.csv
    Used only to annotate clusters with validation/debug counts when available.

Typical CMD use from F:\SRIA\SRIA_RT_v01:
    py sria_rt_v054_source_cluster_packaging.py --queue-dir v051_deployment_rf_depth10 --out-dir v054_source_clusters_rf_depth10 --queue-sizes 100,500,1000,5000 --debug-queue v051_deployment_rf_depth10\research_debug_queue_top5000.csv

Outputs:
    source_cluster_report.txt
    source_cluster_summary_top100.csv
    source_cluster_summary_top500.csv
    source_cluster_summary_top1000.csv
    source_cluster_summary_top5000.csv
    source_cluster_representatives_top100.csv
    source_cluster_representatives_top500.csv
    source_cluster_representatives_top1000.csv
    source_cluster_representatives_top5000.csv
    v054_manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any, Dict, Iterable, List, Optional, Tuple


VALIDATION_FIELD_NAMES = {
    "label",
    "is_positive",
    "positive",
    "redteam_count",
    "redteam_indices",
    "represented_redteam_events",
    "represented_redteam_count",
    "exact_start_count",
    "matched_redteam",
    "matched_redteam_events",
    "redteam_event_count",
    "redteam_group",
    "rt_events",
    "rt_recall",
}


def safe_float(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    try:
        x = float(v)
        if math.isnan(x) or math.isinf(x):
            return default
        return x
    except Exception:
        return default


def safe_int(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    try:
        return int(float(str(v).replace(",", "")))
    except Exception:
        return default


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", errors="replace", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def split_signals(v: Any) -> List[str]:
    if v is None:
        return []
    s = str(v).strip()
    if not s:
        return []
    # Deployment CSV uses semicolon-separated signals.
    if ";" in s:
        return [x.strip() for x in s.split(";") if x.strip()]
    if "," in s:
        return [x.strip() for x in s.split(",") if x.strip()]
    return [s]


def compact_counter(counter: Counter, limit: int = 5) -> str:
    if not counter:
        return ""
    parts = []
    for key, count in counter.most_common(limit):
        parts.append(f"{key}:{count}")
    return ";".join(parts)


def compact_values(values: Iterable[Any], limit: int = 12) -> str:
    seen = []
    added = set()
    for v in values:
        s = str(v).strip()
        if not s or s in added:
            continue
        seen.append(s)
        added.add(s)
        if len(seen) >= limit:
            break
    return ";".join(seen)


def maybe_bool(v: Any) -> bool:
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "positive"}


def get_positive_flag(row: Dict[str, Any]) -> bool:
    for k in ("label", "is_positive", "positive"):
        if k in row and maybe_bool(row.get(k)):
            return True
    return False


def get_redteam_count(row: Dict[str, Any]) -> int:
    for k in ("redteam_count", "represented_redteam_events", "represented_redteam_count", "redteam_event_count", "rt_events"):
        if k in row:
            return safe_int(row.get(k), 0)
    indices = str(row.get("redteam_indices", "")).strip()
    if indices:
        return len([x for x in indices.replace(";", ",").split(",") if x.strip()])
    return 0


def build_debug_by_episode(debug_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in debug_rows:
        ep_id = str(row.get("episode_id") or row.get("id") or "").strip()
        if not ep_id:
            continue
        out[ep_id] = row
    return out


def enrich_with_debug(rows: List[Dict[str, Any]], debug_by_episode: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not debug_by_episode:
        return rows
    enriched = []
    for row in rows:
        r = dict(row)
        ep_id = str(r.get("episode_id") or r.get("id") or "").strip()
        dbg = debug_by_episode.get(ep_id)
        if dbg:
            r["debug_positive"] = "1" if get_positive_flag(dbg) else "0"
            r["debug_redteam_count"] = str(get_redteam_count(dbg))
            r["debug_exact_start_count"] = str(safe_int(dbg.get("exact_start_count"), 0))
        else:
            r["debug_positive"] = "0"
            r["debug_redteam_count"] = "0"
            r["debug_exact_start_count"] = "0"
        enriched.append(r)
    return enriched


def cluster_rows(rows: List[Dict[str, Any]], top_n_representatives: int = 5) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        source = str(row.get("source") or "unknown").strip() or "unknown"
        by_source[source].append(row)

    cluster_summaries: List[Dict[str, Any]] = []
    representatives: List[Dict[str, Any]] = []

    for source, group in by_source.items():
        # The input queue is already ranked; sort defensively by rank.
        group_sorted = sorted(group, key=lambda r: safe_int(r.get("rank"), 10**12))
        ranks = [safe_int(r.get("rank"), 0) for r in group_sorted]
        scores = [safe_float(r.get("sria_rt_model_score"), 0.0) for r in group_sorted]
        starts = [safe_int(r.get("start_time"), 0) for r in group_sorted if str(r.get("start_time", "")).strip()]
        ends = [safe_int(r.get("end_time"), 0) for r in group_sorted if str(r.get("end_time", "")).strip()]
        durations = [safe_float(r.get("duration"), 0.0) for r in group_sorted if str(r.get("duration", "")).strip()]
        dest_counts = [safe_float(r.get("destination_count"), 0.0) for r in group_sorted if str(r.get("destination_count", "")).strip()]
        event_counts = [safe_float(r.get("events_count"), 0.0) for r in group_sorted if str(r.get("events_count", "")).strip()]

        users = [str(r.get("user") or "").strip() for r in group_sorted if str(r.get("user") or "").strip()]
        gates = Counter(str(r.get("candidate_gate") or "unknown").strip() or "unknown" for r in group_sorted)
        severities = Counter(str(r.get("severity") or "unknown").strip() or "unknown" for r in group_sorted)
        priorities = Counter(str(r.get("review_priority") or "unknown").strip() or "unknown" for r in group_sorted)
        signal_counter: Counter = Counter()
        for r in group_sorted:
            signal_counter.update(split_signals(r.get("signals")))

        positive_eps = sum(1 for r in group_sorted if safe_int(r.get("debug_positive"), 0) > 0)
        represented_rt = sum(safe_int(r.get("debug_redteam_count"), 0) for r in group_sorted)
        exact_start = sum(safe_int(r.get("debug_exact_start_count"), 0) for r in group_sorted)

        top_reps = group_sorted[:top_n_representatives]
        rep_ids = [str(r.get("episode_id") or r.get("id") or "") for r in top_reps]
        rep_explanations = [str(r.get("explanation_short") or "") for r in top_reps]

        summary = {
            "source": source,
            "episode_count": len(group_sorted),
            "top_rank": min(ranks) if ranks else "",
            "last_rank": max(ranks) if ranks else "",
            "rank_span": (max(ranks) - min(ranks)) if ranks else "",
            "top_model_score": max(scores) if scores else 0.0,
            "score_max": max(scores) if scores else 0.0,
            "score_median": median(scores) if scores else 0.0,
            "score_min": min(scores) if scores else 0.0,
            "time_min": min(starts) if starts else "",
            "time_max": max(ends) if ends else "",
            "time_span": (max(ends) - min(starts)) if starts and ends else "",
            "unique_user_count": len(set(users)),
            "unique_users": compact_values(users, limit=20),
            "median_duration": median(durations) if durations else "",
            "median_destination_count": median(dest_counts) if dest_counts else "",
            "median_events_count": median(event_counts) if event_counts else "",
            "dominant_gate": gates.most_common(1)[0][0] if gates else "",
            "dominant_gate_count": gates.most_common(1)[0][1] if gates else 0,
            "top_gates": compact_counter(gates, 5),
            "dominant_severity": severities.most_common(1)[0][0] if severities else "",
            "dominant_severity_count": severities.most_common(1)[0][1] if severities else 0,
            "top_review_priorities": compact_counter(priorities, 5),
            "dominant_signal": signal_counter.most_common(1)[0][0] if signal_counter else "",
            "dominant_signal_count": signal_counter.most_common(1)[0][1] if signal_counter else 0,
            "top_signals": compact_counter(signal_counter, 8),
            "representative_episode_ids": compact_values(rep_ids, limit=top_n_representatives),
            "representative_explanations": " || ".join([x for x in rep_explanations if x][:top_n_representatives]),
            "debug_positive_episodes": positive_eps,
            "debug_represented_redteam_events": represented_rt,
            "debug_exact_start_count": exact_start,
        }
        cluster_summaries.append(summary)

        for idx, r in enumerate(top_reps, start=1):
            representatives.append({
                "source": source,
                "cluster_episode_count": len(group_sorted),
                "representative_index": idx,
                "rank": r.get("rank", ""),
                "episode_id": r.get("episode_id", ""),
                "sria_rt_model_score": r.get("sria_rt_model_score", ""),
                "severity": r.get("severity", ""),
                "review_priority": r.get("review_priority", ""),
                "start_time": r.get("start_time", ""),
                "end_time": r.get("end_time", ""),
                "duration": r.get("duration", ""),
                "user": r.get("user", ""),
                "destination_count": r.get("destination_count", ""),
                "events_count": r.get("events_count", ""),
                "candidate_gate": r.get("candidate_gate", ""),
                "explanation_short": r.get("explanation_short", ""),
                "signals": r.get("signals", ""),
                "debug_positive": r.get("debug_positive", ""),
                "debug_redteam_count": r.get("debug_redteam_count", ""),
                "debug_exact_start_count": r.get("debug_exact_start_count", ""),
            })

    cluster_summaries.sort(key=lambda r: (safe_int(r.get("episode_count"), 0), safe_float(r.get("top_model_score"), 0.0)), reverse=True)
    representatives.sort(key=lambda r: (safe_int(r.get("cluster_episode_count"), 0), -safe_int(r.get("representative_index"), 0)), reverse=True)
    return cluster_summaries, representatives


def format_pct(x: float) -> str:
    return f"{x * 100:.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="SRIA RT v0.5.4 source-cluster analyst packaging")
    ap.add_argument("--queue-dir", required=True, help="Directory containing v0.5.1 deployment queue CSVs")
    ap.add_argument("--out-dir", required=True, help="Output directory for v0.5.4 cluster package")
    ap.add_argument("--queue-sizes", default="100,500,1000,5000", help="Comma-separated queue sizes")
    ap.add_argument("--debug-queue", default="", help="Optional v0.5.1 research_debug_queue_top5000.csv for validation annotation only")
    ap.add_argument("--representatives-per-cluster", type=int, default=5, help="Representative top episodes per source cluster")
    args = ap.parse_args()

    queue_dir = Path(args.queue_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    queue_sizes = [int(x.strip()) for x in args.queue_sizes.split(",") if x.strip()]
    reps_per_cluster = max(1, int(args.representatives_per_cluster))

    debug_by_episode: Dict[str, Dict[str, Any]] = {}
    debug_queue_path = Path(args.debug_queue) if args.debug_queue else None
    if debug_queue_path and debug_queue_path.exists():
        debug_rows = read_csv_rows(debug_queue_path)
        debug_by_episode = build_debug_by_episode(debug_rows)
    elif debug_queue_path:
        print(f"[warn] Debug queue not found: {debug_queue_path}")

    print("=" * 80)
    print("SRIA RT v0.5.4 - Source-Cluster Analyst Packaging")
    print("=" * 80)
    print(f"Queue dir: {queue_dir}")
    print(f"Output dir: {out_dir}")
    print(f"Queue sizes: {queue_sizes}")
    print(f"Representatives per cluster: {reps_per_cluster}")
    print(f"Optional debug annotation: {'enabled' if debug_by_episode else 'disabled'}")
    print("NOTE: This script preserves queue ranking and does not remove episodes.")
    print("NOTE: It reads clean deployment queues; optional debug queue only annotates cluster summaries.")
    print("=" * 80)

    cluster_fieldnames = [
        "source", "episode_count", "top_rank", "last_rank", "rank_span",
        "top_model_score", "score_max", "score_median", "score_min",
        "time_min", "time_max", "time_span",
        "unique_user_count", "unique_users",
        "median_duration", "median_destination_count", "median_events_count",
        "dominant_gate", "dominant_gate_count", "top_gates",
        "dominant_severity", "dominant_severity_count", "top_review_priorities",
        "dominant_signal", "dominant_signal_count", "top_signals",
        "representative_episode_ids", "representative_explanations",
        "debug_positive_episodes", "debug_represented_redteam_events", "debug_exact_start_count",
    ]

    representative_fieldnames = [
        "source", "cluster_episode_count", "representative_index", "rank", "episode_id",
        "sria_rt_model_score", "severity", "review_priority", "start_time", "end_time", "duration",
        "user", "destination_count", "events_count", "candidate_gate", "explanation_short", "signals",
        "debug_positive", "debug_redteam_count", "debug_exact_start_count",
    ]

    manifest: Dict[str, Any] = {
        "version": "v0.5.4",
        "purpose": "source-cluster analyst packaging",
        "queue_dir": str(queue_dir),
        "out_dir": str(out_dir),
        "queue_sizes": queue_sizes,
        "representatives_per_cluster": reps_per_cluster,
        "debug_annotation_enabled": bool(debug_by_episode),
        "ranking_policy": "preserve existing uncapped ranking; no episodes removed or reordered inside deployment queue",
        "inputs": {},
        "outputs": {},
    }

    report_lines: List[str] = []
    report_lines.append("SRIA RT v0.5.4 Source-Cluster Analyst Packaging")
    report_lines.append("=" * 80)
    report_lines.append(f"queue_dir: {queue_dir}")
    report_lines.append(f"out_dir: {out_dir}")
    report_lines.append(f"representatives_per_cluster: {reps_per_cluster}")
    report_lines.append("analysis_scope: clean deployment queues; optional debug annotation only")
    report_lines.append("exclusions: no model loading, no auth.txt, no accepted JSONL, no redteam.txt, no queue reranking")
    report_lines.append("")
    report_lines.append("Cluster summary by queue size:")

    for size in queue_sizes:
        input_path = queue_dir / f"deployment_queue_top{size}.csv"
        if not input_path.exists():
            print(f"[warn] Missing queue file: {input_path}")
            report_lines.append(f"  top{size}: MISSING {input_path}")
            manifest["inputs"][f"top{size}"] = {"path": str(input_path), "exists": False}
            continue

        rows = read_csv_rows(input_path)
        rows = enrich_with_debug(rows, debug_by_episode)
        clusters, representatives = cluster_rows(rows, top_n_representatives=reps_per_cluster)

        cluster_path = out_dir / f"source_cluster_summary_top{size}.csv"
        reps_path = out_dir / f"source_cluster_representatives_top{size}.csv"
        write_csv(cluster_path, clusters, cluster_fieldnames)
        write_csv(reps_path, representatives, representative_fieldnames)

        source_count = len(clusters)
        top_cluster = clusters[0] if clusters else {}
        top_episode_count = safe_int(top_cluster.get("episode_count"), 0)
        top_source_share = top_episode_count / len(rows) if rows else 0.0
        top5_count = sum(safe_int(c.get("episode_count"), 0) for c in clusters[:5])
        top10_count = sum(safe_int(c.get("episode_count"), 0) for c in clusters[:10])
        debug_rt_total = sum(safe_int(c.get("debug_represented_redteam_events"), 0) for c in clusters)
        debug_pos_total = sum(safe_int(c.get("debug_positive_episodes"), 0) for c in clusters)

        report_lines.append(
            f"  top{size}: rows={len(rows):,} source_clusters={source_count:,} "
            f"largest_source={top_cluster.get('source', '')} largest_cluster={top_episode_count} "
            f"largest_share={format_pct(top_source_share)} top5_cluster_share={format_pct(top5_count / len(rows) if rows else 0.0)} "
            f"debug_pos_eps={debug_pos_total} debug_rt_events={debug_rt_total}"
        )

        print(
            f"[cluster] top{size}: rows={len(rows):,} clusters={source_count:,} "
            f"largest={top_cluster.get('source', '')}:{top_episode_count} ({format_pct(top_source_share)})"
        )

        manifest["inputs"][f"top{size}"] = {"path": str(input_path), "exists": True, "rows": len(rows)}
        manifest["outputs"][f"source_cluster_summary_top{size}"] = str(cluster_path)
        manifest["outputs"][f"source_cluster_representatives_top{size}"] = str(reps_path)

    report_lines.append("")
    report_lines.append("Interpretation guide:")
    report_lines.append("  - This layer is packaging only: it does not delete, cap, rerank, or rescore episodes.")
    report_lines.append("  - Large clusters indicate analyst batching opportunities, not automatic suppression candidates.")
    report_lines.append("  - Preserve the uncapped queue as the decision source; use cluster summaries as the review interface.")
    report_lines.append("")
    report_lines.append("Generated files:")
    report_lines.append("  source_cluster_summary_top*.csv")
    report_lines.append("  source_cluster_representatives_top*.csv")
    report_lines.append("  source_cluster_report.txt")
    report_lines.append("  v054_manifest.json")

    report_path = out_dir / "source_cluster_report.txt"
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8", errors="replace")
    manifest_path = out_dir / "v054_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8", errors="replace")

    print("=" * 80)
    print("\n".join(report_lines))
    print(f"\nWrote report: {report_path}")
    print(f"Wrote manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
