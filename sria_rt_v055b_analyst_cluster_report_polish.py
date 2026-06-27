#!/usr/bin/env python3
r"""
sria_rt_v055b_analyst_cluster_report_polish.py

SRIA RT v0.5.5b - Analyst Cluster Report Polish

Purpose:
- Produce a clean analyst-facing report from v0.5.4 source-cluster outputs.
- Incorporate the v0.5.5 official metric note so debug annotation totals are not confused with official recall.
- Preserve queue ranking and packaging outputs exactly as produced upstream.
- Do NOT rescore, rerank, cap, filter, mutate, or validate episodes.

Inputs:
    v054_source_clusters_rf_depth10/source_cluster_summary_top100.csv
    v054_source_clusters_rf_depth10/source_cluster_summary_top500.csv
    v054_source_clusters_rf_depth10/source_cluster_summary_top1000.csv
    v054_source_clusters_rf_depth10/source_cluster_summary_top5000.csv
    v054_source_clusters_rf_depth10/source_cluster_representatives_top100.csv
    v054_source_clusters_rf_depth10/source_cluster_representatives_top500.csv
    v055_debug_annotation_diagnostic/official_metric_note.txt
    v055_debug_annotation_diagnostic/debug_annotation_summary.csv

Typical CMD use from F:\SRIA\SRIA_RT_v01:
    py sria_rt_v055b_analyst_cluster_report_polish.py --cluster-dir v054_source_clusters_rf_depth10 --diagnostic-dir v055_debug_annotation_diagnostic --out-dir v055b_analyst_cluster_packet --queue-sizes 100,500,1000,5000 --focus-source C17693

Outputs:
    analyst_cluster_packet.txt
    analyst_cluster_packet.md
    analyst_cluster_summary.csv
    top_clusters_for_briefing.csv
    representative_episode_briefing.csv
    v055b_manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(str(v).replace(",", "")))
    except Exception:
        return default


def safe_float(v: Any, default: float = 0.0) -> float:
    try:
        x = float(str(v).replace(",", ""))
        if math.isnan(x) or math.isinf(x):
            return default
        return x
    except Exception:
        return default


def pct(v: float) -> str:
    return f"{v * 100:.2f}%"


def fmt_num(v: Any) -> str:
    if isinstance(v, int):
        return f"{v:,}"
    try:
        x = float(v)
        if x.is_integer():
            return f"{int(x):,}"
        return f"{x:,.6f}"
    except Exception:
        return str(v)


def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return [dict(r) for r in csv.DictReader(f)]


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", errors="replace", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def first_nonempty(*values: Any) -> str:
    for v in values:
        if v is not None and str(v).strip() != "":
            return str(v)
    return ""


def load_diagnostic_summary(diagnostic_dir: Path) -> Dict[int, Dict[str, str]]:
    rows = read_csv(diagnostic_dir / "debug_annotation_summary.csv")
    out: Dict[int, Dict[str, str]] = {}
    for r in rows:
        q = safe_int(r.get("queue_size"))
        if q:
            out[q] = r
    return out


def read_metric_note(diagnostic_dir: Path) -> str:
    p = diagnostic_dir / "official_metric_note.txt"
    if p.exists():
        return p.read_text(encoding="utf-8", errors="replace").strip()
    return (
        "Cluster debug counts are annotation totals used for analyst context. "
        "Official recall is computed only from the deduplicated union of represented red-team event indices across the queue."
    )


def summarize_queue(size: int, clusters: List[Dict[str, str]], diagnostic: Optional[Dict[str, str]]) -> Dict[str, Any]:
    if not clusters:
        return {"queue_size": size, "error": "missing cluster summary"}

    rows = sum(safe_int(c.get("episode_count")) for c in clusters)
    cluster_count = len(clusters)
    largest = clusters[0]
    largest_count = safe_int(largest.get("episode_count"))
    largest_share = largest_count / rows if rows else 0.0
    top5_share = sum(safe_int(c.get("episode_count")) for c in clusters[:5]) / rows if rows else 0.0
    top10_share = sum(safe_int(c.get("episode_count")) for c in clusters[:10]) / rows if rows else 0.0

    debug_pos = safe_int(first_nonempty(largest.get("__queue_debug_pos"), diagnostic.get("positive_episodes") if diagnostic else ""))
    official_unique = safe_int(diagnostic.get("official_unique_represented_redteam_events") if diagnostic else 0)
    official_recall = safe_float(diagnostic.get("official_represented_recall") if diagnostic else 0.0)
    annotation_total = safe_int(diagnostic.get("episode_annotation_event_total") if diagnostic else 0)
    duplicate_delta = safe_int(diagnostic.get("duplicate_annotation_delta") if diagnostic else 0)

    return {
        "queue_size": size,
        "rows": rows,
        "source_clusters": cluster_count,
        "largest_source": largest.get("source", ""),
        "largest_cluster_count": largest_count,
        "largest_cluster_share": largest_share,
        "top5_cluster_share": top5_share,
        "top10_cluster_share": top10_share,
        "official_positive_episodes": safe_int(diagnostic.get("positive_episodes") if diagnostic else debug_pos),
        "official_unique_represented_redteam_events": official_unique,
        "official_represented_recall": official_recall,
        "annotation_event_total": annotation_total,
        "duplicate_annotation_delta": duplicate_delta,
        "median_largest_cluster_score": largest.get("score_median", ""),
        "largest_cluster_unique_users": largest.get("unique_user_count", ""),
        "largest_cluster_time_span": largest.get("time_span", ""),
        "largest_cluster_dominant_gate": largest.get("dominant_gate", ""),
        "error": "",
    }


def top_clusters_brief(size: int, clusters: List[Dict[str, str]], limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in clusters[:limit]:
        out.append({
            "queue_size": size,
            "source": c.get("source", ""),
            "episode_count": c.get("episode_count", ""),
            "top_rank": c.get("top_rank", ""),
            "last_rank": c.get("last_rank", ""),
            "top_model_score": c.get("top_model_score", ""),
            "score_median": c.get("score_median", ""),
            "time_min": c.get("time_min", ""),
            "time_max": c.get("time_max", ""),
            "time_span": c.get("time_span", ""),
            "unique_user_count": c.get("unique_user_count", ""),
            "median_duration": c.get("median_duration", ""),
            "median_destination_count": c.get("median_destination_count", ""),
            "median_events_count": c.get("median_events_count", ""),
            "dominant_gate": c.get("dominant_gate", ""),
            "top_gates": c.get("top_gates", ""),
            "dominant_signal": c.get("dominant_signal", ""),
            "top_signals": c.get("top_signals", ""),
            "representative_episode_ids": c.get("representative_episode_ids", ""),
            "debug_positive_episodes_annotation": c.get("debug_positive_episodes", ""),
            "debug_rt_event_annotation_total": c.get("debug_represented_redteam_events", ""),
            "debug_exact_start_annotation_total": c.get("debug_exact_start_count", ""),
        })
    return out


def representative_brief(size: int, reps: List[Dict[str, str]], source_filter: str = "", limit: int = 20) -> List[Dict[str, Any]]:
    rows = reps
    if source_filter:
        rows = [r for r in reps if r.get("source") == source_filter]
    out: List[Dict[str, Any]] = []
    for r in rows[:limit]:
        out.append({
            "queue_size": size,
            "source": r.get("source", ""),
            "cluster_episode_count": r.get("cluster_episode_count", ""),
            "representative_index": r.get("representative_index", ""),
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
            "debug_positive": r.get("debug_positive", ""),
            "debug_redteam_count_annotation": r.get("debug_redteam_count", ""),
            "debug_exact_start_count_annotation": r.get("debug_exact_start_count", ""),
        })
    return out


def make_report(
    queue_sizes: List[int],
    summaries: List[Dict[str, Any]],
    clusters_by_size: Dict[int, List[Dict[str, str]]],
    reps_by_size: Dict[int, List[Dict[str, str]]],
    metric_note: str,
    focus_source: str,
    top_cluster_limit: int,
) -> str:
    lines: List[str] = []
    add = lines.append
    add("SRIA RT v0.5.5b Analyst Cluster Packet")
    add("=" * 80)
    add("Purpose: analyst-facing report over the v0.5.4 source-cluster packaging output.")
    add("Scope: packaging/reporting only; no scoring, ranking, filtering, model loading, or validation recomputation.")
    add("")
    add("Official metric note:")
    add(f"  {metric_note}")
    add("")
    add("Executive summary:")
    for s in summaries:
        if s.get("error"):
            add(f"  top{s.get('queue_size')}: ERROR: {s.get('error')}")
            continue
        add(
            f"  top{s['queue_size']}: rows={fmt_num(s['rows'])} "
            f"clusters={fmt_num(s['source_clusters'])} "
            f"largest={s['largest_source']}:{fmt_num(s['largest_cluster_count'])} ({pct(s['largest_cluster_share'])}) "
            f"top5_cluster_share={pct(s['top5_cluster_share'])} "
            f"official_recall={pct(s['official_represented_recall'])} "
            f"official_rt_events={fmt_num(s['official_unique_represented_redteam_events'])} "
            f"annotation_total={fmt_num(s['annotation_event_total'])}"
        )
    add("")
    add("Interpretation:")
    add("  The uncapped ranking is preserved as the decision source.")
    add("  Source clusters are an analyst batching interface, not suppression rules.")
    add("  Large repeated-source clusters should be reviewed as structured activity bundles.")
    add("  Debug annotation totals may exceed official recall numerators because annotations can double-count represented events.")
    add("")

    for size in queue_sizes:
        clusters = clusters_by_size.get(size, [])
        reps = reps_by_size.get(size, [])
        if not clusters:
            continue
        add("-" * 80)
        add(f"Top {size} Analyst Packet")
        add("-" * 80)
        s = next((x for x in summaries if x.get("queue_size") == size), {})
        add(
            f"Queue breadth: {fmt_num(s.get('source_clusters', 0))} source clusters across "
            f"{fmt_num(s.get('rows', 0))} episodes. Largest cluster is "
            f"{s.get('largest_source', '')} with {fmt_num(s.get('largest_cluster_count', 0))} episodes "
            f"({pct(safe_float(s.get('largest_cluster_share', 0.0)))})."
        )
        add(
            f"Official validation summary: {fmt_num(s.get('official_positive_episodes', 0))} positive episodes; "
            f"{fmt_num(s.get('official_unique_represented_redteam_events', 0))} deduplicated represented red-team events; "
            f"official represented recall {pct(safe_float(s.get('official_represented_recall', 0.0)))}."
        )
        add("")
        add(f"Top {min(top_cluster_limit, len(clusters))} source clusters:")
        for c in clusters[:top_cluster_limit]:
            add(
                f"  - {c.get('source','')}: episodes={c.get('episode_count','')} ranks={c.get('top_rank','')}-{c.get('last_rank','')} "
                f"users={c.get('unique_user_count','')} span={c.get('time_span','')}s "
                f"gate={c.get('dominant_gate','')} score_max={c.get('score_max','')} "
                f"debug_annotation_total={c.get('debug_represented_redteam_events','')}"
            )
        add("")
        if focus_source:
            focus_cluster = next((c for c in clusters if c.get("source") == focus_source), None)
            if focus_cluster:
                add(f"Focus cluster: {focus_source}")
                add(
                    f"  episodes={focus_cluster.get('episode_count','')} top_rank={focus_cluster.get('top_rank','')} "
                    f"last_rank={focus_cluster.get('last_rank','')} time_span={focus_cluster.get('time_span','')}s "
                    f"unique_users={focus_cluster.get('unique_user_count','')} dominant_gate={focus_cluster.get('dominant_gate','')}"
                )
                add(f"  top_gates={focus_cluster.get('top_gates','')}")
                add(f"  top_signals={focus_cluster.get('top_signals','')}")
                add(f"  representative_episode_ids={focus_cluster.get('representative_episode_ids','')}")
                focus_reps = [r for r in reps if r.get("source") == focus_source][:5]
                if focus_reps:
                    add("  representative episodes:")
                    for r in focus_reps:
                        add(
                            f"    rank {r.get('rank','')}, episode {r.get('episode_id','')}, user={r.get('user','')}, "
                            f"score={r.get('sria_rt_model_score','')}, gate={r.get('candidate_gate','')}, "
                            f"explanation={r.get('explanation_short','')}"
                        )
                add("")
    add("Recommended use:")
    add("  Use deployment queues for ranked review order.")
    add("  Use this packet to batch repeated-source activity into analyst-readable clusters.")
    add("  Use official deduplicated recall values in research/reporting claims.")
    add("  Treat annotation totals as contextual debug metadata only.")
    add("")
    return "\n".join(lines)


def make_markdown(text_report: str) -> str:
    lines = text_report.splitlines()
    out: List[str] = []
    for i, line in enumerate(lines):
        if i == 0:
            out.append(f"# {line}")
        elif set(line) in ({"="}, {"-"}) and len(line) >= 20:
            continue
        elif line.endswith("Analyst Packet") and line.startswith("Top "):
            out.append(f"## {line}")
        elif line in {"Official metric note:", "Executive summary:", "Interpretation:", "Recommended use:"}:
            out.append(f"## {line[:-1]}")
        elif line.startswith("  - "):
            out.append(line[2:])
        elif line.startswith("  "):
            out.append(line)
        else:
            out.append(line)
    return "\n".join(out) + "\n"


def parse_int_list(s: str) -> List[int]:
    vals: List[int] = []
    for part in str(s).split(","):
        part = part.strip()
        if part:
            vals.append(int(part))
    return vals


def main() -> None:
    ap = argparse.ArgumentParser(description="SRIA RT v0.5.5b analyst cluster report polish")
    ap.add_argument("--cluster-dir", required=True, help="Directory containing v0.5.4 source cluster outputs")
    ap.add_argument("--diagnostic-dir", required=True, help="Directory containing v0.5.5 debug annotation diagnostic outputs")
    ap.add_argument("--out-dir", required=True, help="Output directory for polished analyst packet")
    ap.add_argument("--queue-sizes", default="100,500,1000,5000", help="Comma-separated queue sizes")
    ap.add_argument("--focus-source", default="C17693", help="Optional source to highlight in report")
    ap.add_argument("--top-clusters", type=int, default=10, help="Number of top clusters to include in report/briefing")
    args = ap.parse_args()

    cluster_dir = Path(args.cluster_dir)
    diagnostic_dir = Path(args.diagnostic_dir)
    out_dir = Path(args.out_dir)
    queue_sizes = parse_int_list(args.queue_sizes)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SRIA RT v0.5.5b - Analyst Cluster Report Polish")
    print("=" * 80)
    print(f"Cluster dir: {cluster_dir}")
    print(f"Diagnostic dir: {diagnostic_dir}")
    print(f"Output dir: {out_dir}")
    print(f"Queue sizes: {queue_sizes}")
    print(f"Focus source: {args.focus_source}")
    print("NOTE: This is a reporting layer only; it does not mutate queues or recompute scores.")
    print("=" * 80)

    diagnostic = load_diagnostic_summary(diagnostic_dir)
    metric_note = read_metric_note(diagnostic_dir)

    clusters_by_size: Dict[int, List[Dict[str, str]]] = {}
    reps_by_size: Dict[int, List[Dict[str, str]]] = {}
    summaries: List[Dict[str, Any]] = []
    top_cluster_rows: List[Dict[str, Any]] = []
    representative_rows: List[Dict[str, Any]] = []

    for size in queue_sizes:
        cluster_path = cluster_dir / f"source_cluster_summary_top{size}.csv"
        reps_path = cluster_dir / f"source_cluster_representatives_top{size}.csv"
        clusters = read_csv(cluster_path)
        reps = read_csv(reps_path)
        clusters_by_size[size] = clusters
        reps_by_size[size] = reps
        summary = summarize_queue(size, clusters, diagnostic.get(size))
        summaries.append(summary)
        top_cluster_rows.extend(top_clusters_brief(size, clusters, args.top_clusters))
        representative_rows.extend(representative_brief(size, reps, args.focus_source, limit=20))
        if clusters:
            print(
                f"[packet] top{size}: clusters={len(clusters):,} largest={clusters[0].get('source')}:{clusters[0].get('episode_count')} "
                f"official_recall={pct(safe_float(summary.get('official_represented_recall', 0.0)))}"
            )
        else:
            print(f"[packet] top{size}: missing cluster file {cluster_path}")

    summary_fields = [
        "queue_size", "rows", "source_clusters", "largest_source", "largest_cluster_count", "largest_cluster_share",
        "top5_cluster_share", "top10_cluster_share", "official_positive_episodes",
        "official_unique_represented_redteam_events", "official_represented_recall", "annotation_event_total",
        "duplicate_annotation_delta", "median_largest_cluster_score", "largest_cluster_unique_users",
        "largest_cluster_time_span", "largest_cluster_dominant_gate", "error"
    ]
    cluster_fields = [
        "queue_size", "source", "episode_count", "top_rank", "last_rank", "top_model_score", "score_median",
        "time_min", "time_max", "time_span", "unique_user_count", "median_duration", "median_destination_count",
        "median_events_count", "dominant_gate", "top_gates", "dominant_signal", "top_signals",
        "representative_episode_ids", "debug_positive_episodes_annotation", "debug_rt_event_annotation_total",
        "debug_exact_start_annotation_total"
    ]
    rep_fields = [
        "queue_size", "source", "cluster_episode_count", "representative_index", "rank", "episode_id",
        "sria_rt_model_score", "severity", "review_priority", "start_time", "end_time", "duration", "user",
        "destination_count", "events_count", "candidate_gate", "explanation_short", "debug_positive",
        "debug_redteam_count_annotation", "debug_exact_start_count_annotation"
    ]

    write_csv(out_dir / "analyst_cluster_summary.csv", summaries, summary_fields)
    write_csv(out_dir / "top_clusters_for_briefing.csv", top_cluster_rows, cluster_fields)
    write_csv(out_dir / "representative_episode_briefing.csv", representative_rows, rep_fields)

    report = make_report(queue_sizes, summaries, clusters_by_size, reps_by_size, metric_note, args.focus_source, args.top_clusters)
    write_text(out_dir / "analyst_cluster_packet.txt", report)
    write_text(out_dir / "analyst_cluster_packet.md", make_markdown(report))

    manifest = {
        "version": "v0.5.5b",
        "purpose": "Analyst cluster report polish from v0.5.4 clusters plus v0.5.5 metric note",
        "cluster_dir": str(cluster_dir),
        "diagnostic_dir": str(diagnostic_dir),
        "out_dir": str(out_dir),
        "queue_sizes": queue_sizes,
        "focus_source": args.focus_source,
        "top_clusters": args.top_clusters,
        "outputs": [
            "analyst_cluster_packet.txt",
            "analyst_cluster_packet.md",
            "analyst_cluster_summary.csv",
            "top_clusters_for_briefing.csv",
            "representative_episode_briefing.csv",
            "v055b_manifest.json",
        ],
        "scope_guardrails": [
            "No model loading",
            "No auth.txt access",
            "No accepted JSONL access",
            "No redteam.txt access",
            "No queue reranking",
            "No queue mutation",
            "Official recall from v0.5.5 deduplicated metric only",
        ],
    }
    write_text(out_dir / "v055b_manifest.json", json.dumps(manifest, indent=2))

    print("=" * 80)
    print(report)
    print(f"Wrote report: {out_dir / 'analyst_cluster_packet.txt'}")
    print(f"Wrote markdown: {out_dir / 'analyst_cluster_packet.md'}")
    print(f"Wrote summary: {out_dir / 'analyst_cluster_summary.csv'}")
    print(f"Wrote manifest: {out_dir / 'v055b_manifest.json'}")


if __name__ == "__main__":
    main()
