#!/usr/bin/env python3
r"""
sria_rt_v064_apply_ranker_to_background.py

SRIA RT v0.6.4 - Apply Current Primary Learned Ranker to Background Episodes

Purpose:
- Apply the existing SRIA RT learned ranker to v0.6.3 accepted background episodes.
- Preserve the v0.6 negative-background evaluation boundary:
    * no retraining
    * no feature changes
    * no threshold tuning
    * no red-team validation
    * no auth.txt scan
- Produce aggregate and per-window deployment-style queues for burden analysis.

Typical CMD use from F:\SRIA\SRIA_RT_v01:

  py sria_rt_v064_apply_ranker_to_background.py ^
    --episodes-dir v063_background_episodes_tierB ^
    --generation-summary v063_background_episodes_tierB\v063_background_generation_summary.csv ^
    --model-artifact v044_train_v033_score_v036\model_v033_rf_depth10_cw_none.joblib ^
    --out-dir v064_background_ranked_tierB ^
    --queue-sizes 100,500,1000,5000 ^
    --write-all-ranked

Inputs:
- bg_###_episodes.jsonl files from v0.6.3
- v063_background_generation_summary.csv for window/band metadata
- Existing joblib ranker artifact with model + feature_names

Outputs:
- aggregate_deployment_queue_top*.csv/jsonl
- per_window\bg_###_deployment_queue_top*.csv/jsonl
- v064_background_ranker_summary.csv
- v064_score_distribution_by_scope.csv
- aggregate_deployment_queue_all_ranked.csv (optional)
- v064_background_ranking_report.txt
- v064_manifest.json
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import joblib
    import numpy as np
except Exception as e:  # pragma: no cover
    print("ERROR: This script requires numpy and joblib.")
    print("Install with:")
    print("  py -m pip install numpy joblib")
    print(f"Original import error: {e}")
    raise SystemExit(2)


DEFAULT_SIGNAL_NAMES = [
    "first_time_source_user_to_dest",
    "first_time_user_to_dest",
    "first_time_source_to_dest",
    "source_fanout",
    "source_user_fanout",
    "user_fanout",
    "compact_lateral_burst",
    "fanout_velocity",
    "propagation_convergence_bonus",
    "compact_rescue_bonus",
    "source_user_fanout_rescue_bonus",
    "entropy_low_novelty",
    "entropy_soft_duration",
    "entropy_long_duration",
    "entropy_many_events",
    "entropy_extreme_events",
    "entropy_oversized_fanout",
    "entropy_excessive_destinations",
]

DEPLOYMENT_FIELDS = [
    "rank",
    "rank_scope",
    "rank_global",
    "rank_in_window",
    "sria_rt_model_score",
    "severity",
    "review_priority",
    "window_id",
    "band",
    "background_episode_key",
    "episode_id",
    "start_time",
    "end_time",
    "duration",
    "source",
    "user",
    "destination_count",
    "events_count",
    "user_count",
    "candidate_gate",
    "legacy_sria_score",
    "legacy_raw_score",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "first_time_signal_hits",
    "first_time_event_count",
    "new_destination_event_count",
    "explanation_short",
    "signals",
]

SUMMARY_FIELDS = [
    "scope",
    "window_id",
    "band",
    "rows_scored",
    "unique_sources",
    "unique_users",
    "top_source",
    "top_source_count",
    "top_source_share",
    "top5_sources_share",
    "top10_sources_share",
    "dominant_gate",
    "dominant_gate_share",
    "dominant_signal",
    "dominant_signal_share",
    "score_min",
    "score_p50",
    "score_p75",
    "score_p90",
    "score_p95",
    "score_p99",
    "score_max",
    "background_count",
    "low_review_count",
    "medium_review_count",
    "high_review_count",
    "critical_review_count",
    "nearest_redteam_distance",
    "accepted_episodes_from_generation",
    "parsed_success_events",
    "accepted_per_million_parsed_events",
]

DISTRIBUTION_FIELDS = [
    "scope",
    "window_id",
    "band",
    "rows_scored",
    "score_min",
    "score_p01",
    "score_p05",
    "score_p10",
    "score_p25",
    "score_p50",
    "score_p75",
    "score_p90",
    "score_p95",
    "score_p99",
    "score_max",
]


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
        return int(float(v))
    except Exception:
        return default


def load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def normalize_signals(signals: Any) -> List[str]:
    if signals is None:
        return []
    if isinstance(signals, list):
        return [str(s) for s in signals if str(s)]
    if isinstance(signals, set):
        return [str(s) for s in signals if str(s)]
    if isinstance(signals, tuple):
        return [str(s) for s in signals if str(s)]
    if isinstance(signals, str):
        if ";" in signals:
            return [s.strip() for s in signals.split(";") if s.strip()]
        if "," in signals:
            return [s.strip() for s in signals.split(",") if s.strip()]
        return [signals] if signals else []
    return []


def load_csv_rows(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def load_generation_meta(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    meta: Dict[str, Dict[str, Any]] = {}
    if path is None or not path.exists():
        return meta
    for r in load_csv_rows(path):
        wid = str(r.get("window_id") or "").strip()
        if not wid:
            continue
        meta[wid] = dict(r)
    return meta


def episode_file_window_id(path: Path) -> str:
    name = path.name
    if name.endswith("_episodes.jsonl"):
        return name[: -len("_episodes.jsonl")]
    return path.stem


def episode_id_from_obj(obj: Dict[str, Any]) -> str:
    for k in ("episode_id", "id"):
        if k in obj and obj[k] is not None:
            return str(obj[k])
    ep = obj.get("episode")
    if isinstance(ep, dict):
        for k in ("episode_id", "id"):
            if k in ep and ep[k] is not None:
                return str(ep[k])
    return ""


def row_from_episode(obj: Dict[str, Any], window_id: str, window_meta: Dict[str, Any], signal_names: Sequence[str]) -> Dict[str, Any]:
    ep = obj.get("episode", obj)
    if not isinstance(ep, dict):
        ep = obj

    ep_id = str(ep.get("id") or ep.get("episode_id") or obj.get("episode_id") or "")
    bg_key = f"{window_id}:{ep_id}" if ep_id else f"{window_id}:"
    signals = normalize_signals(ep.get("signals"))
    sigset = set(signals)

    start_time = safe_int(ep.get("start_time"))
    end_time = safe_int(ep.get("end_time"))
    duration = safe_float(ep.get("duration"), max(0, end_time - start_time))

    dest_count = safe_float(ep.get("destination_count"), 0.0)
    if dest_count == 0.0:
        dests = ep.get("destinations") or ep.get("destinations_sample") or []
        if isinstance(dests, (list, set, tuple)):
            dest_count = float(len(dests))

    events_count = safe_float(ep.get("events_count"), 0.0)
    new_dest_count = safe_float(ep.get("new_destination_event_count"), dest_count)
    first_time_event_count = safe_float(ep.get("first_time_event_count"), 0.0)
    first_time_signal_hits = safe_float(ep.get("first_time_signal_hits"), 0.0)
    if first_time_signal_hits == 0.0:
        first_time_signal_hits = float(sum(1 for s in signals if s.startswith("first_time")))

    novelty_ratio = safe_float(ep.get("novelty_ratio"), 0.0)
    if novelty_ratio == 0.0 and events_count > 0:
        novelty_ratio = min(1.0, new_dest_count / max(events_count, 1.0))

    row: Dict[str, Any] = {
        "window_id": window_id,
        "band": window_meta.get("band", ""),
        "tier": window_meta.get("tier", ""),
        "background_episode_key": bg_key,
        "episode_id": ep_id,
        "start_time": start_time,
        "end_time": end_time,
        "duration": duration,
        "source": ep.get("source", ""),
        "user": ep.get("user", ""),
        "candidate_gate": ep.get("candidate_gate", "UNKNOWN"),
        "legacy_sria_score": safe_float(ep.get("score")),
        "legacy_raw_score": safe_float(ep.get("raw_score"), safe_float(ep.get("score"))),
        "entropy_penalty": safe_float(ep.get("entropy_penalty")),
        "max_risk": safe_float(ep.get("max_risk")),
        "events_count": events_count,
        "destination_count": dest_count,
        "user_count": safe_float(ep.get("user_count"), 1.0 if ep.get("user") else 0.0),
        "new_destination_event_count": new_dest_count,
        "first_time_event_count": first_time_event_count,
        "first_time_signal_hits": first_time_signal_hits,
        "novelty_ratio": novelty_ratio,
        "compactness_score": safe_float(ep.get("compactness_score")),
        "fanout_velocity_score": safe_float(ep.get("fanout_velocity_score")),
        "peak_velocity_new_dests": safe_float(ep.get("peak_velocity_new_dests")),
        "signals": ";".join(sorted(sigset)),
        "nearest_redteam_distance": safe_int(window_meta.get("nearest_redteam_distance"), -1),
    }

    for s in signal_names:
        row[f"sig__{s}"] = 1.0 if s in sigset else 0.0

    return row


def matrix_from_rows(rows: Sequence[Dict[str, Any]], feature_names: Sequence[str]) -> np.ndarray:
    X = np.zeros((len(rows), len(feature_names)), dtype=np.float32)
    for i, r in enumerate(rows):
        for j, n in enumerate(feature_names):
            X[i, j] = safe_float(r.get(n))
    return X


def unpack_model_artifact(path: Path) -> Tuple[Any, List[str], Dict[str, Any]]:
    artifact = joblib.load(path)
    if isinstance(artifact, dict) and "model" in artifact:
        model = artifact["model"]
        feature_names = list(artifact.get("feature_names") or [])
        meta = {k: v for k, v in artifact.items() if k != "model"}
    else:
        model = artifact
        feature_names = []
        meta = {"artifact_format": "raw_model_no_feature_names"}
    if not feature_names:
        raise ValueError("Model artifact does not contain feature_names. Re-export using the SRIA RT v0.4.x/v0.5.x artifact format.")
    return model, feature_names, meta


def model_scores(model: Any, X: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        if proba.shape[1] == 2:
            return proba[:, 1]
        return proba[:, -1]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        z = np.asarray(z, dtype=np.float64)
        return 1.0 / (1.0 + np.exp(-np.clip(z, -50, 50)))
    pred = model.predict(X)
    return np.asarray(pred, dtype=np.float64)


def severity_from_score(score: float) -> str:
    if score >= 0.90:
        return "critical_review"
    if score >= 0.75:
        return "high_review"
    if score >= 0.50:
        return "medium_review"
    if score >= 0.25:
        return "low_review"
    return "background"


def priority_from_rank(rank: int) -> str:
    if rank <= 100:
        return "P1_top100"
    if rank <= 500:
        return "P2_top500"
    if rank <= 1000:
        return "P3_top1000"
    if rank <= 5000:
        return "P4_top5000"
    return "P5_long_tail"


def explanation_short(row: Dict[str, Any]) -> str:
    parts: List[str] = []
    sigs = set(normalize_signals(row.get("signals")))
    if "first_time_source_user_to_dest" in sigs:
        parts.append("first-time source-user-destination edge")
    elif "first_time_user_to_dest" in sigs or "first_time_source_to_dest" in sigs:
        parts.append("first-time authentication edge")
    if "fanout_velocity" in sigs:
        parts.append("fanout velocity")
    if "compact_lateral_burst" in sigs:
        parts.append("compact lateral burst")
    if "propagation_convergence_bonus" in sigs:
        parts.append("propagation convergence")
    if not parts:
        parts.append("authentication topology anomaly")
    gate = str(row.get("candidate_gate") or "UNKNOWN")
    return f"{'; '.join(parts)}; gate={gate}"


def deployment_row(row: Dict[str, Any], rank: int, rank_scope: str, score: float, rank_global: int = 0, rank_in_window: int = 0) -> Dict[str, Any]:
    out = {k: row.get(k, "") for k in DEPLOYMENT_FIELDS if k not in {
        "rank", "rank_scope", "rank_global", "rank_in_window", "sria_rt_model_score", "severity", "review_priority", "explanation_short"
    }}
    out["rank"] = rank
    out["rank_scope"] = rank_scope
    out["rank_global"] = rank_global
    out["rank_in_window"] = rank_in_window
    out["sria_rt_model_score"] = float(score)
    out["severity"] = severity_from_score(float(score))
    out["review_priority"] = priority_from_rank(rank)
    out["explanation_short"] = explanation_short(row)
    return out


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fields), extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def percentile(scores: Sequence[float], p: float) -> float:
    if not scores:
        return 0.0
    return float(np.percentile(np.asarray(scores, dtype=np.float64), p))


def top_share(values: Sequence[str], n: int) -> float:
    if not values:
        return 0.0
    c = Counter(values)
    return sum(v for _, v in c.most_common(n)) / len(values)


def summarize_scope(scope: str, rows: Sequence[Dict[str, Any]], scores: Sequence[float], generation_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    generation_meta = generation_meta or {}
    n = len(rows)
    sources = [str(r.get("source", "")) for r in rows if str(r.get("source", ""))]
    users = [str(r.get("user", "")) for r in rows if str(r.get("user", ""))]
    gates = Counter(str(r.get("candidate_gate", "UNKNOWN")) for r in rows)
    sig_counter: Counter = Counter()
    for r in rows:
        sig_counter.update(normalize_signals(r.get("signals")))
    source_counts = Counter(sources)
    top_source, top_source_count = (source_counts.most_common(1)[0] if source_counts else ("", 0))
    dominant_gate, dominant_gate_count = (gates.most_common(1)[0] if gates else ("", 0))
    dominant_signal, dominant_signal_count = (sig_counter.most_common(1)[0] if sig_counter else ("", 0))
    sev_counts = Counter(severity_from_score(s) for s in scores)
    return {
        "scope": scope,
        "window_id": generation_meta.get("window_id", "aggregate" if scope == "aggregate" else ""),
        "band": generation_meta.get("band", "all" if scope == "aggregate" else ""),
        "rows_scored": n,
        "unique_sources": len(source_counts),
        "unique_users": len(set(users)),
        "top_source": top_source,
        "top_source_count": top_source_count,
        "top_source_share": top_source_count / n if n else 0.0,
        "top5_sources_share": top_share(sources, 5),
        "top10_sources_share": top_share(sources, 10),
        "dominant_gate": dominant_gate,
        "dominant_gate_share": dominant_gate_count / n if n else 0.0,
        "dominant_signal": dominant_signal,
        "dominant_signal_share": dominant_signal_count / n if n else 0.0,
        "score_min": percentile(scores, 0),
        "score_p50": percentile(scores, 50),
        "score_p75": percentile(scores, 75),
        "score_p90": percentile(scores, 90),
        "score_p95": percentile(scores, 95),
        "score_p99": percentile(scores, 99),
        "score_max": percentile(scores, 100),
        "background_count": sev_counts.get("background", 0),
        "low_review_count": sev_counts.get("low_review", 0),
        "medium_review_count": sev_counts.get("medium_review", 0),
        "high_review_count": sev_counts.get("high_review", 0),
        "critical_review_count": sev_counts.get("critical_review", 0),
        "nearest_redteam_distance": generation_meta.get("nearest_redteam_distance", ""),
        "accepted_episodes_from_generation": generation_meta.get("accepted_episodes", n),
        "parsed_success_events": generation_meta.get("parsed_success_events", ""),
        "accepted_per_million_parsed_events": generation_meta.get("accepted_per_million_parsed_events", ""),
    }


def distribution_row(scope: str, rows: Sequence[Dict[str, Any]], scores: Sequence[float], generation_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    generation_meta = generation_meta or {}
    return {
        "scope": scope,
        "window_id": generation_meta.get("window_id", "aggregate" if scope == "aggregate" else ""),
        "band": generation_meta.get("band", "all" if scope == "aggregate" else ""),
        "rows_scored": len(rows),
        "score_min": percentile(scores, 0),
        "score_p01": percentile(scores, 1),
        "score_p05": percentile(scores, 5),
        "score_p10": percentile(scores, 10),
        "score_p25": percentile(scores, 25),
        "score_p50": percentile(scores, 50),
        "score_p75": percentile(scores, 75),
        "score_p90": percentile(scores, 90),
        "score_p95": percentile(scores, 95),
        "score_p99": percentile(scores, 99),
        "score_max": percentile(scores, 100),
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v0.6.4 apply learned ranker to background episodes")
    p.add_argument("--episodes-dir", required=True, help="Directory containing bg_###_episodes.jsonl files from v0.6.3")
    p.add_argument("--generation-summary", required=True, help="v063_background_generation_summary.csv")
    p.add_argument("--model-artifact", required=True, help="Existing joblib ranker artifact with model + feature_names")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--queue-sizes", default="100,500,1000,5000", help="Comma-separated queue sizes")
    p.add_argument("--pattern", default="bg_*_episodes.jsonl", help="Episode JSONL filename glob")
    p.add_argument("--write-all-ranked", action="store_true", help="Write aggregate_deployment_queue_all_ranked.csv")
    p.add_argument("--no-window-queues", action="store_true", help="Skip per-window top queue outputs")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    episodes_dir = Path(args.episodes_dir)
    generation_summary = Path(args.generation_summary)
    model_artifact = Path(args.model_artifact)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    queue_sizes = [int(x) for x in args.queue_sizes.split(",") if x.strip()]

    print("=" * 80)
    print("SRIA RT v0.6.4 - Apply Learned Ranker to Background Episodes")
    print("=" * 80)
    print(f"Episodes dir: {episodes_dir}")
    print(f"Generation summary: {generation_summary}")
    print(f"Model artifact: {model_artifact}")
    print(f"Output dir: {out_dir}")
    print(f"Queue sizes: {queue_sizes}")
    print("NOTE: Current primary learned ranker is applied unchanged.")
    print("NOTE: No retraining, no feature/gate changes, no red-team validation, no auth.txt scan.")
    print("=" * 80)

    t0 = time.time()
    model, feature_names, artifact_meta = unpack_model_artifact(model_artifact)
    signal_names = [n.replace("sig__", "") for n in feature_names if n.startswith("sig__")]
    if not signal_names:
        signal_names = list(DEFAULT_SIGNAL_NAMES)

    gen_meta = load_generation_meta(generation_summary)
    episode_files = sorted(episodes_dir.glob(args.pattern))
    if not episode_files:
        raise FileNotFoundError(f"No episode files matched {episodes_dir / args.pattern}")

    all_rows: List[Dict[str, Any]] = []
    rows_by_window: Dict[str, List[Dict[str, Any]]] = {}
    print(f"Loading background accepted episodes from {len(episode_files)} files...")
    for path in episode_files:
        wid = episode_file_window_id(path)
        meta = gen_meta.get(wid, {"window_id": wid})
        rows: List[Dict[str, Any]] = []
        for obj in load_jsonl(path):
            rows.append(row_from_episode(obj, wid, meta, signal_names))
        rows_by_window[wid] = rows
        all_rows.extend(rows)
        print(f"  {wid}: loaded {len(rows):,} accepted episodes from {path.name}")

    print(f"Total background accepted episodes loaded: {len(all_rows):,}")

    X = matrix_from_rows(all_rows, feature_names)
    all_scores_np = model_scores(model, X)
    all_scores = [float(x) for x in all_scores_np]

    # Build per-window score slices.
    scores_by_window: Dict[str, List[float]] = {}
    offset = 0
    for wid in sorted(rows_by_window):
        n = len(rows_by_window[wid])
        scores_by_window[wid] = all_scores[offset: offset + n]
        offset += n

    # Aggregate ranking.
    order = np.argsort(-np.asarray(all_scores, dtype=np.float64))
    aggregate_ranked: List[Tuple[int, Dict[str, Any], float]] = []
    for rank, idx in enumerate(order, 1):
        aggregate_ranked.append((rank, all_rows[int(idx)], all_scores[int(idx)]))

    # Per-window rankings and rank maps for aggregate rows.
    window_rank_map: Dict[str, Dict[str, int]] = defaultdict(dict)
    window_ranked: Dict[str, List[Tuple[int, Dict[str, Any], float]]] = {}
    for wid in sorted(rows_by_window):
        rows = rows_by_window[wid]
        scores = scores_by_window[wid]
        worder = np.argsort(-np.asarray(scores, dtype=np.float64))
        ranked: List[Tuple[int, Dict[str, Any], float]] = []
        for wrank, idx in enumerate(worder, 1):
            r = rows[int(idx)]
            s = scores[int(idx)]
            ranked.append((wrank, r, s))
            window_rank_map[wid][str(r.get("background_episode_key", ""))] = wrank
        window_ranked[wid] = ranked

    # Aggregate queues.
    for k in queue_sizes:
        selected = aggregate_ranked[: min(k, len(aggregate_ranked))]
        out_rows = []
        for rank, r, score in selected:
            wid = str(r.get("window_id", ""))
            bg_key = str(r.get("background_episode_key", ""))
            wrank = window_rank_map.get(wid, {}).get(bg_key, 0)
            out_rows.append(deployment_row(r, rank, "aggregate", score, rank_global=rank, rank_in_window=wrank))
        write_csv(out_dir / f"aggregate_deployment_queue_top{k}.csv", out_rows, DEPLOYMENT_FIELDS)
        write_jsonl(out_dir / f"aggregate_deployment_queue_top{k}.jsonl", out_rows)

    if args.write_all_ranked:
        all_out = []
        for rank, r, score in aggregate_ranked:
            wid = str(r.get("window_id", ""))
            bg_key = str(r.get("background_episode_key", ""))
            wrank = window_rank_map.get(wid, {}).get(bg_key, 0)
            all_out.append(deployment_row(r, rank, "aggregate", score, rank_global=rank, rank_in_window=wrank))
        write_csv(out_dir / "aggregate_deployment_queue_all_ranked.csv", all_out, DEPLOYMENT_FIELDS)

    # Per-window queues.
    if not args.no_window_queues:
        per_dir = out_dir / "per_window"
        for wid, ranked in window_ranked.items():
            for k in queue_sizes:
                selected = ranked[: min(k, len(ranked))]
                out_rows = [deployment_row(r, wrank, wid, score, rank_global=0, rank_in_window=wrank) for wrank, r, score in selected]
                write_csv(per_dir / f"{wid}_deployment_queue_top{k}.csv", out_rows, DEPLOYMENT_FIELDS)
                write_jsonl(per_dir / f"{wid}_deployment_queue_top{k}.jsonl", out_rows)

    # Summaries.
    summary_rows: List[Dict[str, Any]] = []
    distribution_rows: List[Dict[str, Any]] = []
    summary_rows.append(summarize_scope("aggregate", all_rows, all_scores, {"window_id": "aggregate", "band": "all"}))
    distribution_rows.append(distribution_row("aggregate", all_rows, all_scores, {"window_id": "aggregate", "band": "all"}))
    for wid in sorted(rows_by_window):
        meta = dict(gen_meta.get(wid, {}))
        meta.setdefault("window_id", wid)
        summary_rows.append(summarize_scope("window", rows_by_window[wid], scores_by_window[wid], meta))
        distribution_rows.append(distribution_row("window", rows_by_window[wid], scores_by_window[wid], meta))
    write_csv(out_dir / "v064_background_ranker_summary.csv", summary_rows, SUMMARY_FIELDS)
    write_csv(out_dir / "v064_score_distribution_by_scope.csv", distribution_rows, DISTRIBUTION_FIELDS)

    manifest = {
        "version": "v0.6.4",
        "purpose": "apply_current_primary_learned_ranker_to_background_episodes",
        "episodes_dir": str(episodes_dir),
        "generation_summary": str(generation_summary),
        "model_artifact": str(model_artifact),
        "queue_sizes": queue_sizes,
        "episode_files": [str(p) for p in episode_files],
        "rows_scored": len(all_rows),
        "window_count": len(rows_by_window),
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "artifact_meta": artifact_meta,
        "boundary": {
            "no_retraining": True,
            "no_feature_changes": True,
            "no_gate_changes": True,
            "no_redteam_validation": True,
            "no_auth_txt_scan": True,
        },
        "elapsed_seconds": round(time.time() - t0, 3),
    }
    (out_dir / "v064_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    agg = summary_rows[0]
    lines: List[str] = []
    lines.append("SRIA RT v0.6.4 Background Learned-Ranker Application")
    lines.append("=" * 80)
    lines.append(f"episodes_dir: {episodes_dir}")
    lines.append(f"generation_summary: {generation_summary}")
    lines.append(f"model_artifact: {model_artifact}")
    lines.append(f"out_dir: {out_dir}")
    lines.append("analysis_scope: apply current primary learned ranker to accepted background episodes")
    lines.append("exclusions: no retraining, no feature changes, no gate changes, no red-team validation, no auth.txt scan")
    lines.append("")
    lines.append("Run summary:")
    lines.append(f"  windows_scored: {len(rows_by_window):,}")
    lines.append(f"  accepted_background_episodes_scored: {len(all_rows):,}")
    lines.append(f"  feature_count: {len(feature_names):,}")
    lines.append(f"  elapsed_seconds: {time.time() - t0:.2f}")
    lines.append("")
    lines.append("Aggregate score / burden summary:")
    lines.append(f"  score_max: {safe_float(agg.get('score_max')):.6f}")
    lines.append(f"  score_p99: {safe_float(agg.get('score_p99')):.6f}")
    lines.append(f"  score_p95: {safe_float(agg.get('score_p95')):.6f}")
    lines.append(f"  score_p90: {safe_float(agg.get('score_p90')):.6f}")
    lines.append(f"  score_p50: {safe_float(agg.get('score_p50')):.6f}")
    lines.append(f"  severity_background: {safe_int(agg.get('background_count')):,}")
    lines.append(f"  severity_low_review: {safe_int(agg.get('low_review_count')):,}")
    lines.append(f"  severity_medium_review: {safe_int(agg.get('medium_review_count')):,}")
    lines.append(f"  severity_high_review: {safe_int(agg.get('high_review_count')):,}")
    lines.append(f"  severity_critical_review: {safe_int(agg.get('critical_review_count')):,}")
    lines.append(f"  unique_sources: {safe_int(agg.get('unique_sources')):,}")
    lines.append(f"  unique_users: {safe_int(agg.get('unique_users')):,}")
    lines.append(f"  top_source: {agg.get('top_source')} ({safe_float(agg.get('top_source_share')):.2%})")
    lines.append(f"  top5_sources_share: {safe_float(agg.get('top5_sources_share')):.2%}")
    lines.append("")
    lines.append("Per-window rows scored:")
    for wid in sorted(rows_by_window):
        srow = next((r for r in summary_rows if r.get("window_id") == wid), {})
        lines.append(
            f"  {wid}: band={srow.get('band')} rows={safe_int(srow.get('rows_scored')):,} "
            f"score_max={safe_float(srow.get('score_max')):.6f} "
            f"score_p99={safe_float(srow.get('score_p99')):.6f} "
            f"top_source={srow.get('top_source')} ({safe_float(srow.get('top_source_share')):.2%})"
        )
    lines.append("")
    lines.append("Outputs:")
    lines.append("  aggregate_deployment_queue_top*.csv/jsonl")
    if args.write_all_ranked:
        lines.append("  aggregate_deployment_queue_all_ranked.csv")
    if not args.no_window_queues:
        lines.append("  per_window\\bg_###_deployment_queue_top*.csv/jsonl")
    lines.append("  v064_background_ranker_summary.csv")
    lines.append("  v064_score_distribution_by_scope.csv")
    lines.append("  v064_manifest.json")

    report_path = out_dir / "v064_background_ranking_report.txt"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"Wrote report: {report_path}")
    print(f"Wrote summary: {out_dir / 'v064_background_ranker_summary.csv'}")
    print(f"Wrote manifest: {out_dir / 'v064_manifest.json'}")


if __name__ == "__main__":
    main()
