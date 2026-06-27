#!/usr/bin/env python3
"""
sria_rt_v050_apply_learned_ranker.py

SRIA RT v0.5.0 - Offline Learned Ranker Application

Purpose:
- Load a learned ranker artifact exported from v0.4.4.
- Apply it to existing accepted episode JSONL files.
- Write ranked analyst queues without rescanning auth.txt.
- Preserve validation labels only when a match file is explicitly supplied.

This is an integration step, not a new detector run.

Recommended first run:
  py sria_rt_v050_apply_learned_ranker.py ^
    --model v044_train_v033_score_v036\model_v033_rf_depth10_cw_none.joblib ^
    --episodes v036_batches\episodes_v036_accepted.jsonl ^
    --matches v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl ^
    --out-dir v050_apply_rf_depth10_v036 ^
    --top-k 100,500,1000,5000

Expected acceptance check:
- top100 should remain near 126 represented red-team events.
- top500 should recover all 138 represented red-team events.

Safety / methodology:
- The model artifact controls the feature list.
- Label/redteam/exact-start fields are never used as features.
- Gate-output leakage remains excluded because the v0.4.4 model was trained with a stripped feature set.
- This script only applies the model to accepted episodes. It does not estimate full deployment precision.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import joblib
    import numpy as np
except Exception as exc:  # pragma: no cover
    print("ERROR: This script requires joblib and numpy.")
    print("Install with:")
    print("  py -m pip install numpy joblib scikit-learn")
    print(f"Original import error: {exc}")
    raise SystemExit(2)


SIGNAL_NAMES = [
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

# Validation/debug fields must not be used as model features.
VALIDATION_ONLY_FIELDS = {
    "label",
    "redteam_count",
    "redteam_indices",
    "redteam_group",
    "exact_start_count",
}

# Legacy/gate fields are allowed as output metadata but are not used unless a model artifact
# explicitly includes them. A proper v0.4.4 artifact should not include these.
LEAKAGE_GUARD_FIELDS = {
    "score",
    "raw_score",
    "legacy_sria_score",
    "legacy_raw_score",
    "entropy_penalty",
    "max_risk",
    "candidate_gate_encoded",
}


def safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        x = float(value)
        if math.isnan(x) or math.isinf(x):
            return default
        return x
    except Exception:
        return default


def safe_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(float(value))
    except Exception:
        return default


def load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def normalize_signals(signals: Any) -> List[str]:
    if signals is None:
        return []
    if isinstance(signals, list):
        return [str(s) for s in signals]
    if isinstance(signals, set):
        return [str(s) for s in signals]
    if isinstance(signals, str):
        if ";" in signals:
            return [s for s in signals.split(";") if s]
        if "," in signals:
            return [s.strip() for s in signals.split(",") if s.strip()]
        return [signals] if signals else []
    return []


def get_episode_obj(obj: Dict[str, Any]) -> Dict[str, Any]:
    ep = obj.get("episode")
    if isinstance(ep, dict):
        return ep
    return obj


def episode_id_from_obj(obj: Dict[str, Any]) -> str:
    for key in ("episode_id", "id"):
        if key in obj and obj[key] is not None:
            return str(obj[key])
    ep = obj.get("episode")
    if isinstance(ep, dict):
        for key in ("episode_id", "id"):
            if key in ep and ep[key] is not None:
                return str(ep[key])
    return ""


def load_match_maps(path: Optional[Path]) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, List[int]], Dict[str, int]]:
    by_ep: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    rt_indices_by_ep: Dict[str, List[int]] = defaultdict(list)
    exact_by_ep: Dict[str, int] = defaultdict(int)

    if path is None:
        return by_ep, rt_indices_by_ep, exact_by_ep
    if not path.exists():
        print(f"WARNING: match file not found: {path}")
        return by_ep, rt_indices_by_ep, exact_by_ep

    count = 0
    for obj in load_jsonl(path):
        count += 1
        ep = obj.get("episode", {})
        ep_id = str(ep.get("id") or ep.get("episode_id") or obj.get("episode_id") or "")
        if not ep_id:
            continue
        by_ep[ep_id].append(obj)
        idx = obj.get("redteam_index")
        if idx is not None:
            try:
                rt_indices_by_ep[ep_id].append(int(idx))
            except Exception:
                pass
        if obj.get("exact_start_match"):
            exact_by_ep[ep_id] += 1

    unique_rt = len({idx for vals in rt_indices_by_ep.values() for idx in vals})
    print(
        f"Loaded validation matches: records={count:,} "
        f"positive_episodes={len(by_ep):,} represented_redteam_events={unique_rt:,}"
    )
    return by_ep, rt_indices_by_ep, exact_by_ep


def row_from_episode(
    obj: Dict[str, Any],
    match_by_ep: Dict[str, List[Dict[str, Any]]],
    rt_by_ep: Dict[str, List[int]],
    exact_by_ep: Dict[str, int],
    include_validation: bool,
) -> Dict[str, Any]:
    ep = get_episode_obj(obj)
    ep_id = str(ep.get("id") or ep.get("episode_id") or obj.get("episode_id") or "")

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
        first_time_signal_hits = sum(1 for s in signals if s.startswith("first_time"))

    novelty_ratio = safe_float(ep.get("novelty_ratio"), 0.0)
    if novelty_ratio == 0.0 and events_count > 0:
        novelty_ratio = min(1.0, new_dest_count / max(events_count, 1.0))

    row: Dict[str, Any] = {
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
    }

    for signal in SIGNAL_NAMES:
        row[f"sig__{signal}"] = 1.0 if signal in sigset else 0.0

    if include_validation:
        label = 1 if ep_id in match_by_ep else 0
        rt_indices = sorted(set(rt_by_ep.get(ep_id, [])))
        row["label"] = label
        row["redteam_indices"] = ";".join(str(i) for i in rt_indices)
        row["redteam_count"] = len(rt_indices)
        row["exact_start_count"] = exact_by_ep.get(ep_id, 0)
        if rt_indices:
            row["redteam_group"] = "rtgrp:" + "+".join(str(i) for i in rt_indices)
        else:
            row["redteam_group"] = f"neg:{ep_id}"

    return row


def load_model_artifact(path: Path) -> Tuple[Any, List[str], Dict[str, Any]]:
    artifact = joblib.load(path)
    if isinstance(artifact, dict) and "model" in artifact:
        model = artifact["model"]
        feature_names = list(artifact.get("feature_names", []))
        meta = {k: v for k, v in artifact.items() if k not in {"model"}}
    else:
        model = artifact
        feature_names = []
        meta = {}

    if not feature_names:
        raise SystemExit(
            "ERROR: model artifact does not contain feature_names. "
            "Use the v0.4.4 exported joblib artifact."
        )

    forbidden = sorted(set(feature_names) & VALIDATION_ONLY_FIELDS)
    if forbidden:
        raise SystemExit(f"ERROR: model feature list contains validation-only fields: {forbidden}")

    leaked = sorted(set(feature_names) & LEAKAGE_GUARD_FIELDS)
    if leaked:
        print(f"WARNING: model feature list includes legacy/gate fields: {leaked}")
        print("This should not happen for a clean v0.4.4 stripped model.")

    return model, feature_names, meta


def matrix_from_rows(rows: Sequence[Dict[str, Any]], feature_names: Sequence[str]) -> np.ndarray:
    x = np.zeros((len(rows), len(feature_names)), dtype=np.float32)
    for i, row in enumerate(rows):
        for j, name in enumerate(feature_names):
            x[i, j] = safe_float(row.get(name))
    return x


def model_scores(model: Any, x: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(x)
        if proba.shape[1] == 2:
            return proba[:, 1]
        return proba[:, -1]
    if hasattr(model, "decision_function"):
        z = np.asarray(model.decision_function(x), dtype=np.float64)
        return 1.0 / (1.0 + np.exp(-np.clip(z, -50, 50)))
    return np.asarray(model.predict(x), dtype=np.float64)


def represented_redteam_set(rows: Sequence[Dict[str, Any]]) -> set[int]:
    out: set[int] = set()
    for row in rows:
        for x in str(row.get("redteam_indices", "")).split(";"):
            if x.strip().isdigit():
                out.add(int(x))
    return out


def topk_stats(rows: Sequence[Dict[str, Any]], top_ks: Sequence[int]) -> Dict[int, Dict[str, Any]]:
    total_rt = len(represented_redteam_set(rows))
    stats: Dict[int, Dict[str, Any]] = {}

    for k in top_ks:
        kk = min(k, len(rows))
        subset = rows[:kk]
        rt_events = represented_redteam_set(subset)
        pos_eps = sum(1 for row in subset if safe_int(row.get("label")) == 1)
        exact_start = sum(safe_int(row.get("exact_start_count")) for row in subset)
        gates = Counter(str(row.get("candidate_gate", "UNKNOWN")) for row in subset)
        sources = Counter(str(row.get("source", "")) for row in subset)
        users = Counter(str(row.get("user", "")) for row in subset)
        signals = Counter()
        for row in subset:
            for signal in str(row.get("signals", "")).split(";"):
                signal = signal.strip()
                if signal:
                    signals[signal] += 1
        stats[k] = {
            "k": kk,
            "positive_episodes": pos_eps,
            "episode_precision": pos_eps / kk if kk else 0.0,
            "redteam_events": len(rt_events),
            "redteam_recall": len(rt_events) / total_rt if total_rt else 0.0,
            "exact_start_count": exact_start,
            "top_gates": gates.most_common(10),
            "top_sources": sources.most_common(10),
            "top_users": users.most_common(10),
            "top_signals": signals.most_common(12),
        }
    return stats


def sorted_rows_with_scores(rows: List[Dict[str, Any]], scores: Sequence[float]) -> List[Dict[str, Any]]:
    enriched = []
    for row, score in zip(rows, scores):
        out = dict(row)
        out["model_score"] = float(score)
        enriched.append(out)
    enriched.sort(
        key=lambda r: (
            -safe_float(r.get("model_score")),
            -safe_float(r.get("novelty_ratio")),
            -safe_float(r.get("first_time_signal_hits")),
            -safe_float(r.get("destination_count")),
            -safe_float(r.get("fanout_velocity_score")),
            safe_float(r.get("duration")),
            str(r.get("episode_id", "")),
        )
    )
    for rank, row in enumerate(enriched, 1):
        row["rank"] = rank
    return enriched


def csv_fields(include_validation: bool) -> List[str]:
    fields = [
        "rank",
        "model_score",
        "episode_id",
        "start_time",
        "end_time",
        "duration",
        "source",
        "user",
        "candidate_gate",
        "legacy_sria_score",
        "legacy_raw_score",
        "events_count",
        "destination_count",
        "user_count",
        "new_destination_event_count",
        "first_time_event_count",
        "first_time_signal_hits",
        "novelty_ratio",
        "compactness_score",
        "fanout_velocity_score",
        "peak_velocity_new_dests",
        "signals",
    ]
    if include_validation:
        fields.extend(["label", "redteam_count", "exact_start_count", "redteam_indices", "redteam_group"])
    return fields


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], include_validation: bool) -> None:
    fields = csv_fields(include_validation)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_jsonl(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def format_counter_items(items: Sequence[Tuple[str, int]], indent: str = "  ") -> List[str]:
    return [f"{indent}{name}: {count}" for name, count in items]


def write_report(
    path: Path,
    model_path: Path,
    episodes_path: Path,
    matches_path: Optional[Path],
    meta: Dict[str, Any],
    feature_names: Sequence[str],
    rows: Sequence[Dict[str, Any]],
    stats: Dict[int, Dict[str, Any]],
    include_validation: bool,
    out_dir: Path,
) -> None:
    lines: List[str] = []
    lines.append("SRIA RT v0.5.0 Offline Learned Ranker Application")
    lines.append("=" * 88)
    lines.append(f"model: {model_path}")
    lines.append(f"episodes: {episodes_path}")
    lines.append(f"matches: {matches_path if matches_path else 'none'}")
    lines.append(f"out_dir: {out_dir}")
    lines.append("")
    lines.append("Model artifact metadata")
    lines.append("-" * 88)
    for key in sorted(meta):
        if key == "feature_names":
            continue
        lines.append(f"{key}: {meta[key]}")
    lines.append(f"feature_count: {len(feature_names)}")
    lines.append("")
    lines.append("Methodology")
    lines.append("-" * 88)
    lines.append("This script applies an existing learned ranker to accepted episode JSONL output.")
    lines.append("It does not rescan auth.txt and does not change detector/candidate-generation logic.")
    lines.append("Validation fields are included only because --matches was provided.") if include_validation else lines.append("No validation file was provided; output is deployment-style ranked queue metadata only.")
    lines.append("This is accepted-episode review-queue ranking, not full deployment precision.")
    lines.append("")
    lines.append("Input summary")
    lines.append("-" * 88)
    lines.append(f"rows_scored: {len(rows):,}")
    if include_validation:
        pos_eps = sum(1 for row in rows if safe_int(row.get("label")) == 1)
        rt_events = len(represented_redteam_set(rows))
        lines.append(f"positive_episodes: {pos_eps:,}")
        lines.append(f"represented_redteam_events: {rt_events:,}")
    lines.append("")

    if include_validation:
        lines.append("Top-K validation metrics")
        lines.append("-" * 88)
        for k, value in stats.items():
            lines.append(
                f"Top {k:,}: positive_episodes={value['positive_episodes']} "
                f"episode_precision={value['episode_precision']:.6f} "
                f"redteam_events={value['redteam_events']} "
                f"redteam_recall={value['redteam_recall']:.6f} "
                f"exact_start_count={value['exact_start_count']}"
            )
            lines.append("top gates:")
            lines.extend(format_counter_items(value["top_gates"]))
            lines.append("top sources:")
            lines.extend(format_counter_items(value["top_sources"]))
            lines.append("top users:")
            lines.extend(format_counter_items(value["top_users"]))
            lines.append("top signals:")
            lines.extend(format_counter_items(value["top_signals"]))
            lines.append("")
    else:
        lines.append("Top-K validation metrics unavailable because no --matches file was provided.")
        lines.append("")

    lines.append("Output files")
    lines.append("-" * 88)
    for child in sorted(out_dir.iterdir()):
        if child.is_file():
            lines.append(f"{child.name}: {child.stat().st_size:,} bytes")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_top_k(value: str) -> List[int]:
    out = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(int(part))
    return sorted(set(out))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SRIA RT v0.5.0 offline learned-ranker application")
    parser.add_argument("--model", required=True, help="Path to v0.4.4 .joblib model artifact")
    parser.add_argument("--episodes", required=True, help="Accepted episode JSONL file to score")
    parser.add_argument("--matches", default="", help="Optional redteam match JSONL file for validation/debug labels")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument("--prefix", default="", help="Output file prefix. Default is inferred from model/episodes.")
    parser.add_argument("--top-k", default="100,500,1000,5000", help="Comma-separated top-K CSV outputs")
    parser.add_argument("--jsonl-top", type=int, default=5000, help="Write ranked top-N JSONL")
    parser.add_argument("--deployment-output", action="store_true", help="Exclude validation fields from CSV/JSONL even if --matches is supplied")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_path = Path(args.model)
    episodes_path = Path(args.episodes)
    matches_path = Path(args.matches) if args.matches else None
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not model_path.exists():
        raise SystemExit(f"ERROR: model not found: {model_path}")
    if not episodes_path.exists():
        raise SystemExit(f"ERROR: episodes file not found: {episodes_path}")

    top_ks = parse_top_k(args.top_k)
    include_validation = bool(matches_path) and not args.deployment_output

    print("=" * 88)
    print("SRIA RT v0.5.0 - Offline Learned Ranker Application")
    print("=" * 88)
    print(f"model: {model_path}")
    print(f"episodes: {episodes_path}")
    print(f"matches: {matches_path if matches_path else 'none'}")
    print(f"out_dir: {out_dir}")
    print("NOTE: This does not rescan auth.txt.")
    print("NOTE: This is accepted-episode queue ranking, not deployment precision.")
    print("=" * 88)

    model, feature_names, meta = load_model_artifact(model_path)
    print(f"Loaded model artifact with {len(feature_names)} features.")

    match_by_ep, rt_by_ep, exact_by_ep = load_match_maps(matches_path)

    print("Loading accepted episodes...")
    rows: List[Dict[str, Any]] = []
    for idx, obj in enumerate(load_jsonl(episodes_path), 1):
        if idx % 100000 == 0:
            print(f"  loaded {idx:,} episodes...")
        rows.append(row_from_episode(obj, match_by_ep, rt_by_ep, exact_by_ep, include_validation=include_validation))
    print(f"Loaded episodes: {len(rows):,}")

    x = matrix_from_rows(rows, feature_names)
    print("Scoring episodes...")
    scores = model_scores(model, x)
    ranked_rows = sorted_rows_with_scores(rows, scores)

    if args.prefix:
        prefix = args.prefix
    else:
        model_stem = model_path.stem.replace("model_", "")
        prefix = f"ranked_{model_stem}"

    ranked_csv = out_dir / f"{prefix}_all.csv"
    write_csv(ranked_csv, ranked_rows, include_validation=include_validation)
    print(f"Wrote ranked CSV: {ranked_csv}")

    for k in top_ks:
        out_csv = out_dir / f"{prefix}_top{k}.csv"
        write_csv(out_csv, ranked_rows[:k], include_validation=include_validation)
        print(f"Wrote top{k} CSV: {out_csv}")

    if args.jsonl_top > 0:
        out_jsonl = out_dir / f"{prefix}_top{args.jsonl_top}.jsonl"
        write_jsonl(out_jsonl, ranked_rows[: args.jsonl_top])
        print(f"Wrote top{args.jsonl_top} JSONL: {out_jsonl}")

    stats = topk_stats(ranked_rows, top_ks + ([args.jsonl_top] if args.jsonl_top > 0 else [])) if include_validation else {}

    report_path = out_dir / "v050_ranker_audit_report.txt"
    write_report(
        report_path,
        model_path=model_path,
        episodes_path=episodes_path,
        matches_path=matches_path,
        meta=meta,
        feature_names=feature_names,
        rows=ranked_rows,
        stats=stats,
        include_validation=include_validation,
        out_dir=out_dir,
    )
    print(f"Wrote report: {report_path}")

    if include_validation:
        print("")
        print("Top-K validation summary:")
        for k in top_ks:
            s = stats[k]
            print(
                f"  top{k}: pos_eps={s['positive_episodes']} "
                f"rt_events={s['redteam_events']} "
                f"rt_recall={s['redteam_recall']:.6f} "
                f"exact_start={s['exact_start_count']}"
            )

    print("Done.")


if __name__ == "__main__":
    main()
