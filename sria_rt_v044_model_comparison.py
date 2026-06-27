#!/usr/bin/env python3
"""
sria_rt_v044_model_comparison.py

SRIA RT v0.4.4 - Clean Model Comparison

Purpose:
- Compare stronger learned rankers against the current v0.4.2 winner.
- Preserve v0.4.1 leakage discipline:
    DROP score/raw_score/entropy_penalty/max_risk/gate outputs for learned models.
- Reuse existing episode JSONL outputs. This does NOT rescan auth.txt.
- Evaluate review-queue ranking quality on accepted episodes from score_branch.
- Train on train_branch accepted + sampled suppressed negatives.
- Score score_branch accepted episodes.

Recommended first run:
  train v033 -> score v036

Notes:
- This is queue-generation / cross-branch scoring, not deployment precision.
- If train_branch == score_branch, the result is useful for queue generation only,
  not held-out validation.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import SGDClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.pipeline import Pipeline
except Exception as e:
    print("ERROR: This script requires numpy, scikit-learn, and joblib.")
    print("Install with:")
    print("  py -m pip install numpy scikit-learn joblib")
    print(f"Original import error: {e}")
    raise SystemExit(2)


TOP_KS_DEFAULT = [20, 50, 100, 500, 1000, 5000, 10000]

BRANCH_FILES = {
    "v033": {
        "accepted": Path("v033_full/episodes_v033_all.jsonl"),
        "matches": Path("v033_full/redteam_matches_v033.jsonl"),
        "suppressed": Path("v033_full/episodes_v033_suppressed_entropy.jsonl"),
        "suppressed_near": Path("v033_full/redteam_suppressed_near_matches_v033.jsonl"),
    },
    "v036": {
        "accepted": Path("v036_batches/episodes_v036_accepted.jsonl"),
        "matches": Path("v036_batches/redteam_matches_v036_FINAL_SPARSE.jsonl"),
        "suppressed": Path("v036_batches/episodes_v036_suppressed.jsonl"),
        "suppressed_near": Path("v036_batches/redteam_suppressed_near_matches_v036.jsonl"),
    },
}

DROP_FOR_LEARNED_PREFIXES = ("gate__",)
DROP_FOR_LEARNED_NAMES = {
    "score",
    "raw_score",
    "legacy_sria_score",
    "legacy_raw_score",
    "entropy_penalty",
    "max_risk",
    "candidate_gate_encoded",
}

BASE_NUMERIC_FEATURES = [
    "duration",
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
]

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


def load_match_maps(path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, List[int]], Dict[str, int]]:
    by_ep: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    rt_indices_by_ep: Dict[str, List[int]] = defaultdict(list)
    exact_by_ep: Dict[str, int] = defaultdict(int)

    if not path.exists():
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

    unique_pos = len(by_ep)
    unique_rt = len({i for vals in rt_indices_by_ep.values() for i in vals})
    print(f"Loaded {count} match records from {path}; positive episodes={unique_pos}; represented redteam events={unique_rt}")
    return by_ep, rt_indices_by_ep, exact_by_ep


def load_suppressed_near_ids(path: Path) -> set[str]:
    ids = set()
    if not path.exists():
        return ids
    for obj in load_jsonl(path):
        ep = obj.get("episode", {})
        ep_id = str(ep.get("id") or ep.get("episode_id") or obj.get("episode_id") or "")
        if ep_id:
            ids.add(ep_id)
    print(f"Loaded {len(ids)} suppressed near-match ids from {path}")
    return ids


def row_from_episode(
    obj: Dict[str, Any],
    branch: str,
    source_set: str,
    match_by_ep: Dict[str, List[Dict[str, Any]]],
    rt_by_ep: Dict[str, List[int]],
    exact_by_ep: Dict[str, int],
) -> Dict[str, Any]:
    ep = obj.get("episode", obj)
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
        "branch": branch,
        "source_set": source_set,
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

    for s in SIGNAL_NAMES:
        row[f"sig__{s}"] = 1.0 if s in sigset else 0.0

    label = 1 if ep_id in match_by_ep else 0
    row["label"] = label
    rt_indices = sorted(set(rt_by_ep.get(ep_id, [])))
    row["redteam_indices"] = ";".join(str(i) for i in rt_indices)
    row["redteam_count"] = len(rt_indices)
    row["exact_start_count"] = exact_by_ep.get(ep_id, 0)

    if rt_indices:
        row["redteam_group"] = "rtgrp:" + "+".join(str(i) for i in rt_indices)
    else:
        row["redteam_group"] = f"neg:{ep_id}"

    return row


def load_branch_rows(
    base_dir: Path,
    branch: str,
    include_suppressed: bool,
    negative_sample: int,
    sample_mode: str,
    accepted_only_for_scoring: bool = False,
    seed: int = 1337,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    files = BRANCH_FILES[branch]
    accepted_path = base_dir / files["accepted"]
    matches_path = base_dir / files["matches"]
    suppressed_path = base_dir / files["suppressed"]
    suppressed_near_path = base_dir / files["suppressed_near"]

    match_by_ep, rt_by_ep, exact_by_ep = load_match_maps(matches_path)
    _near_ids = load_suppressed_near_ids(suppressed_near_path)

    rows: List[Dict[str, Any]] = []

    print(f"Loading accepted episodes for {branch} from {accepted_path}...")
    for i, obj in enumerate(load_jsonl(accepted_path), 1):
        if i % 100000 == 0:
            print(f"  loaded {i:,} accepted episodes...")
        rows.append(row_from_episode(obj, branch, "accepted", match_by_ep, rt_by_ep, exact_by_ep))
    accepted_count = len(rows)
    print(f"Loaded accepted rows for {branch}: {accepted_count:,}")

    suppressed_count = 0
    if include_suppressed and not accepted_only_for_scoring:
        if not suppressed_path.exists():
            print(f"WARNING: suppressed file not found: {suppressed_path}")
        else:
            print(f"Sampling up to {negative_sample:,} suppressed negatives from {suppressed_path} using mode={sample_mode}...")
            if sample_mode == "first":
                for obj in load_jsonl(suppressed_path):
                    if suppressed_count >= negative_sample:
                        break
                    row = row_from_episode(obj, branch, "suppressed", match_by_ep, rt_by_ep, exact_by_ep)
                    if row["label"] == 0:
                        rows.append(row)
                        suppressed_count += 1
            elif sample_mode == "reservoir":
                rng = random.Random(seed)
                reservoir: List[Dict[str, Any]] = []
                seen = 0
                for obj in load_jsonl(suppressed_path):
                    row = row_from_episode(obj, branch, "suppressed", match_by_ep, rt_by_ep, exact_by_ep)
                    if row["label"] != 0:
                        continue
                    seen += 1
                    if len(reservoir) < negative_sample:
                        reservoir.append(row)
                    else:
                        j = rng.randint(1, seen)
                        if j <= negative_sample:
                            reservoir[j - 1] = row
                    if seen % 1000000 == 0:
                        print(f"  reservoir scanned {seen:,} lines; kept {len(reservoir):,}/{negative_sample:,}...")
                rows.extend(reservoir)
                suppressed_count = len(reservoir)
            else:
                raise ValueError(f"Unsupported sample_mode: {sample_mode}")
            print(f"Loaded suppressed negative rows for {branch}: {suppressed_count:,}")

    unique_rt = len({int(x) for r in rows for x in str(r.get("redteam_indices", "")).split(";") if x.strip().isdigit()})
    meta = {
        "accepted_rows": accepted_count,
        "suppressed_rows": suppressed_count,
        "total_rows": len(rows),
        "positive_episodes": sum(1 for r in rows if r["label"] == 1),
        "represented_redteam_events": unique_rt,
    }
    print(
        f"Final rows for {branch}: {len(rows):,}; "
        f"positive episodes: {meta['positive_episodes']:,}; "
        f"represented redteam events: {unique_rt:,}"
    )
    return rows, meta


def build_feature_names(rows: Sequence[Dict[str, Any]]) -> List[str]:
    names = list(BASE_NUMERIC_FEATURES)
    names.extend([f"sig__{s}" for s in SIGNAL_NAMES])
    # Keep only names present and not leaked.
    out = []
    for n in names:
        if n in DROP_FOR_LEARNED_NAMES:
            continue
        if any(n.startswith(p) for p in DROP_FOR_LEARNED_PREFIXES):
            continue
        if any(n in r for r in rows):
            out.append(n)
    return out


def matrix_from_rows(rows: Sequence[Dict[str, Any]], feature_names: Sequence[str]) -> np.ndarray:
    X = np.zeros((len(rows), len(feature_names)), dtype=np.float32)
    for i, r in enumerate(rows):
        for j, n in enumerate(feature_names):
            X[i, j] = safe_float(r.get(n))
    return X


def labels_from_rows(rows: Sequence[Dict[str, Any]]) -> np.ndarray:
    return np.array([int(r.get("label", 0)) for r in rows], dtype=np.int32)


def build_model(name: str, random_state: int) -> Any:
    if name == "sgd_cw_none":
        return Pipeline([
            ("scaler", StandardScaler()),
            ("clf", SGDClassifier(
                loss="log_loss",
                penalty="l2",
                alpha=1e-4,
                max_iter=3000,
                tol=1e-4,
                class_weight=None,
                random_state=random_state,
            )),
        ])
    if name == "sgd_cw_balanced":
        return Pipeline([
            ("scaler", StandardScaler()),
            ("clf", SGDClassifier(
                loss="log_loss",
                penalty="l2",
                alpha=1e-4,
                max_iter=3000,
                tol=1e-4,
                class_weight="balanced",
                random_state=random_state,
            )),
        ])
    if name.startswith("tree_depth"):
        depth = int(name.split("tree_depth", 1)[1].split("_", 1)[0])
        cw = "balanced" if name.endswith("_cw_balanced") else None
        return DecisionTreeClassifier(
            max_depth=depth,
            min_samples_leaf=5,
            class_weight=cw,
            random_state=random_state,
        )
    if name.startswith("rf"):
        # Supported forms:
        # rf_depth8_cw_none
        # rf_depth10_cw_balanced
        parts = name.split("_")
        depth = 8
        cw = None
        for p in parts:
            if p.startswith("depth"):
                depth = int(p.replace("depth", ""))
        if name.endswith("_cw_balanced"):
            cw = "balanced"
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=depth,
            min_samples_leaf=5,
            class_weight=cw,
            n_jobs=-1,
            random_state=random_state,
        )
    if name.startswith("hgb"):
        # Supported:
        # hgb_depth3
        # hgb_depth5
        depth = 3
        for p in name.split("_"):
            if p.startswith("depth"):
                depth = int(p.replace("depth", ""))
        return HistGradientBoostingClassifier(
            max_iter=200,
            learning_rate=0.05,
            max_leaf_nodes=31,
            max_depth=depth,
            l2_regularization=0.01,
            random_state=random_state,
        )
    raise ValueError(f"Unknown model name: {name}")


def model_scores(model: Any, X: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        if proba.shape[1] == 2:
            return proba[:, 1]
        return proba[:, -1]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        z = np.asarray(z, dtype=np.float64)
        # stable sigmoid
        return 1.0 / (1.0 + np.exp(-np.clip(z, -50, 50)))
    pred = model.predict(X)
    return np.asarray(pred, dtype=np.float64)


def topk_stats(rows: Sequence[Dict[str, Any]], scores: Sequence[float], top_ks: Sequence[int]) -> Dict[int, Dict[str, Any]]:
    order = np.argsort(-np.asarray(scores))
    total_rt = len({int(x) for r in rows for x in str(r.get("redteam_indices", "")).split(";") if x.strip().isdigit()})
    out: Dict[int, Dict[str, Any]] = {}

    for k in top_ks:
        kk = min(k, len(rows))
        idxs = order[:kk]
        pos_eps = 0
        rt_events = set()
        exact = 0
        gates = Counter()
        sources = Counter()
        users = Counter()

        for i in idxs:
            r = rows[int(i)]
            if int(r.get("label", 0)) == 1:
                pos_eps += 1
            exact += safe_int(r.get("exact_start_count"))
            gates[str(r.get("candidate_gate", "UNKNOWN"))] += 1
            sources[str(r.get("source", ""))] += 1
            users[str(r.get("user", ""))] += 1
            for x in str(r.get("redteam_indices", "")).split(";"):
                if x.strip().isdigit():
                    rt_events.add(int(x))

        out[k] = {
            "k": kk,
            "positive_episodes": pos_eps,
            "episode_precision": pos_eps / kk if kk else 0.0,
            "redteam_events": len(rt_events),
            "redteam_recall": len(rt_events) / total_rt if total_rt else 0.0,
            "exact_start_count": exact,
            "top_gates": gates.most_common(5),
            "top_sources": sources.most_common(5),
            "top_users": users.most_common(5),
        }

    return out


def write_ranked_csv(
    out_path: Path,
    rows: Sequence[Dict[str, Any]],
    scores: Sequence[float],
    top_n: Optional[int] = None,
) -> None:
    order = np.argsort(-np.asarray(scores))
    if top_n is not None:
        order = order[:top_n]

    fields = [
        "rank",
        "model_score",
        "branch",
        "source_set",
        "episode_id",
        "start_time",
        "end_time",
        "duration",
        "source",
        "user",
        "candidate_gate",
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
        "label",
        "redteam_count",
        "exact_start_count",
        "redteam_indices",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for rank, i in enumerate(order, 1):
            r = dict(rows[int(i)])
            r["rank"] = rank
            r["model_score"] = float(scores[int(i)])
            w.writerow(r)


def write_ranked_jsonl(
    out_path: Path,
    rows: Sequence[Dict[str, Any]],
    scores: Sequence[float],
    top_n: int,
) -> None:
    order = np.argsort(-np.asarray(scores))[:top_n]
    with out_path.open("w", encoding="utf-8") as f:
        for rank, i in enumerate(order, 1):
            r = dict(rows[int(i)])
            r["rank"] = rank
            r["model_score"] = float(scores[int(i)])
            f.write(json.dumps(r, sort_keys=True) + "\n")


def metric_summary(y: np.ndarray, scores: np.ndarray) -> Dict[str, Optional[float]]:
    if len(set(y.tolist())) < 2:
        return {"roc_auc": None, "average_precision": None}
    return {
        "roc_auc": float(roc_auc_score(y, scores)),
        "average_precision": float(average_precision_score(y, scores)),
    }


def format_topk_lines(stats: Dict[int, Dict[str, Any]]) -> List[str]:
    lines = []
    for k, s in stats.items():
        lines.append(
            f"  top{k}: pos_eps={s['positive_episodes']} "
            f"ep_prec={s['episode_precision']:.4f} "
            f"rt_events={s['redteam_events']} "
            f"rt_recall={s['redteam_recall']:.4f} "
            f"exact_start={s['exact_start_count']}"
        )
    return lines


def importance_lines(model_name: str, model: Any, feature_names: Sequence[str], limit: int = 25) -> List[str]:
    lines = []
    clf = model
    if isinstance(model, Pipeline):
        clf = model.named_steps.get("clf", model)

    if hasattr(clf, "coef_"):
        coefs = clf.coef_[0]
        pairs = sorted(zip(feature_names, coefs), key=lambda x: abs(x[1]), reverse=True)[:limit]
        lines.append(f"Top coefficients for {model_name}:")
        for n, v in pairs:
            lines.append(f"  {n}: {float(v):.6f}")
    elif hasattr(clf, "feature_importances_"):
        imps = clf.feature_importances_
        pairs = sorted(zip(feature_names, imps), key=lambda x: x[1], reverse=True)[:limit]
        lines.append(f"Top importances for {model_name}:")
        for n, v in pairs:
            lines.append(f"  {n}: {float(v):.6f}")
    else:
        lines.append(f"Feature importances unavailable for {model_name}.")
    return lines


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v0.4.4 clean model comparison")
    p.add_argument("--base-dir", default=".", help="Base SRIA directory")
    p.add_argument("--train-branch", choices=sorted(BRANCH_FILES), required=True)
    p.add_argument("--score-branch", choices=sorted(BRANCH_FILES), required=True)
    p.add_argument("--include-suppressed", action="store_true", help="Include sampled suppressed negatives in training")
    p.add_argument("--negative-sample", type=int, default=100000)
    p.add_argument("--sample-mode", choices=["first", "reservoir"], default="reservoir")
    p.add_argument("--models", default="tree_depth6_cw_none,tree_depth8_cw_none,tree_depth10_cw_none,rf_depth8_cw_none,rf_depth10_cw_none,hgb_depth3,hgb_depth5")
    p.add_argument("--score-set", choices=["accepted"], default="accepted")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--top-k", default="20,50,100,500,1000,5000,10000")
    p.add_argument("--random-state", type=int, default=1337)
    p.add_argument("--top-jsonl", type=int, default=5000)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    base = Path(args.base_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    top_ks = [int(x) for x in args.top_k.split(",") if x.strip()]

    print("=" * 80)
    print("SRIA RT v0.4.4 - Clean Model Comparison")
    print("=" * 80)
    print(f"Train branch: {args.train_branch}")
    print(f"Score branch: {args.score_branch}")
    print(f"Models: {', '.join(models)}")
    print(f"Output dir: {out_dir}")
    print("NOTE: This compares queue rankers using stripped upstream features only.")
    print("NOTE: This is not a held-out deployment precision estimate.")
    print("=" * 80)

    train_rows, train_meta = load_branch_rows(
        base,
        args.train_branch,
        include_suppressed=args.include_suppressed,
        negative_sample=args.negative_sample,
        sample_mode=args.sample_mode,
        accepted_only_for_scoring=False,
        seed=args.random_state,
    )

    # Always score accepted only for the score branch.
    score_rows, score_meta_full = load_branch_rows(
        base,
        args.score_branch,
        include_suppressed=False,
        negative_sample=0,
        sample_mode=args.sample_mode,
        accepted_only_for_scoring=True,
        seed=args.random_state,
    )

    feature_names = build_feature_names(train_rows + score_rows)
    feature_path = out_dir / f"features_train_{args.train_branch}_score_{args.score_branch}.txt"
    feature_path.write_text("\n".join(feature_names) + "\n", encoding="utf-8")

    X_train = matrix_from_rows(train_rows, feature_names)
    y_train = labels_from_rows(train_rows)
    X_score = matrix_from_rows(score_rows, feature_names)
    y_score = labels_from_rows(score_rows)

    comparison_rows = []
    report_lines = []
    report_lines.append("SRIA RT v0.4.4 Clean Model Comparison")
    report_lines.append("=" * 80)
    report_lines.append(f"train_branch: {args.train_branch}")
    report_lines.append(f"score_branch: {args.score_branch}")
    report_lines.append(f"include_suppressed_training: {args.include_suppressed}")
    report_lines.append(f"negative_sample: {args.negative_sample:,}")
    report_lines.append(f"sample_mode: {args.sample_mode}")
    report_lines.append(f"train_rows: {len(train_rows):,}")
    report_lines.append(f"train_positive_episodes: {int(y_train.sum()):,}")
    report_lines.append(f"scored_rows: {len(score_rows):,}")
    report_lines.append(f"scored_positive_episodes: {int(y_score.sum()):,}")
    report_lines.append("feature_set: STRIPPED only; drops score/raw_score/entropy_penalty/max_risk/gate outputs")
    report_lines.append(f"feature_count: {len(feature_names)}")
    report_lines.append("methodological_note: queue generation / cross-branch scoring, not deployment precision.")
    report_lines.append("")

    # Legacy reference
    legacy_scores = np.array([safe_float(r.get("legacy_sria_score")) for r in score_rows], dtype=np.float64)
    legacy_stats = topk_stats(score_rows, legacy_scores, top_ks)
    legacy_metrics = metric_summary(y_score, legacy_scores)

    report_lines.append("Legacy SRIA score reference")
    report_lines.append("-" * 80)
    report_lines.append(f"ROC_AUC={legacy_metrics['roc_auc']} AP={legacy_metrics['average_precision']}")
    report_lines.extend(format_topk_lines(legacy_stats))
    report_lines.append("")

    for k, s in legacy_stats.items():
        comparison_rows.append({
            "model": "legacy_sria_score",
            "k": k,
            "positive_episodes": s["positive_episodes"],
            "episode_precision": s["episode_precision"],
            "redteam_events": s["redteam_events"],
            "redteam_recall": s["redteam_recall"],
            "exact_start_count": s["exact_start_count"],
            "roc_auc": legacy_metrics["roc_auc"],
            "average_precision": legacy_metrics["average_precision"],
        })

    for model_name in models:
        print(f"Training {model_name} on {len(train_rows):,} rows...")
        t0 = time.time()
        model = build_model(model_name, args.random_state)
        model.fit(X_train, y_train)
        dt = time.time() - t0
        print(f"  done {model_name} in {dt:.1f}s")

        artifact = out_dir / f"model_{args.train_branch}_{model_name}.joblib"
        joblib.dump({
            "model": model,
            "feature_names": feature_names,
            "train_branch": args.train_branch,
            "score_branch": args.score_branch,
            "model_name": model_name,
            "version": "v0.4.4",
            "leakage_discipline": "stripped_features_no_score_raw_entropy_maxrisk_gate_outputs",
        }, artifact)

        print(f"Scoring {model_name} on {len(score_rows):,} rows...")
        scores = model_scores(model, X_score)

        metrics = metric_summary(y_score, scores)
        stats = topk_stats(score_rows, scores, top_ks)

        ranked_csv = out_dir / f"ranked_{args.score_branch}_{model_name}.csv"
        ranked_jsonl = out_dir / f"ranked_{args.score_branch}_{model_name}_top{args.top_jsonl}.jsonl"
        write_ranked_csv(ranked_csv, score_rows, scores)
        write_ranked_jsonl(ranked_jsonl, score_rows, scores, top_n=args.top_jsonl)

        report_lines.append(f"Model: {model_name}")
        report_lines.append("-" * 80)
        report_lines.append(f"artifact: {artifact}")
        report_lines.append(f"ranked_csv: {ranked_csv}")
        report_lines.append(f"ranked_jsonl_top{args.top_jsonl}: {ranked_jsonl}")
        report_lines.append(f"ROC_AUC={metrics['roc_auc']} AP={metrics['average_precision']}")
        report_lines.extend(format_topk_lines(stats))
        report_lines.extend(importance_lines(model_name, model, feature_names))
        report_lines.append("")

        for k, s in stats.items():
            comparison_rows.append({
                "model": model_name,
                "k": k,
                "positive_episodes": s["positive_episodes"],
                "episode_precision": s["episode_precision"],
                "redteam_events": s["redteam_events"],
                "redteam_recall": s["redteam_recall"],
                "exact_start_count": s["exact_start_count"],
                "roc_auc": metrics["roc_auc"],
                "average_precision": metrics["average_precision"],
            })

    comparison_csv = out_dir / f"model_comparison_train_{args.train_branch}_score_{args.score_branch}.csv"
    with comparison_csv.open("w", encoding="utf-8", newline="") as f:
        fields = [
            "model",
            "k",
            "positive_episodes",
            "episode_precision",
            "redteam_events",
            "redteam_recall",
            "exact_start_count",
            "roc_auc",
            "average_precision",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in comparison_rows:
            w.writerow(r)

    # Winner summary by K
    report_lines.append("Winner summary by K")
    report_lines.append("-" * 80)
    by_k: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for r in comparison_rows:
        by_k[int(r["k"])].append(r)
    for k in top_ks:
        rows = sorted(by_k[k], key=lambda r: (float(r["redteam_events"]), float(r["positive_episodes"])), reverse=True)
        if rows:
            w = rows[0]
            report_lines.append(
                f"top{k}: winner={w['model']} rt_events={w['redteam_events']} "
                f"rt_recall={float(w['redteam_recall']):.4f} pos_eps={w['positive_episodes']}"
            )

    report_lines.append("")
    report_lines.append(f"Model comparison CSV: {comparison_csv}")

    report_path = out_dir / f"v044_model_comparison_train_{args.train_branch}_score_{args.score_branch}.txt"
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print("")
    print("\n".join(report_lines))
    print(f"Wrote report: {report_path}")


if __name__ == "__main__":
    main()
