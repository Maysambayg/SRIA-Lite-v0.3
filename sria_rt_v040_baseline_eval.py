#!/usr/bin/env python3
"""
SRIA RT v0.4.0 - Baseline Evaluation Harness

Purpose
-------
Compare SRIA hand-gated episode scoring against simple learned baselines using
existing JSONL episode outputs. This script does NOT rescan auth.txt.

It builds an episode-level dataset from:
  - accepted episode JSONL
  - red-team match JSONL (post-hoc labels only)
  - optional suppressed episode JSONL sampled as additional negatives
  - optional suppressed near-match JSONL to exclude ambiguous negatives

Then it evaluates:
  - SRIA gate score / raw score ranking
  - simple feature sum ranking
  - L1/L2 logistic regression
  - random forest
  - histogram gradient boosting, when available

Important limitations
---------------------
This is a baseline over existing sparse-window episode/candidate outputs. It is
NOT a deployment precision estimate over the full negative-only auth population.
It is designed to answer the immediate research question:

  Do simple learned baselines rank/lift red-team-overlap episodes better than
  our hand-gated SRIA score using the same engineered features?

Recommended first run
---------------------
  py sria_rt_v040_baseline_eval.py --base-dir . --branch v033 --include-suppressed --negative-sample 300000

Useful follow-up
----------------
  py sria_rt_v040_baseline_eval.py --base-dir . --branch v036 --include-suppressed --negative-sample 300000
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import numpy as np
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
except Exception as exc:  # pragma: no cover
    print("ERROR: This script requires scikit-learn and numpy.")
    print("Install with:")
    print("  py -m pip install scikit-learn numpy")
    print(f"Original import error: {exc}")
    sys.exit(1)


NUMERIC_FEATURES = [
    "duration",
    "events_count",
    "destination_count",
    "user_count",
    "first_time_event_count",
    "first_time_signal_hits",
    "new_destination_event_count",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "entropy_penalty",
    "raw_score",
    "score",
    "max_risk",
]

SIGNAL_FEATURES = [
    "first_time_source_user_to_dest",
    "first_time_user_to_dest",
    "first_time_source_to_dest",
    "source_fanout",
    "user_fanout",
    "source_user_fanout",
    "compact_lateral_burst",
    "fanout_velocity",
    "propagation_convergence_bonus",
    "entropy_low_novelty",
    "entropy_soft_duration",
    "entropy_long_duration",
    "entropy_many_events",
    "entropy_extreme_events",
    "entropy_oversized_fanout",
    "entropy_excessive_destinations",
    "source_user_fanout_rescue_bonus",
    "compact_rescue_bonus",
]

GATES = [
    "A_balanced_source_user_propagation",
    "B_high_velocity",
    "C_dense_novel_burst",
    "D_compact_novelty_rescue",
    "E_source_user_fanout_rescue",
]

ALL_FEATURES = NUMERIC_FEATURES + [f"sig__{s}" for s in SIGNAL_FEATURES] + [f"gate__{g}" for g in GATES]


@dataclass
class BranchPaths:
    name: str
    accepted: Path
    matches: Path
    suppressed: Optional[Path]
    suppressed_near: Optional[Path]


def default_branch_paths(base_dir: Path, branch: str) -> BranchPaths:
    branch = branch.lower()
    if branch == "v033":
        return BranchPaths(
            name="v033",
            accepted=base_dir / "v033_full" / "episodes_v033_all.jsonl",
            matches=base_dir / "v033_full" / "redteam_matches_v033.jsonl",
            suppressed=base_dir / "v033_full" / "episodes_v033_suppressed_entropy.jsonl",
            suppressed_near=base_dir / "v033_full" / "redteam_suppressed_near_matches_v033.jsonl",
        )
    if branch == "v036":
        match = base_dir / "v036_batches" / "redteam_matches_v036_FINAL_SPARSE.jsonl"
        if not match.exists():
            match = base_dir / "v036_batches" / "redteam_matches_v036.jsonl"
        return BranchPaths(
            name="v036",
            accepted=base_dir / "v036_batches" / "episodes_v036_accepted.jsonl",
            matches=match,
            suppressed=base_dir / "v036_batches" / "episodes_v036_suppressed.jsonl",
            suppressed_near=base_dir / "v036_batches" / "redteam_suppressed_near_matches_v036.jsonl",
        )
    raise ValueError(f"Unknown branch: {branch}. Use v033 or v036, or pass explicit paths.")


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as exc:
                print(f"WARNING: Skipping malformed JSON line {line_no} in {path}: {exc}")


def load_match_maps(path: Path) -> Tuple[Set[int], Dict[int, Set[int]], Dict[int, int], Dict[int, Counter]]:
    """Return positive episode ids, episode->redteam indices, exact counts, gate counts."""
    positive_ep_ids: Set[int] = set()
    ep_to_rt: Dict[int, Set[int]] = defaultdict(set)
    ep_exact_counts: Dict[int, int] = defaultdict(int)
    ep_gate_counts: Dict[int, Counter] = defaultdict(Counter)

    for obj in iter_jsonl(path):
        ep = obj.get("episode", {}) or {}
        ep_id = ep.get("id")
        if ep_id is None:
            continue
        try:
            ep_id = int(ep_id)
        except Exception:
            continue
        positive_ep_ids.add(ep_id)
        idx = obj.get("redteam_index")
        if idx is not None:
            try:
                ep_to_rt[ep_id].add(int(idx))
            except Exception:
                pass
        if bool(obj.get("exact_start_match")):
            ep_exact_counts[ep_id] += 1
        gate = ep.get("candidate_gate") or "UNKNOWN"
        ep_gate_counts[ep_id][gate] += 1
    return positive_ep_ids, ep_to_rt, ep_exact_counts, ep_gate_counts


def load_suppressed_near_ids(path: Optional[Path]) -> Set[int]:
    ids: Set[int] = set()
    if not path or not path.exists():
        return ids
    for obj in iter_jsonl(path):
        ep = obj.get("episode", {}) or {}
        ep_id = ep.get("id")
        if ep_id is None:
            continue
        try:
            ids.add(int(ep_id))
        except Exception:
            pass
    return ids


def reservoir_sample_jsonl(path: Path, k: int, seed: int, skip_ids: Set[int]) -> List[Dict[str, Any]]:
    """Reservoir sample up to k JSON objects from path, skipping ambiguous ids."""
    rng = random.Random(seed)
    sample: List[Dict[str, Any]] = []
    seen = 0
    for obj in iter_jsonl(path):
        ep_id = obj.get("id")
        try:
            ep_id_i = int(ep_id)
        except Exception:
            ep_id_i = None
        if ep_id_i is not None and ep_id_i in skip_ids:
            continue
        seen += 1
        if len(sample) < k:
            sample.append(obj)
        else:
            j = rng.randint(1, seen)
            if j <= k:
                sample[j - 1] = obj
    return sample


def safe_float(x: Any, default: float = 0.0) -> float:
    try:
        if x is None:
            return default
        v = float(x)
        if math.isnan(v) or math.isinf(v):
            return default
        return v
    except Exception:
        return default


def episode_to_row(
    ep: Dict[str, Any],
    source_set: str,
    positive_ep_ids: Set[int],
    ep_to_rt: Dict[int, Set[int]],
    ep_exact_counts: Dict[int, int],
    ep_gate_counts: Dict[int, Counter],
) -> Dict[str, Any]:
    ep_id = int(ep.get("id"))
    signals = set(ep.get("signals", []) or [])
    gate = ep.get("candidate_gate", "") or ""
    row: Dict[str, Any] = {
        "episode_id": ep_id,
        "source_set": source_set,
        "label": 1 if ep_id in positive_ep_ids else 0,
        "redteam_count": len(ep_to_rt.get(ep_id, set())),
        "exact_start_count": ep_exact_counts.get(ep_id, 0),
        "start_time": int(safe_float(ep.get("start_time"), 0)),
        "end_time": int(safe_float(ep.get("end_time"), 0)),
        "candidate_gate": gate,
        "source": ep.get("source", ""),
        "user": ep.get("user", ""),
    }
    for name in NUMERIC_FEATURES:
        row[name] = safe_float(ep.get(name), 0.0)
    for sig in SIGNAL_FEATURES:
        row[f"sig__{sig}"] = 1.0 if sig in signals else 0.0
    for g in GATES:
        row[f"gate__{g}"] = 1.0 if gate == g else 0.0
    # Useful compact composite not directly in the original output.
    row["simple_feature_sum"] = (
        row["novelty_ratio"]
        + row["compactness_score"]
        + row["fanout_velocity_score"]
        + 0.25 * row["sig__first_time_source_user_to_dest"]
        + 0.15 * row["sig__source_user_fanout"]
        - row["entropy_penalty"]
    )
    return row


def write_dataset_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    fields = [
        "episode_id", "source_set", "label", "redteam_count", "exact_start_count",
        "start_time", "end_time", "candidate_gate", "source", "user",
    ] + ALL_FEATURES + ["simple_feature_sum"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def make_matrix(rows: Sequence[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[int]]:
    feature_names = ALL_FEATURES + ["simple_feature_sum"]
    X = np.array([[safe_float(r.get(c), 0.0) for c in feature_names] for r in rows], dtype=float)
    y = np.array([int(r["label"]) for r in rows], dtype=int)
    times = np.array([int(r.get("start_time", 0)) for r in rows], dtype=np.int64)
    episode_ids = [int(r["episode_id"]) for r in rows]
    return X, y, times, episode_ids


def split_indices(y: np.ndarray, times: np.ndarray, mode: str, seed: int, train_frac: float = 0.70) -> Tuple[np.ndarray, np.ndarray]:
    n = len(y)
    if mode == "time":
        order = np.argsort(times, kind="mergesort")
        cut = int(n * train_frac)
        train_idx = order[:cut]
        test_idx = order[cut:]
    elif mode == "stratified_random":
        rng = np.random.default_rng(seed)
        pos = np.where(y == 1)[0]
        neg = np.where(y == 0)[0]
        rng.shuffle(pos)
        rng.shuffle(neg)
        pos_cut = int(len(pos) * train_frac)
        neg_cut = int(len(neg) * train_frac)
        train_idx = np.concatenate([pos[:pos_cut], neg[:neg_cut]])
        test_idx = np.concatenate([pos[pos_cut:], neg[neg_cut:]])
        rng.shuffle(train_idx)
        rng.shuffle(test_idx)
    else:
        raise ValueError(mode)
    return train_idx, test_idx


def scores_gate(rows: Sequence[Dict[str, Any]], field: str) -> np.ndarray:
    return np.array([safe_float(r.get(field), 0.0) for r in rows], dtype=float)


def topk_metrics(
    rows: Sequence[Dict[str, Any]],
    scores: np.ndarray,
    ep_to_rt: Dict[int, Set[int]],
    topks: Sequence[int],
) -> List[Dict[str, Any]]:
    order = np.argsort(-scores, kind="mergesort")
    total_positive_eps = sum(1 for r in rows if int(r["label"]) == 1)
    total_redteam = set()
    for r in rows:
        if int(r["label"]) == 1:
            total_redteam.update(ep_to_rt.get(int(r["episode_id"]), set()))
    total_redteam_count = len(total_redteam)

    out = []
    for k in topks:
        kk = min(k, len(order))
        chosen = order[:kk]
        hit_eps = 0
        hit_redteam = set()
        for i in chosen:
            row = rows[int(i)]
            ep_id = int(row["episode_id"])
            if int(row["label"]) == 1:
                hit_eps += 1
                hit_redteam.update(ep_to_rt.get(ep_id, set()))
        out.append({
            "top_k": kk,
            "positive_episodes_hit": hit_eps,
            "episode_precision_at_k": hit_eps / kk if kk else 0.0,
            "episode_recall_at_k": hit_eps / total_positive_eps if total_positive_eps else 0.0,
            "redteam_events_hit": len(hit_redteam),
            "redteam_recall_at_k": len(hit_redteam) / total_redteam_count if total_redteam_count else 0.0,
            "total_positive_episodes_in_eval": total_positive_eps,
            "total_redteam_events_in_eval": total_redteam_count,
        })
    return out


def fit_models(X_train: np.ndarray, y_train: np.ndarray, seed: int) -> Dict[str, Any]:
    models: Dict[str, Any] = {}

    if len(np.unique(y_train)) < 2:
        return models

    models["logreg_l2"] = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            penalty="l2",
            solver="liblinear",
            class_weight="balanced",
            max_iter=1000,
            random_state=seed,
        )),
    ])

    models["logreg_l1"] = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            penalty="l1",
            solver="liblinear",
            class_weight="balanced",
            max_iter=1000,
            random_state=seed,
        )),
    ])

    models["random_forest"] = RandomForestClassifier(
        n_estimators=250,
        max_depth=10,
        min_samples_leaf=5,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=seed,
    )

    models["hist_gradient_boosting"] = HistGradientBoostingClassifier(
        max_iter=180,
        learning_rate=0.06,
        max_leaf_nodes=31,
        l2_regularization=0.01,
        random_state=seed,
    )

    for name, model in list(models.items()):
        try:
            if name == "hist_gradient_boosting":
                # Approximate class weighting via sample weights.
                pos = max(1, int(np.sum(y_train == 1)))
                neg = max(1, int(np.sum(y_train == 0)))
                weights = np.where(y_train == 1, neg / pos, 1.0)
                model.fit(X_train, y_train, sample_weight=weights)
            else:
                model.fit(X_train, y_train)
        except Exception as exc:
            print(f"WARNING: model {name} failed: {exc}")
            models.pop(name, None)
    return models


def proba_or_score(model: Any, X: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        return 1.0 / (1.0 + np.exp(-z))
    return model.predict(X).astype(float)


def safe_auc(y_true: np.ndarray, scores: np.ndarray) -> Tuple[Optional[float], Optional[float]]:
    if len(np.unique(y_true)) < 2:
        return None, None
    try:
        roc = float(roc_auc_score(y_true, scores))
    except Exception:
        roc = None
    try:
        ap = float(average_precision_score(y_true, scores))
    except Exception:
        ap = None
    return roc, ap


def feature_importance_lines(model_name: str, model: Any, feature_names: List[str], limit: int = 25) -> List[str]:
    lines = []
    try:
        if model_name.startswith("logreg") and hasattr(model, "named_steps"):
            clf = model.named_steps["clf"]
            coef = clf.coef_[0]
            pairs = sorted(zip(feature_names, coef), key=lambda x: abs(x[1]), reverse=True)[:limit]
            lines.append(f"Top coefficients for {model_name}:")
            for name, val in pairs:
                lines.append(f"  {name}: {val:.5f}")
        elif model_name == "random_forest":
            pairs = sorted(zip(feature_names, model.feature_importances_), key=lambda x: x[1], reverse=True)[:limit]
            lines.append(f"Top importances for {model_name}:")
            for name, val in pairs:
                lines.append(f"  {name}: {val:.5f}")
    except Exception as exc:
        lines.append(f"Could not extract feature importances for {model_name}: {exc}")
    return lines


def evaluate_split(
    split_name: str,
    rows: List[Dict[str, Any]],
    train_idx: np.ndarray,
    test_idx: np.ndarray,
    ep_to_rt: Dict[int, Set[int]],
    out_dir: Path,
    seed: int,
) -> List[str]:
    feature_names = ALL_FEATURES + ["simple_feature_sum"]
    X, y, times, episode_ids = make_matrix(rows)
    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    test_rows = [rows[int(i)] for i in test_idx]

    topks = [50, 100, 250, 500, 1000, 2500, 5000, 10000, 20000, 50000, 100000]
    topks = [k for k in topks if k <= len(test_rows)] + ([len(test_rows)] if len(test_rows) not in topks else [])

    lines = []
    lines.append(f"Split: {split_name}")
    lines.append("-" * 80)
    lines.append(f"train episodes: {len(train_idx):,}  positives: {int(y_train.sum()):,}")
    lines.append(f"test episodes:  {len(test_idx):,}  positives: {int(y_test.sum()):,}")
    lines.append("")

    score_sets: Dict[str, np.ndarray] = {
        "sria_score": scores_gate(test_rows, "score"),
        "sria_raw_score": scores_gate(test_rows, "raw_score"),
        "simple_feature_sum": scores_gate(test_rows, "simple_feature_sum"),
        "fanout_velocity_score": scores_gate(test_rows, "fanout_velocity_score"),
        "novelty_ratio": scores_gate(test_rows, "novelty_ratio"),
    }

    models = fit_models(X_train, y_train, seed)
    for name, model in models.items():
        score_sets[name] = proba_or_score(model, X_test)

    metrics_csv = out_dir / f"metrics_{split_name}.csv"
    with metrics_csv.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "split", "model", "roc_auc", "average_precision", "top_k",
            "positive_episodes_hit", "episode_precision_at_k", "episode_recall_at_k",
            "redteam_events_hit", "redteam_recall_at_k",
            "total_positive_episodes_in_eval", "total_redteam_events_in_eval",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for model_name, scores in score_sets.items():
            roc, ap = safe_auc(y_test, scores)
            rows_k = topk_metrics(test_rows, scores, ep_to_rt, topks)
            for r in rows_k:
                rec = {
                    "split": split_name,
                    "model": model_name,
                    "roc_auc": "" if roc is None else f"{roc:.6f}",
                    "average_precision": "" if ap is None else f"{ap:.6f}",
                    **r,
                }
                w.writerow(rec)

    # Human-readable top-line summary at selected K.
    selected_k = [100, 500, 1000, 5000, 10000]
    lines.append("Top-line model metrics:")
    for model_name, scores in score_sets.items():
        roc, ap = safe_auc(y_test, scores)
        lines.append(f"  {model_name}: ROC_AUC={roc if roc is not None else 'NA'} AP={ap if ap is not None else 'NA'}")
        m = {r["top_k"]: r for r in topk_metrics(test_rows, scores, ep_to_rt, [k for k in selected_k if k <= len(test_rows)])}
        for k in selected_k:
            if k in m:
                r = m[k]
                lines.append(
                    f"    top{k}: pos_eps={r['positive_episodes_hit']} "
                    f"ep_prec={r['episode_precision_at_k']:.4f} "
                    f"rt_events={r['redteam_events_hit']} "
                    f"rt_recall={r['redteam_recall_at_k']:.4f}"
                )
    lines.append("")
    lines.append(f"Detailed metrics CSV: {metrics_csv}")
    lines.append("")

    # Feature importances.
    for name, model in models.items():
        imp = feature_importance_lines(name, model, feature_names)
        if imp:
            lines.extend(imp)
            lines.append("")

    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description="SRIA RT v0.4.0 baseline evaluation harness")
    ap.add_argument("--base-dir", default=".", help="Base directory containing v033_full/v036_batches")
    ap.add_argument("--branch", default="v033", choices=["v033", "v036"], help="Default file layout to use")
    ap.add_argument("--episodes", default="", help="Override accepted episodes JSONL")
    ap.add_argument("--matches", default="", help="Override redteam matches JSONL")
    ap.add_argument("--suppressed", default="", help="Override suppressed episodes JSONL")
    ap.add_argument("--suppressed-near", default="", help="Override suppressed near-match JSONL")
    ap.add_argument("--include-suppressed", action="store_true", help="Sample suppressed episodes as additional negatives")
    ap.add_argument("--negative-sample", type=int, default=300_000, help="Suppressed negative reservoir sample size")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default="", help="Output directory; default v040_baselines_<branch>")
    args = ap.parse_args()

    base = Path(args.base_dir)
    paths = default_branch_paths(base, args.branch)
    if args.episodes:
        paths.accepted = Path(args.episodes)
    if args.matches:
        paths.matches = Path(args.matches)
    if args.suppressed:
        paths.suppressed = Path(args.suppressed)
    if args.suppressed_near:
        paths.suppressed_near = Path(args.suppressed_near)

    out_dir = Path(args.out_dir) if args.out_dir else base / f"v040_baselines_{paths.name}"
    out_dir.mkdir(parents=True, exist_ok=True)

    for p, desc in [(paths.accepted, "accepted episodes"), (paths.matches, "redteam matches")]:
        if not p.exists():
            print(f"ERROR: Missing {desc}: {p}")
            return 2

    positive_ep_ids, ep_to_rt, ep_exact_counts, ep_gate_counts = load_match_maps(paths.matches)
    near_ids = load_suppressed_near_ids(paths.suppressed_near)

    rows: List[Dict[str, Any]] = []
    accepted_count = 0
    for ep in iter_jsonl(paths.accepted):
        try:
            int(ep.get("id"))
        except Exception:
            continue
        rows.append(episode_to_row(ep, "accepted", positive_ep_ids, ep_to_rt, ep_exact_counts, ep_gate_counts))
        accepted_count += 1

    suppressed_count = 0
    if args.include_suppressed:
        if paths.suppressed and paths.suppressed.exists():
            print(f"Sampling up to {args.negative_sample:,} suppressed negatives from {paths.suppressed} ...")
            negs = reservoir_sample_jsonl(paths.suppressed, args.negative_sample, args.seed, skip_ids=near_ids | positive_ep_ids)
            for ep in negs:
                try:
                    int(ep.get("id"))
                except Exception:
                    continue
                rows.append(episode_to_row(ep, "suppressed_sample", positive_ep_ids, ep_to_rt, ep_exact_counts, ep_gate_counts))
                suppressed_count += 1
        else:
            print(f"WARNING: --include-suppressed requested but suppressed file not found: {paths.suppressed}")

    # De-duplicate by episode_id, keeping accepted if duplicate.
    dedup: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        ep_id = int(row["episode_id"])
        if ep_id not in dedup or row["source_set"] == "accepted":
            dedup[ep_id] = row
    rows = list(dedup.values())

    if not rows:
        print("ERROR: No rows loaded.")
        return 2

    positives = sum(1 for r in rows if int(r["label"]) == 1)
    redteam_events = set()
    for r in rows:
        if int(r["label"]) == 1:
            redteam_events.update(ep_to_rt.get(int(r["episode_id"]), set()))

    dataset_csv = out_dir / f"episode_dataset_{paths.name}.csv"
    write_dataset_csv(dataset_csv, rows)

    lines = []
    lines.append("SRIA RT v0.4.0 Baseline Evaluation")
    lines.append("=" * 80)
    lines.append(f"branch: {paths.name}")
    lines.append(f"accepted episodes file: {paths.accepted}")
    lines.append(f"matches file: {paths.matches}")
    lines.append(f"suppressed file: {paths.suppressed}")
    lines.append(f"suppressed near-match file: {paths.suppressed_near}")
    lines.append(f"accepted rows loaded: {accepted_count:,}")
    lines.append(f"suppressed negative rows sampled: {suppressed_count:,}")
    lines.append(f"final dataset rows: {len(rows):,}")
    lines.append(f"positive episode labels: {positives:,}")
    lines.append(f"unique redteam events represented by positive episodes: {len(redteam_events):,}")
    lines.append(f"dataset CSV: {dataset_csv}")
    lines.append("")
    lines.append("Limitations:")
    lines.append("  - Labels are post-hoc red-team-overlap labels; they are NOT used by SRIA scoring.")
    lines.append("  - This evaluates existing sparse-window episode/candidate outputs, not deployment precision over the full negative-only population.")
    lines.append("  - Suppressed episodes are sampled negatives; use larger --negative-sample for more stable estimates.")
    lines.append("")

    # Build splits.
    X, y, times, episode_ids = make_matrix(rows)
    for split_name in ["time", "stratified_random"]:
        try:
            tr, te = split_indices(y, times, split_name, args.seed)
            if len(np.unique(y[tr])) < 2 or len(np.unique(y[te])) < 2:
                lines.append(f"Skipping split {split_name}: train/test lacks both classes.")
                continue
            lines.extend(evaluate_split(split_name, rows, tr, te, ep_to_rt, out_dir, args.seed))
        except Exception as exc:
            lines.append(f"Split {split_name} failed: {exc}")
            lines.append("")

    summary_path = out_dir / f"baseline_summary_{paths.name}.txt"
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWrote summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
