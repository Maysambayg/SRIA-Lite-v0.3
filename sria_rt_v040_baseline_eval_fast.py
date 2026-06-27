#!/usr/bin/env python3
"""
SRIA RT v0.4.0 FAST Baseline Evaluation Harness

Purpose
-------
A fast, laptop-safe baseline harness for comparing SRIA episode scores against
simple learned baselines using existing JSONL outputs. This does NOT rescan
auth.txt.

Why this file exists
--------------------
The original v040 baseline script used heavier LogisticRegression settings and
can stall on Python 3.13 + scikit-learn 1.8. This fast version avoids those
models by default, prints progress before every expensive step, and uses quick
baselines:

  - SRIA score / raw score rankers
  - simple engineered feature sum
  - SGD logistic classifier
  - shallow decision tree
  - optional small random forest

Recommended smoke test
----------------------
  py sria_rt_v040_baseline_eval_fast.py --base-dir . --branch v033 --include-suppressed --negative-sample 50000 --sample-mode first --models sgd,tree

Then inspect:
  powershell -NoProfile -Command "Get-Content .\\v040_fast_v033_50k\\baseline_summary_v033.txt -Tail 200"
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import SGDClassifier
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier
except Exception as exc:
    print("ERROR: This script requires scikit-learn and numpy.")
    print("Install with: py -m pip install numpy scikit-learn")
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

ALL_FEATURES = NUMERIC_FEATURES + [f"sig__{s}" for s in SIGNAL_FEATURES] + [f"gate__{g}" for g in GATES] + ["simple_feature_sum"]


@dataclass
class BranchPaths:
    name: str
    accepted: Path
    matches: Path
    suppressed: Optional[Path]
    suppressed_near: Optional[Path]


def log(msg: str) -> None:
    print(msg, flush=True)


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
    raise ValueError(f"Unknown branch: {branch}. Use v033 or v036.")


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception as exc:
                log(f"WARNING: skipping malformed JSON line {line_no} in {path}: {exc}")


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


def safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(float(x))
    except Exception:
        return default


def load_match_maps(path: Path) -> Tuple[Set[int], Dict[int, Set[int]], Dict[int, int], Dict[int, Counter]]:
    positive_ep_ids: Set[int] = set()
    ep_to_rt: Dict[int, Set[int]] = defaultdict(set)
    ep_exact_counts: Dict[int, int] = defaultdict(int)
    ep_gate_counts: Dict[int, Counter] = defaultdict(Counter)
    count = 0
    for obj in iter_jsonl(path):
        ep = obj.get("episode", {}) or {}
        ep_id = ep.get("id")
        if ep_id is None:
            continue
        ep_id = safe_int(ep_id, -1)
        if ep_id < 0:
            continue
        count += 1
        positive_ep_ids.add(ep_id)
        idx = obj.get("redteam_index")
        if idx is not None:
            ep_to_rt[ep_id].add(safe_int(idx, -1))
            ep_to_rt[ep_id].discard(-1)
        if bool(obj.get("exact_start_match")):
            ep_exact_counts[ep_id] += 1
        gate = ep.get("candidate_gate") or "UNKNOWN"
        ep_gate_counts[ep_id][gate] += 1
    log(f"Loaded {count:,} match records from {path}; positive episodes={len(positive_ep_ids):,}")
    return positive_ep_ids, ep_to_rt, ep_exact_counts, ep_gate_counts


def load_suppressed_near_ids(path: Optional[Path]) -> Set[int]:
    ids: Set[int] = set()
    if not path or not path.exists():
        return ids
    for obj in iter_jsonl(path):
        ep = obj.get("episode", {}) or obj
        ep_id = ep.get("id")
        if ep_id is not None:
            ids.add(safe_int(ep_id, -1))
    ids.discard(-1)
    log(f"Loaded {len(ids):,} suppressed near-match ids from {path}")
    return ids


def sample_suppressed_first(path: Path, k: int, skip_ids: Set[int]) -> List[Dict[str, Any]]:
    sample: List[Dict[str, Any]] = []
    scanned = 0
    for obj in iter_jsonl(path):
        scanned += 1
        ep_id = safe_int(obj.get("id"), -1)
        if ep_id in skip_ids:
            continue
        sample.append(obj)
        if len(sample) >= k:
            break
        if scanned % 100000 == 0:
            log(f"  sampled {len(sample):,}/{k:,} suppressed negatives after scanning {scanned:,} lines...")
    return sample


def sample_suppressed_reservoir(path: Path, k: int, seed: int, skip_ids: Set[int]) -> List[Dict[str, Any]]:
    rng = random.Random(seed)
    sample: List[Dict[str, Any]] = []
    seen = 0
    scanned = 0
    for obj in iter_jsonl(path):
        scanned += 1
        ep_id = safe_int(obj.get("id"), -1)
        if ep_id in skip_ids:
            continue
        seen += 1
        if len(sample) < k:
            sample.append(obj)
        else:
            j = rng.randint(1, seen)
            if j <= k:
                sample[j - 1] = obj
        if scanned % 1000000 == 0:
            log(f"  reservoir scanned {scanned:,} lines; kept {len(sample):,}/{k:,}...")
    return sample


def episode_to_row(
    ep: Dict[str, Any],
    source_set: str,
    positive_ep_ids: Set[int],
    ep_to_rt: Dict[int, Set[int]],
    ep_exact_counts: Dict[int, int],
) -> Optional[Dict[str, Any]]:
    ep_id = safe_int(ep.get("id"), -1)
    if ep_id < 0:
        return None
    signals = set(ep.get("signals", []) or [])
    gate = ep.get("candidate_gate", "") or ""
    row: Dict[str, Any] = {
        "episode_id": ep_id,
        "source_set": source_set,
        "label": 1 if ep_id in positive_ep_ids else 0,
        "redteam_count": len(ep_to_rt.get(ep_id, set())),
        "exact_start_count": ep_exact_counts.get(ep_id, 0),
        "start_time": safe_int(ep.get("start_time"), 0),
        "end_time": safe_int(ep.get("end_time"), 0),
        "candidate_gate": gate,
    }
    for name in NUMERIC_FEATURES:
        row[name] = safe_float(ep.get(name), 0.0)
    for sig in SIGNAL_FEATURES:
        row[f"sig__{sig}"] = 1.0 if sig in signals else 0.0
    for g in GATES:
        row[f"gate__{g}"] = 1.0 if gate == g else 0.0
    row["simple_feature_sum"] = (
        row["novelty_ratio"]
        + row["compactness_score"]
        + row["fanout_velocity_score"]
        + 0.25 * row["sig__first_time_source_user_to_dest"]
        + 0.15 * row["sig__source_user_fanout"]
        - row["entropy_penalty"]
    )
    return row


def make_matrix(rows: Sequence[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    X = np.array([[safe_float(r.get(c), 0.0) for c in ALL_FEATURES] for r in rows], dtype=np.float32)
    y = np.array([int(r["label"]) for r in rows], dtype=np.int8)
    times = np.array([safe_int(r.get("start_time"), 0) for r in rows], dtype=np.int64)
    return X, y, times


def split_indices(y: np.ndarray, times: np.ndarray, mode: str, seed: int, train_frac: float = 0.70) -> Tuple[np.ndarray, np.ndarray]:
    n = len(y)
    if mode == "time":
        order = np.argsort(times, kind="mergesort")
        cut = int(n * train_frac)
        return order[:cut], order[cut:]
    rng = np.random.default_rng(seed)
    pos = np.where(y == 1)[0]
    neg = np.where(y == 0)[0]
    rng.shuffle(pos)
    rng.shuffle(neg)
    train = np.concatenate([pos[: int(len(pos) * train_frac)], neg[: int(len(neg) * train_frac)]])
    test = np.concatenate([pos[int(len(pos) * train_frac):], neg[int(len(neg) * train_frac):]])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test


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


def topk_metrics(rows: Sequence[Dict[str, Any]], scores: np.ndarray, ep_to_rt: Dict[int, Set[int]], topks: Sequence[int]) -> List[Dict[str, Any]]:
    order = np.argsort(-scores, kind="mergesort")
    total_pos_eps = sum(1 for r in rows if int(r["label"]) == 1)
    total_rt: Set[int] = set()
    for r in rows:
        if int(r["label"]) == 1:
            total_rt.update(ep_to_rt.get(int(r["episode_id"]), set()))
    out: List[Dict[str, Any]] = []
    for k in topks:
        kk = min(k, len(order))
        chosen = order[:kk]
        hit_eps = 0
        hit_rt: Set[int] = set()
        for idx in chosen:
            row = rows[int(idx)]
            if int(row["label"]) == 1:
                hit_eps += 1
                hit_rt.update(ep_to_rt.get(int(row["episode_id"]), set()))
        out.append({
            "top_k": kk,
            "positive_episodes_hit": hit_eps,
            "episode_precision_at_k": hit_eps / kk if kk else 0.0,
            "episode_recall_at_k": hit_eps / total_pos_eps if total_pos_eps else 0.0,
            "redteam_events_hit": len(hit_rt),
            "redteam_recall_at_k": len(hit_rt) / len(total_rt) if total_rt else 0.0,
            "total_positive_episodes_in_eval": total_pos_eps,
            "total_redteam_events_in_eval": len(total_rt),
        })
    return out


def proba_or_score(model: Any, X: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        z = np.clip(z, -40, 40)
        return 1.0 / (1.0 + np.exp(-z))
    return model.predict(X).astype(float)


def fit_requested_models(X_train: np.ndarray, y_train: np.ndarray, model_names: Set[str], seed: int) -> Dict[str, Any]:
    models: Dict[str, Any] = {}
    if len(np.unique(y_train)) < 2:
        log("Skipping learned models: train split lacks both classes.")
        return models

    specs: Dict[str, Any] = {}
    if "sgd" in model_names:
        specs["sgd_logreg_l2"] = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("clf", SGDClassifier(
                loss="log_loss",
                penalty="l2",
                alpha=1e-4,
                max_iter=1000,
                tol=1e-3,
                class_weight="balanced",
                random_state=seed,
                n_jobs=-1,
            )),
        ])
    if "tree" in model_names:
        specs["decision_tree_depth6"] = DecisionTreeClassifier(
            max_depth=6,
            min_samples_leaf=10,
            class_weight="balanced",
            random_state=seed,
        )
    if "rf" in model_names:
        specs["random_forest_small"] = RandomForestClassifier(
            n_estimators=60,
            max_depth=8,
            min_samples_leaf=10,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=seed,
        )
    if "hgb" in model_names:
        specs["hist_gradient_boosting_small"] = HistGradientBoostingClassifier(
            max_iter=60,
            learning_rate=0.08,
            max_leaf_nodes=15,
            l2_regularization=0.01,
            random_state=seed,
        )

    for name, model in specs.items():
        t0 = time.time()
        log(f"Training {name} on {len(y_train):,} rows...")
        try:
            if name == "hist_gradient_boosting_small":
                pos = max(1, int(np.sum(y_train == 1)))
                neg = max(1, int(np.sum(y_train == 0)))
                weights = np.where(y_train == 1, neg / pos, 1.0)
                model.fit(X_train, y_train, sample_weight=weights)
            else:
                model.fit(X_train, y_train)
            models[name] = model
            log(f"  done {name} in {time.time() - t0:.1f}s")
        except Exception as exc:
            log(f"  WARNING: model {name} failed: {exc}")
    return models


def feature_importance_lines(model_name: str, model: Any, limit: int = 20) -> List[str]:
    lines: List[str] = []
    try:
        if model_name == "sgd_logreg_l2" and hasattr(model, "named_steps"):
            coef = model.named_steps["clf"].coef_[0]
            pairs = sorted(zip(ALL_FEATURES, coef), key=lambda x: abs(x[1]), reverse=True)[:limit]
            lines.append(f"Top coefficients for {model_name}:")
            for name, val in pairs:
                lines.append(f"  {name}: {val:.5f}")
        elif hasattr(model, "feature_importances_"):
            pairs = sorted(zip(ALL_FEATURES, model.feature_importances_), key=lambda x: x[1], reverse=True)[:limit]
            lines.append(f"Top importances for {model_name}:")
            for name, val in pairs:
                lines.append(f"  {name}: {val:.5f}")
    except Exception as exc:
        lines.append(f"Could not extract importances for {model_name}: {exc}")
    return lines


def evaluate_split(split_name: str, rows: List[Dict[str, Any]], train_idx: np.ndarray, test_idx: np.ndarray, ep_to_rt: Dict[int, Set[int]], out_dir: Path, seed: int, model_names: Set[str]) -> List[str]:
    X, y, _ = make_matrix(rows)
    X_train, y_train = X[train_idx], y[train_idx]
    X_test, y_test = X[test_idx], y[test_idx]
    test_rows = [rows[int(i)] for i in test_idx]

    lines: List[str] = []
    lines.append(f"Split: {split_name}")
    lines.append("-" * 80)
    lines.append(f"train episodes: {len(train_idx):,} positives: {int(y_train.sum()):,}")
    lines.append(f"test episodes:  {len(test_idx):,} positives: {int(y_test.sum()):,}")
    if len(np.unique(y_train)) < 2 or len(np.unique(y_test)) < 2:
        lines.append("Skipping split: train or test lacks both classes.")
        lines.append("")
        return lines

    score_sets: Dict[str, np.ndarray] = {
        "sria_score": np.array([safe_float(r.get("score"), 0.0) for r in test_rows], dtype=float),
        "sria_raw_score": np.array([safe_float(r.get("raw_score"), 0.0) for r in test_rows], dtype=float),
        "simple_feature_sum": np.array([safe_float(r.get("simple_feature_sum"), 0.0) for r in test_rows], dtype=float),
        "fanout_velocity_score": np.array([safe_float(r.get("fanout_velocity_score"), 0.0) for r in test_rows], dtype=float),
        "novelty_ratio": np.array([safe_float(r.get("novelty_ratio"), 0.0) for r in test_rows], dtype=float),
    }

    models = fit_requested_models(X_train, y_train, model_names, seed)
    for name, model in models.items():
        t0 = time.time()
        log(f"Scoring {name} on {len(test_rows):,} test rows...")
        score_sets[name] = proba_or_score(model, X_test)
        log(f"  scored {name} in {time.time() - t0:.1f}s")

    topks = [50, 100, 250, 500, 1000, 2500, 5000, 10000, 20000, 50000, 100000]
    topks = [k for k in topks if k <= len(test_rows)]
    if len(test_rows) not in topks:
        topks.append(len(test_rows))

    metrics_path = out_dir / f"metrics_{split_name}.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as f:
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
            for r in topk_metrics(test_rows, scores, ep_to_rt, topks):
                w.writerow({
                    "split": split_name,
                    "model": model_name,
                    "roc_auc": "" if roc is None else f"{roc:.6f}",
                    "average_precision": "" if ap is None else f"{ap:.6f}",
                    **r,
                })

    lines.append("Top-line model metrics:")
    selected_k = [100, 500, 1000, 5000, 10000]
    for model_name, scores in score_sets.items():
        roc, ap = safe_auc(y_test, scores)
        lines.append(f"  {model_name}: ROC_AUC={roc if roc is not None else 'NA'} AP={ap if ap is not None else 'NA'}")
        km = {r["top_k"]: r for r in topk_metrics(test_rows, scores, ep_to_rt, [k for k in selected_k if k <= len(test_rows)])}
        for k in selected_k:
            if k in km:
                r = km[k]
                lines.append(
                    f"    top{k}: pos_eps={r['positive_episodes_hit']} "
                    f"ep_prec={r['episode_precision_at_k']:.4f} "
                    f"rt_events={r['redteam_events_hit']} "
                    f"rt_recall={r['redteam_recall_at_k']:.4f}"
                )
    lines.append(f"Detailed metrics CSV: {metrics_path}")
    lines.append("")

    for name, model in models.items():
        imp = feature_importance_lines(name, model)
        if imp:
            lines.extend(imp)
            lines.append("")
    return lines


def write_dataset_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    fields = ["episode_id", "source_set", "label", "redteam_count", "exact_start_count", "start_time", "end_time", "candidate_gate"] + ALL_FEATURES
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def main() -> int:
    ap = argparse.ArgumentParser(description="SRIA RT v0.4.0 FAST baseline evaluation harness")
    ap.add_argument("--base-dir", default=".")
    ap.add_argument("--branch", default="v033", choices=["v033", "v036"])
    ap.add_argument("--include-suppressed", action="store_true")
    ap.add_argument("--negative-sample", type=int, default=50_000)
    ap.add_argument("--sample-mode", choices=["first", "reservoir"], default="first")
    ap.add_argument("--models", default="sgd,tree", help="Comma list: sgd,tree,rf,hgb,none")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--write-dataset", action="store_true")
    args = ap.parse_args()

    base = Path(args.base_dir)
    paths = default_branch_paths(base, args.branch)
    out_dir = Path(args.out_dir) if args.out_dir else base / f"v040_fast_{args.branch}_{args.negative_sample // 1000}k"
    out_dir.mkdir(parents=True, exist_ok=True)

    for p, desc in [(paths.accepted, "accepted episodes"), (paths.matches, "redteam matches")]:
        if not p.exists():
            log(f"ERROR: Missing {desc}: {p}")
            return 2

    log(f"Using accepted file: {paths.accepted}")
    log(f"Using matches file:  {paths.matches}")
    positive_ep_ids, ep_to_rt, ep_exact_counts, _ = load_match_maps(paths.matches)
    near_ids = load_suppressed_near_ids(paths.suppressed_near)

    rows: List[Dict[str, Any]] = []
    accepted_count = 0
    log("Loading accepted episodes...")
    for ep in iter_jsonl(paths.accepted):
        row = episode_to_row(ep, "accepted", positive_ep_ids, ep_to_rt, ep_exact_counts)
        if row is not None:
            rows.append(row)
            accepted_count += 1
        if accepted_count and accepted_count % 100000 == 0:
            log(f"  loaded {accepted_count:,} accepted episodes...")
    log(f"Loaded accepted rows: {accepted_count:,}")

    suppressed_count = 0
    if args.include_suppressed:
        if paths.suppressed and paths.suppressed.exists():
            log(f"Sampling up to {args.negative_sample:,} suppressed negatives from {paths.suppressed} using mode={args.sample_mode}...")
            skip_ids = near_ids | positive_ep_ids
            if args.sample_mode == "reservoir":
                negs = sample_suppressed_reservoir(paths.suppressed, args.negative_sample, args.seed, skip_ids)
            else:
                negs = sample_suppressed_first(paths.suppressed, args.negative_sample, skip_ids)
            for ep in negs:
                row = episode_to_row(ep, "suppressed_sample", positive_ep_ids, ep_to_rt, ep_exact_counts)
                if row is not None:
                    rows.append(row)
                    suppressed_count += 1
            log(f"Loaded suppressed negative rows: {suppressed_count:,}")
        else:
            log(f"WARNING: suppressed file missing: {paths.suppressed}")

    # Deduplicate by episode_id. Prefer accepted rows if duplicates exist.
    dedup: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        ep_id = int(row["episode_id"])
        if ep_id not in dedup or row["source_set"] == "accepted":
            dedup[ep_id] = row
    rows = list(dedup.values())

    positives = sum(1 for r in rows if int(r["label"]) == 1)
    represented_rt: Set[int] = set()
    for r in rows:
        if int(r["label"]) == 1:
            represented_rt.update(ep_to_rt.get(int(r["episode_id"]), set()))

    log(f"Final rows: {len(rows):,}; positive episodes: {positives:,}; represented redteam events: {len(represented_rt):,}")
    if positives < 2:
        log("ERROR: Too few positive episodes for baseline evaluation.")
        return 2

    if args.write_dataset:
        dataset_csv = out_dir / f"episode_dataset_{paths.name}.csv"
        log(f"Writing dataset CSV: {dataset_csv}")
        write_dataset_csv(dataset_csv, rows)
    else:
        dataset_csv = None

    model_names = {m.strip().lower() for m in args.models.split(",") if m.strip()}
    if "none" in model_names:
        model_names = set()

    X, y, times = make_matrix(rows)
    lines: List[str] = []
    lines.append("SRIA RT v0.4.0 FAST Baseline Evaluation")
    lines.append("=" * 80)
    lines.append(f"branch: {paths.name}")
    lines.append(f"accepted episodes file: {paths.accepted}")
    lines.append(f"matches file: {paths.matches}")
    lines.append(f"suppressed file: {paths.suppressed}")
    lines.append(f"sample_mode: {args.sample_mode}")
    lines.append(f"models: {','.join(sorted(model_names)) if model_names else 'none'}")
    lines.append(f"accepted rows loaded: {accepted_count:,}")
    lines.append(f"suppressed negative rows sampled: {suppressed_count:,}")
    lines.append(f"final dataset rows: {len(rows):,}")
    lines.append(f"positive episode labels: {positives:,}")
    lines.append(f"unique redteam events represented by positive episodes: {len(represented_rt):,}")
    if dataset_csv:
        lines.append(f"dataset CSV: {dataset_csv}")
    lines.append("")
    lines.append("Limitations:")
    lines.append("  - This is an episode-level baseline over existing sparse-window outputs.")
    lines.append("  - Labels are post-hoc red-team-overlap labels; they are not used by SRIA scoring.")
    lines.append("  - sample_mode=first is a fast smoke test, not a publication-grade negative sample.")
    lines.append("")

    for split_name in ["time", "stratified_random"]:
        log(f"Evaluating split: {split_name}")
        try:
            tr, te = split_indices(y, times, split_name, args.seed)
            lines.extend(evaluate_split(split_name, rows, tr, te, ep_to_rt, out_dir, args.seed, model_names))
        except Exception as exc:
            lines.append(f"Split {split_name} failed: {exc}")
            lines.append("")
            log(f"WARNING: split {split_name} failed: {exc}")

    summary_path = out_dir / f"baseline_summary_{paths.name}.txt"
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines), flush=True)
    log(f"\nWrote summary: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
