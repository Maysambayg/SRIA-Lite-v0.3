#!/usr/bin/env python3
"""
SRIA RT v0.4.2 - Leakage-Stripped Learned Scorer Export

Purpose
-------
Train deployable/re-rankable learned scorers from the clean SRIA RT episode
features established in v0.4.1, then export:

  1. model artifacts (.joblib)
  2. ranked episode queues (.csv + .jsonl)
  3. top-K comparison against the legacy SRIA score
  4. feature importance / coefficient summaries

Important methodological boundary
---------------------------------
This script DOES NOT rescan auth.txt.
It consumes existing episode JSONL files produced by v033/v036.

The learned models use leakage-stripped inputs only:
  - DROPS score, raw_score, entropy_penalty, max_risk
  - DROPS candidate_gate / gate__* outputs
  - KEEPS upstream engineered episode properties and primitive signal indicators

This is a re-ranking/export tool, not a final deployment precision estimator.
If you train and score on the same branch, the ranked queue is useful for
inspection, but not an honest held-out performance claim.

Recommended first run:
  py sria_rt_v042_learned_scorer_export.py --base-dir . --train-branch v033 --score-branch v033 --include-suppressed --negative-sample 100000 --sample-mode reservoir --models sgd_cw_none,tree_depth6_cw_none --out-dir v042_train_v033_score_v033

Cross-branch sanity run:
  py sria_rt_v042_learned_scorer_export.py --base-dir . --train-branch v033 --score-branch v036 --include-suppressed --negative-sample 100000 --sample-mode reservoir --models sgd_cw_none,tree_depth6_cw_none --out-dir v042_train_v033_score_v036
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
    import joblib
    import numpy as np
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import SGDClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier
except Exception as exc:
    print("ERROR: This script requires numpy, scikit-learn, and joblib.")
    print("Install with: py -m pip install numpy scikit-learn joblib")
    print(f"Original import error: {exc}")
    sys.exit(1)


NUMERIC_FEATURES_STRIPPED = [
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
]

# Primitive signal indicators. These are upstream episode signals, not gate labels.
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

STRIPPED_FEATURES = NUMERIC_FEATURES_STRIPPED + [f"sig__{s}" for s in SIGNAL_FEATURES]

RANKED_FIELDS = [
    "rank",
    "model_score",
    "legacy_sria_score",
    "legacy_raw_score",
    "episode_id",
    "label",
    "redteam_count",
    "exact_start_count",
    "redteam_indices",
    "source_set",
    "branch",
    "source",
    "user",
    "start_time",
    "end_time",
    "duration",
    "events_count",
    "destination_count",
    "candidate_gate",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "signals",
]


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


class UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[int, int] = {}

    def find(self, x: int) -> int:
        if x not in self.parent:
            self.parent[x] = x
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def load_match_maps(path: Path) -> Tuple[Set[int], Dict[int, Set[int]], Dict[int, int], Dict[int, str]]:
    positive_ep_ids: Set[int] = set()
    ep_to_rt: Dict[int, Set[int]] = defaultdict(set)
    ep_exact_counts: Dict[int, int] = defaultdict(int)
    rt_to_eps: Dict[int, Set[int]] = defaultdict(set)
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
            rt_idx = safe_int(idx, -1)
            if rt_idx >= 0:
                ep_to_rt[ep_id].add(rt_idx)
                rt_to_eps[rt_idx].add(ep_id)
        if bool(obj.get("exact_start_match")):
            ep_exact_counts[ep_id] += 1

    uf = UnionFind()
    for ep_id in positive_ep_ids:
        uf.find(ep_id)
    for eps in rt_to_eps.values():
        eps_list = sorted(eps)
        if len(eps_list) > 1:
            first = eps_list[0]
            for ep_id in eps_list[1:]:
                uf.union(first, ep_id)

    ep_group: Dict[int, str] = {}
    comp_to_rts: Dict[int, Set[int]] = defaultdict(set)
    for ep_id, rts in ep_to_rt.items():
        root = uf.find(ep_id)
        comp_to_rts[root].update(rts)
    for ep_id in positive_ep_ids:
        root = uf.find(ep_id)
        rts = sorted(comp_to_rts.get(root, set()))
        ep_group[ep_id] = "rtgrp:" + "+".join(str(x) for x in rts) if rts else f"rtgrp_ep:{ep_id}"

    log(
        f"Loaded {count:,} match records from {path}; "
        f"positive episodes={len(positive_ep_ids):,}; "
        f"redteam groups={len(set(ep_group.values())):,}"
    )
    return positive_ep_ids, ep_to_rt, ep_exact_counts, ep_group


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
    branch: str,
    source_set: str,
    positive_ep_ids: Set[int],
    ep_to_rt: Dict[int, Set[int]],
    ep_exact_counts: Dict[int, int],
    ep_group: Dict[int, str],
) -> Optional[Dict[str, Any]]:
    ep_id = safe_int(ep.get("id"), -1)
    if ep_id < 0:
        return None
    signals_list = ep.get("signals", []) or []
    signals = set(signals_list)
    label = 1 if ep_id in positive_ep_ids else 0
    row: Dict[str, Any] = {
        "episode_id": ep_id,
        "branch": branch,
        "source_set": source_set,
        "label": label,
        "redteam_count": len(ep_to_rt.get(ep_id, set())),
        "exact_start_count": ep_exact_counts.get(ep_id, 0),
        "redteam_group": ep_group.get(ep_id, f"neg:{ep_id}"),
        "redteam_indices": ";".join(str(x) for x in sorted(ep_to_rt.get(ep_id, set()))),
        "source": str(ep.get("source", "")),
        "user": str(ep.get("user", "")),
        "start_time": safe_int(ep.get("start_time"), 0),
        "end_time": safe_int(ep.get("end_time"), 0),
        "candidate_gate": str(ep.get("candidate_gate", "") or ""),
        "signals": ";".join(str(s) for s in sorted(signals)),
        "legacy_sria_score": safe_float(ep.get("score"), 0.0),
        "legacy_raw_score": safe_float(ep.get("raw_score"), 0.0),
    }
    for name in NUMERIC_FEATURES_STRIPPED:
        row[name] = safe_float(ep.get(name), 0.0)
    for sig in SIGNAL_FEATURES:
        row[f"sig__{sig}"] = 1.0 if sig in signals else 0.0
    return row


def load_rows_for_branch(
    paths: BranchPaths,
    include_suppressed: bool,
    negative_sample: int,
    sample_mode: str,
    seed: int,
) -> Tuple[List[Dict[str, Any]], Dict[int, Set[int]]]:
    if not paths.accepted.exists():
        raise FileNotFoundError(f"Missing accepted episodes file: {paths.accepted}")
    if not paths.matches.exists():
        raise FileNotFoundError(f"Missing redteam matches file: {paths.matches}")

    positive_ep_ids, ep_to_rt, ep_exact_counts, ep_group = load_match_maps(paths.matches)
    near_ids = load_suppressed_near_ids(paths.suppressed_near)

    rows: List[Dict[str, Any]] = []
    accepted_count = 0
    log(f"Loading accepted episodes for {paths.name} from {paths.accepted}...")
    for ep in iter_jsonl(paths.accepted):
        row = episode_to_row(ep, paths.name, "accepted", positive_ep_ids, ep_to_rt, ep_exact_counts, ep_group)
        if row is not None:
            rows.append(row)
            accepted_count += 1
        if accepted_count and accepted_count % 100000 == 0:
            log(f"  loaded {accepted_count:,} accepted episodes...")
    log(f"Loaded accepted rows for {paths.name}: {accepted_count:,}")

    suppressed_count = 0
    if include_suppressed:
        if paths.suppressed and paths.suppressed.exists():
            skip_ids = near_ids | positive_ep_ids
            log(
                f"Sampling up to {negative_sample:,} suppressed negatives from {paths.suppressed} "
                f"using mode={sample_mode}..."
            )
            if sample_mode == "reservoir":
                negs = sample_suppressed_reservoir(paths.suppressed, negative_sample, seed, skip_ids)
            else:
                negs = sample_suppressed_first(paths.suppressed, negative_sample, skip_ids)
            for ep in negs:
                row = episode_to_row(ep, paths.name, "suppressed_sample", positive_ep_ids, ep_to_rt, ep_exact_counts, ep_group)
                if row is not None:
                    rows.append(row)
                    suppressed_count += 1
            log(f"Loaded suppressed negative rows for {paths.name}: {suppressed_count:,}")
        else:
            log(f"WARNING: suppressed file missing for {paths.name}: {paths.suppressed}")

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
    log(
        f"Final rows for {paths.name}: {len(rows):,}; "
        f"positive episodes: {positives:,}; represented redteam events: {len(represented_rt):,}"
    )
    return rows, ep_to_rt


def make_matrix(rows: Sequence[Dict[str, Any]], features: Sequence[str]) -> Tuple[np.ndarray, np.ndarray]:
    X = np.array([[safe_float(r.get(c), 0.0) for c in features] for r in rows], dtype=np.float32)
    y = np.array([int(r["label"]) for r in rows], dtype=np.int8)
    return X, y


def build_model(model_spec: str, seed: int) -> Any:
    spec = model_spec.lower().strip()
    if spec == "sgd_cw_none":
        return Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("clf", SGDClassifier(
                loss="log_loss",
                penalty="l2",
                alpha=1e-4,
                max_iter=1000,
                tol=1e-3,
                class_weight=None,
                random_state=seed,
                n_jobs=-1,
            )),
        ])
    if spec == "sgd_cw_balanced":
        return Pipeline([
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
    if spec == "tree_depth6_cw_none":
        return DecisionTreeClassifier(max_depth=6, min_samples_leaf=10, class_weight=None, random_state=seed)
    if spec == "tree_depth6_cw_balanced":
        return DecisionTreeClassifier(max_depth=6, min_samples_leaf=10, class_weight="balanced", random_state=seed)
    raise ValueError(
        f"Unknown model spec: {model_spec}. Supported: "
        "sgd_cw_none, sgd_cw_balanced, tree_depth6_cw_none, tree_depth6_cw_balanced"
    )


def proba_or_score(model: Any, X: np.ndarray) -> np.ndarray:
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    if hasattr(model, "decision_function"):
        z = model.decision_function(X)
        z = np.clip(z, -40, 40)
        return 1.0 / (1.0 + np.exp(-z))
    return model.predict(X).astype(float)


def feature_importance_lines(model_name: str, model: Any, feature_names: Sequence[str], limit: int = 25) -> List[str]:
    lines: List[str] = []
    try:
        if model_name.startswith("sgd") and hasattr(model, "named_steps"):
            coef = model.named_steps["clf"].coef_[0]
            pairs = sorted(zip(feature_names, coef), key=lambda x: abs(x[1]), reverse=True)[:limit]
            lines.append(f"Top coefficients for {model_name}:")
            for name, val in pairs:
                lines.append(f"  {name}: {val:.6f}")
        elif hasattr(model, "feature_importances_"):
            pairs = sorted(zip(feature_names, model.feature_importances_), key=lambda x: x[1], reverse=True)[:limit]
            lines.append(f"Top importances for {model_name}:")
            for name, val in pairs:
                lines.append(f"  {name}: {val:.6f}")
    except Exception as exc:
        lines.append(f"Could not extract feature importance for {model_name}: {exc}")
    return lines


def topk_eval(rows: Sequence[Dict[str, Any]], scores: np.ndarray, ep_to_rt: Dict[int, Set[int]], topks: Sequence[int]) -> List[Dict[str, Any]]:
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
            "total_positive_episodes": total_pos_eps,
            "total_redteam_events": len(total_rt),
        })
    return out


def write_ranked_outputs(
    out_dir: Path,
    model_name: str,
    score_branch: str,
    rows: Sequence[Dict[str, Any]],
    scores: np.ndarray,
    max_jsonl: int,
) -> Tuple[Path, Path]:
    ranked_idx = np.argsort(-scores, kind="mergesort")
    csv_path = out_dir / f"ranked_{score_branch}_{model_name}.csv"
    jsonl_path = out_dir / f"ranked_{score_branch}_{model_name}_top{max_jsonl}.jsonl"

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=RANKED_FIELDS, extrasaction="ignore")
        w.writeheader()
        for rank, idx in enumerate(ranked_idx, 1):
            r = dict(rows[int(idx)])
            out = {field: r.get(field, "") for field in RANKED_FIELDS}
            out["rank"] = rank
            out["model_score"] = f"{float(scores[int(idx)]):.10f}"
            out["legacy_sria_score"] = f"{safe_float(r.get('legacy_sria_score'), 0.0):.10f}"
            out["legacy_raw_score"] = f"{safe_float(r.get('legacy_raw_score'), 0.0):.10f}"
            w.writerow(out)

    with jsonl_path.open("w", encoding="utf-8") as f:
        for rank, idx in enumerate(ranked_idx[:max_jsonl], 1):
            r = dict(rows[int(idx)])
            r["rank"] = rank
            r["model_score"] = float(scores[int(idx)])
            f.write(json.dumps(r, sort_keys=True) + "\n")

    return csv_path, jsonl_path


def write_topk_csv(path: Path, model_to_eval: Dict[str, List[Dict[str, Any]]]) -> None:
    fields = [
        "model", "top_k", "positive_episodes_hit", "episode_precision_at_k",
        "episode_recall_at_k", "redteam_events_hit", "redteam_recall_at_k",
        "total_positive_episodes", "total_redteam_events",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for model, rows in model_to_eval.items():
            for r in rows:
                w.writerow({"model": model, **r})


def main() -> int:
    ap = argparse.ArgumentParser(description="SRIA RT v0.4.2 leakage-stripped learned scorer export")
    ap.add_argument("--base-dir", default=".")
    ap.add_argument("--train-branch", choices=["v033", "v036"], default="v033")
    ap.add_argument("--score-branch", choices=["v033", "v036"], default="v033")
    ap.add_argument("--include-suppressed", action="store_true", help="Include sampled suppressed negatives in training")
    ap.add_argument("--negative-sample", type=int, default=100_000)
    ap.add_argument("--sample-mode", choices=["first", "reservoir"], default="reservoir")
    ap.add_argument("--models", default="sgd_cw_none,tree_depth6_cw_none")
    ap.add_argument("--score-set", choices=["accepted", "all_loaded"], default="accepted", help="Rows to rank in score branch")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--top-jsonl", type=int, default=5000)
    ap.add_argument("--out-dir", default="")
    args = ap.parse_args()

    base = Path(args.base_dir)
    train_paths = default_branch_paths(base, args.train_branch)
    score_paths = default_branch_paths(base, args.score_branch)
    out_dir = Path(args.out_dir) if args.out_dir else base / f"v042_train_{args.train_branch}_score_{args.score_branch}"
    out_dir.mkdir(parents=True, exist_ok=True)

    log("=" * 80)
    log("SRIA RT v0.4.2 - Leakage-Stripped Learned Scorer Export")
    log("=" * 80)
    log(f"Train branch: {args.train_branch}")
    log(f"Score branch: {args.score_branch}")
    log(f"Models: {args.models}")
    log(f"Output dir: {out_dir}")
    log("NOTE: This exports a scorer/ranked queue. It is not a held-out deployment precision estimate.")
    log("=" * 80)

    train_rows, train_ep_to_rt = load_rows_for_branch(
        train_paths,
        include_suppressed=args.include_suppressed,
        negative_sample=args.negative_sample,
        sample_mode=args.sample_mode,
        seed=args.seed,
    )
    X_train, y_train = make_matrix(train_rows, STRIPPED_FEATURES)
    if len(np.unique(y_train)) < 2:
        log("ERROR: training data lacks both positive and negative labels.")
        return 2

    # Load scoring branch. If same as train, reuse loaded rows. Otherwise load target rows too.
    if args.score_branch == args.train_branch:
        score_all_rows = train_rows
        score_ep_to_rt = train_ep_to_rt
    else:
        score_all_rows, score_ep_to_rt = load_rows_for_branch(
            score_paths,
            include_suppressed=args.include_suppressed,
            negative_sample=args.negative_sample,
            sample_mode=args.sample_mode,
            seed=args.seed,
        )

    if args.score_set == "accepted":
        score_rows = [r for r in score_all_rows if r.get("source_set") == "accepted"]
    else:
        score_rows = score_all_rows

    X_score, y_score = make_matrix(score_rows, STRIPPED_FEATURES)
    log(f"Rows to score: {len(score_rows):,}; positives in scored rows: {int(y_score.sum()):,}")

    model_specs = [m.strip().lower() for m in args.models.split(",") if m.strip()]
    if not model_specs:
        log("ERROR: no models requested.")
        return 2

    report: List[str] = []
    report.append("SRIA RT v0.4.2 Learned Scorer Export")
    report.append("=" * 80)
    report.append(f"train_branch: {args.train_branch}")
    report.append(f"score_branch: {args.score_branch}")
    report.append(f"score_set: {args.score_set}")
    report.append(f"include_suppressed_training: {args.include_suppressed}")
    report.append(f"negative_sample: {args.negative_sample:,}")
    report.append(f"sample_mode: {args.sample_mode}")
    report.append(f"train_rows: {len(train_rows):,}")
    report.append(f"train_positive_episodes: {int(y_train.sum()):,}")
    report.append(f"scored_rows: {len(score_rows):,}")
    report.append(f"scored_positive_episodes: {int(y_score.sum()):,}")
    report.append("feature_set: STRIPPED only; drops score/raw_score/entropy_penalty/max_risk/gate outputs")
    report.append("methodological_note: training and scoring on the same branch is for queue generation, not held-out validation.")
    report.append("")

    topks = [50, 100, 250, 500, 1000, 2500, 5000, 10000, 20000, 50000]
    topks = [k for k in topks if k <= len(score_rows)]
    if len(score_rows) not in topks:
        topks.append(len(score_rows))

    topk_results: Dict[str, List[Dict[str, Any]]] = {}

    # Legacy baseline on the same score rows.
    legacy_scores = np.array([safe_float(r.get("legacy_sria_score"), 0.0) for r in score_rows], dtype=float)
    topk_results["legacy_sria_score"] = topk_eval(score_rows, legacy_scores, score_ep_to_rt, topks)

    for model_spec in model_specs:
        model = build_model(model_spec, args.seed)
        log(f"Training {model_spec} on {len(train_rows):,} rows...")
        t0 = time.time()
        model.fit(X_train, y_train)
        log(f"  done {model_spec} in {time.time() - t0:.1f}s")

        scores = proba_or_score(model, X_score)
        topk_results[model_spec] = topk_eval(score_rows, scores, score_ep_to_rt, topks)

        artifact = {
            "sria_version": "v0.4.2",
            "model_spec": model_spec,
            "train_branch": args.train_branch,
            "score_branch_used_for_export": args.score_branch,
            "feature_names": STRIPPED_FEATURES,
            "dropped_features_note": "score/raw_score/entropy_penalty/max_risk/gate outputs are intentionally excluded",
            "trained_model": model,
            "training_rows": len(train_rows),
            "training_positive_episodes": int(y_train.sum()),
            "created_unix_time": time.time(),
        }
        artifact_path = out_dir / f"model_{args.train_branch}_{model_spec}.joblib"
        joblib.dump(artifact, artifact_path)

        csv_path, jsonl_path = write_ranked_outputs(out_dir, model_spec, args.score_branch, score_rows, scores, args.top_jsonl)

        report.append(f"Model: {model_spec}")
        report.append("-" * 80)
        report.append(f"artifact: {artifact_path}")
        report.append(f"ranked_csv: {csv_path}")
        report.append(f"ranked_jsonl_top{args.top_jsonl}: {jsonl_path}")
        report.extend(feature_importance_lines(model_spec, model, STRIPPED_FEATURES))
        report.append("Top-K on scored rows:")
        for r in topk_results[model_spec]:
            if r["top_k"] in {100, 500, 1000, 5000, 10000, len(score_rows)}:
                report.append(
                    f"  top{r['top_k']}: pos_eps={r['positive_episodes_hit']} "
                    f"ep_prec={r['episode_precision_at_k']:.4f} "
                    f"rt_events={r['redteam_events_hit']} "
                    f"rt_recall={r['redteam_recall_at_k']:.4f}"
                )
        report.append("")

    topk_csv = out_dir / f"topk_comparison_train_{args.train_branch}_score_{args.score_branch}.csv"
    write_topk_csv(topk_csv, topk_results)
    report.append(f"Top-K comparison CSV: {topk_csv}")
    report.append("")
    report.append("Legacy SRIA score top-K on scored rows:")
    for r in topk_results["legacy_sria_score"]:
        if r["top_k"] in {100, 500, 1000, 5000, 10000, len(score_rows)}:
            report.append(
                f"  top{r['top_k']}: pos_eps={r['positive_episodes_hit']} "
                f"ep_prec={r['episode_precision_at_k']:.4f} "
                f"rt_events={r['redteam_events_hit']} "
                f"rt_recall={r['redteam_recall_at_k']:.4f}"
            )

    report_path = out_dir / f"v042_export_report_train_{args.train_branch}_score_{args.score_branch}.txt"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print("\n".join(report), flush=True)
    log(f"\nWrote report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
