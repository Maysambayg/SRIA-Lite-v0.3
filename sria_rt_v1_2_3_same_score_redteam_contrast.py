#!/usr/bin/env python3
r"""
sria_rt_v1_2_3_same_score_redteam_contrast.py

SRIA RT v1.2.3 - Same-Score Redteam Contrast

Purpose:
- Apply the same learned SRIA RT v0.6.4 ranker to known redteam-associated v036 accepted episodes.
- Compare learned-score distribution of:
    1. Tier B background ranked output
    2. Background R2 tail
    3. Redteam-associated v036 accepted episodes scored under the same learned model

Boundary:
- No retraining.
- No feature changes.
- No gate changes.
- No auth.txt scan.
- No new detection logic.
- Redteam labels are used only to select the known redteam-associated v036 subset for contrast measurement.
- The learned ranker artifact is applied unchanged.

Expected inputs:
  v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv
  v036_batches\episodes_v036_accepted.jsonl
  v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl
  v044_train_v033_score_v036\model_v033_rf_depth10_cw_none.joblib

Recommended CMD:

  py sria_rt_v1_2_3_same_score_redteam_contrast.py --background-ranked v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv --accepted-jsonl v036_batches\episodes_v036_accepted.jsonl --matches-jsonl v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl --model-artifact v044_train_v033_score_v036\model_v033_rf_depth10_cw_none.joblib --out-dir v1_2_3_same_score_redteam_contrast_results
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import numpy as np
import pandas as pd

try:
    import joblib
except Exception as e:
    print("ERROR: This script requires joblib.")
    print("Install with:")
    print("  py -m pip install joblib")
    print(f"Original import error: {e}")
    raise SystemExit(2)

try:
    from scipy.stats import wasserstein_distance
except Exception:
    wasserstein_distance = None


VERSION = "v1.2.3"

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

ID_COLUMNS = [
    "episode_id",
    "accepted_episode_id",
    "matched_episode_id",
    "source_episode_id",
    "episode_index",
    "idx",
    "id",
]

KEY_COLUMNS = [
    "background_episode_key",
    "episode_key",
    "accepted_episode_key",
    "matched_episode_key",
]

BACKGROUND_SCORE_COLUMNS = [
    "sria_rt_model_score",
    "model_score",
    "score",
]

BACKGROUND_RANK_COLUMNS = [
    "rank_global",
    "rank",
]

OUTPUT_FIELDS = [
    "rank",
    "same_score_rank_within_redteam",
    "same_score_redteam_score",
    "same_score_background_percentile",
    "same_score_background_rank_equivalent",
    "same_score_severity",
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
    "signals",
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


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"JSONL not found: {path}")
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                raise ValueError(f"Failed parsing {path} line {line_no}: {e}") from e
            if isinstance(obj, dict):
                yield obj


def flatten_dict(d: Dict[str, Any], prefix: str = "", max_depth: int = 2) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    def walk(obj: Any, p: str, depth: int) -> None:
        if isinstance(obj, dict) and depth < max_depth:
            for k, v in obj.items():
                key = f"{p}.{k}" if p else str(k)
                walk(v, key, depth + 1)
        else:
            out[p] = obj

    walk(d, prefix, 0)
    return out


def jsonl_to_df(path: Path) -> pd.DataFrame:
    rows = [flatten_dict(x) for x in load_jsonl(path)]
    return pd.DataFrame(rows)


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


def collect_identifier_values(df: pd.DataFrame, candidates: Sequence[str]) -> Set[str]:
    values: Set[str] = set()
    for col in df.columns:
        last = col.split(".")[-1]
        if col in candidates or last in candidates:
            for x in df[col].dropna().tolist():
                if isinstance(x, list):
                    for y in x:
                        values.add(str(y))
                else:
                    values.add(str(x))
    return values


def positive_like_value(x: Any) -> bool:
    if x is None:
        return False
    if isinstance(x, float) and math.isnan(x):
        return False
    if isinstance(x, bool):
        return x
    if isinstance(x, (int, float)):
        return float(x) > 0
    if isinstance(x, list):
        return len(x) > 0
    if isinstance(x, dict):
        return len(x) > 0

    text = str(x).strip().lower()
    if not text:
        return False
    if text in {"true", "yes", "y", "1", "positive", "matched", "redteam"}:
        return True
    if text in {"false", "no", "n", "0", "none", "nan", "null", "[]", "{}"}:
        return False
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        return True
    return False


def infer_redteam_mask(accepted_df: pd.DataFrame, matches_df: pd.DataFrame) -> Tuple[pd.Series, Dict[str, Any]]:
    diagnostics: Dict[str, Any] = {
        "method": None,
        "matched_count": 0,
        "notes": [],
    }

    direct_cols = [
        c for c in accepted_df.columns
        if any(tok in c.lower() for tok in [
            "redteam",
            "matched_red",
            "represented_red",
            "is_positive",
            "positive",
            "label",
            "match_indices",
        ])
    ]

    masks: List[pd.Series] = []
    used_cols: List[str] = []
    for c in direct_cols:
        m = accepted_df[c].apply(positive_like_value)
        if int(m.sum()) > 0:
            masks.append(m)
            used_cols.append(c)

    if masks:
        mask = masks[0].copy()
        for m in masks[1:]:
            mask = mask | m
        diagnostics["method"] = "direct_positive_columns_in_accepted"
        diagnostics["used_columns"] = used_cols
        diagnostics["matched_count"] = int(mask.sum())
        return mask, diagnostics

    match_id_values = collect_identifier_values(matches_df, ID_COLUMNS)
    for col in accepted_df.columns:
        last = col.split(".")[-1]
        if col in ID_COLUMNS or last in ID_COLUMNS:
            m = accepted_df[col].astype(str).isin(match_id_values)
            if int(m.sum()) > 0:
                diagnostics["method"] = "episode_id_match"
                diagnostics["accepted_id_column"] = col
                diagnostics["match_id_count"] = len(match_id_values)
                diagnostics["matched_count"] = int(m.sum())
                return m, diagnostics

    match_key_values = collect_identifier_values(matches_df, KEY_COLUMNS)
    for col in accepted_df.columns:
        last = col.split(".")[-1]
        if col in KEY_COLUMNS or last in KEY_COLUMNS:
            m = accepted_df[col].astype(str).isin(match_key_values)
            if int(m.sum()) > 0:
                diagnostics["method"] = "episode_key_match"
                diagnostics["accepted_key_column"] = col
                diagnostics["match_key_count"] = len(match_key_values)
                diagnostics["matched_count"] = int(m.sum())
                return m, diagnostics

    diagnostics["method"] = "failed_to_infer_redteam_mask"
    diagnostics["notes"].append("No usable direct redteam columns or shared episode IDs/keys were found.")
    return pd.Series([False] * len(accepted_df), index=accepted_df.index), diagnostics


def unpack_model_artifact(path: Path) -> Tuple[Any, List[str], Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Model artifact not found: {path}")

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
        raise ValueError("Model artifact does not contain feature_names.")

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


def row_from_episode(obj: Dict[str, Any], window_id: str, signal_names: Sequence[str]) -> Dict[str, Any]:
    ep = obj.get("episode", obj)
    if not isinstance(ep, dict):
        ep = obj

    ep_id = str(ep.get("id") or ep.get("episode_id") or obj.get("episode_id") or obj.get("id") or "")
    signals = normalize_signals(ep.get("signals") or obj.get("signals"))
    sigset = set(signals)

    start_time = safe_int(ep.get("start_time") or obj.get("start_time"))
    end_time = safe_int(ep.get("end_time") or obj.get("end_time"))
    duration = safe_float(ep.get("duration") or obj.get("duration"), max(0, end_time - start_time))

    dest_count = safe_float(ep.get("destination_count") or obj.get("destination_count"), 0.0)
    if dest_count == 0.0:
        dests = ep.get("destinations") or ep.get("destinations_sample") or obj.get("destinations") or []
        if isinstance(dests, (list, set, tuple)):
            dest_count = float(len(dests))

    events_count = safe_float(ep.get("events_count") or obj.get("events_count"), 0.0)
    new_dest_count = safe_float(ep.get("new_destination_event_count") or obj.get("new_destination_event_count"), dest_count)
    first_time_event_count = safe_float(ep.get("first_time_event_count") or obj.get("first_time_event_count"), 0.0)
    first_time_signal_hits = safe_float(ep.get("first_time_signal_hits") or obj.get("first_time_signal_hits"), 0.0)
    if first_time_signal_hits == 0.0:
        first_time_signal_hits = float(sum(1 for s in signals if s.startswith("first_time")))

    novelty_ratio = safe_float(ep.get("novelty_ratio") or obj.get("novelty_ratio"), 0.0)
    if novelty_ratio == 0.0 and events_count > 0:
        novelty_ratio = min(1.0, new_dest_count / max(events_count, 1.0))

    row: Dict[str, Any] = {
        "window_id": window_id,
        "episode_id": ep_id,
        "start_time": start_time,
        "end_time": end_time,
        "duration": duration,
        "source": ep.get("source") or obj.get("source") or "",
        "user": ep.get("user") or obj.get("user") or "",
        "candidate_gate": ep.get("candidate_gate") or obj.get("candidate_gate") or "UNKNOWN",
        "legacy_sria_score": safe_float(ep.get("score") or obj.get("score")),
        "legacy_raw_score": safe_float(ep.get("raw_score") or obj.get("raw_score"), safe_float(ep.get("score") or obj.get("score"))),
        "entropy_penalty": safe_float(ep.get("entropy_penalty") or obj.get("entropy_penalty")),
        "max_risk": safe_float(ep.get("max_risk") or obj.get("max_risk")),
        "events_count": events_count,
        "destination_count": dest_count,
        "user_count": safe_float(ep.get("user_count") or obj.get("user_count"), 1.0 if (ep.get("user") or obj.get("user")) else 0.0),
        "new_destination_event_count": new_dest_count,
        "first_time_event_count": first_time_event_count,
        "first_time_signal_hits": first_time_signal_hits,
        "novelty_ratio": novelty_ratio,
        "compactness_score": safe_float(ep.get("compactness_score") or obj.get("compactness_score")),
        "fanout_velocity_score": safe_float(ep.get("fanout_velocity_score") or obj.get("fanout_velocity_score")),
        "peak_velocity_new_dests": safe_float(ep.get("peak_velocity_new_dests") or obj.get("peak_velocity_new_dests")),
        "signals": ";".join(sorted(sigset)),
    }

    for s in signal_names:
        row[f"sig__{s}"] = 1.0 if s in sigset else 0.0

    return row


def add_sig_columns_to_ranked_row(row: Dict[str, Any], signal_names: Sequence[str]) -> Dict[str, Any]:
    out = dict(row)
    sigset = set(normalize_signals(out.get("signals")))
    for s in signal_names:
        out[f"sig__{s}"] = 1.0 if s in sigset else safe_float(out.get(f"sig__{s}"))
    return out


def matrix_from_rows(rows: Sequence[Dict[str, Any]], feature_names: Sequence[str]) -> np.ndarray:
    X = np.zeros((len(rows), len(feature_names)), dtype=np.float32)
    for i, r in enumerate(rows):
        for j, n in enumerate(feature_names):
            X[i, j] = safe_float(r.get(n))
    return X


def load_background_ranked(path: Path, signal_names: Sequence[str]) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Background ranked CSV not found: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"Background ranked CSV is empty: {path}")

    score_col = None
    for c in BACKGROUND_SCORE_COLUMNS:
        if c in df.columns:
            score_col = c
            break
    if not score_col:
        raise ValueError(f"No background score column found. Available: {list(df.columns)}")

    rank_col = None
    for c in BACKGROUND_RANK_COLUMNS:
        if c in df.columns:
            rank_col = c
            break

    df = df.copy()
    df["same_score"] = pd.to_numeric(df[score_col], errors="coerce").fillna(0.0)

    if rank_col:
        df["same_score_rank"] = pd.to_numeric(df[rank_col], errors="coerce").fillna(0).astype(int)
        if df["same_score_rank"].max() <= 0:
            df = df.sort_values("same_score", ascending=False).reset_index(drop=True)
            df["same_score_rank"] = np.arange(1, len(df) + 1)
    else:
        df = df.sort_values("same_score", ascending=False).reset_index(drop=True)
        df["same_score_rank"] = np.arange(1, len(df) + 1)

    df = df.sort_values("same_score_rank", ascending=True).reset_index(drop=True)
    return df


def score_summary(scores: Sequence[float]) -> Dict[str, Any]:
    arr = np.asarray(list(scores), dtype=np.float64)
    if len(arr) == 0:
        return {"count": 0}
    return {
        "count": int(len(arr)),
        "min": float(np.min(arr)),
        "p50": float(np.percentile(arr, 50)),
        "p75": float(np.percentile(arr, 75)),
        "p90": float(np.percentile(arr, 90)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
    }


def wasserstein(a: Sequence[float], b: Sequence[float]) -> float:
    aa = np.asarray(list(a), dtype=np.float64)
    bb = np.asarray(list(b), dtype=np.float64)
    if len(aa) == 0 or len(bb) == 0:
        return 0.0
    if wasserstein_distance is not None:
        return float(wasserstein_distance(aa, bb))
    qs = np.linspace(0, 100, 101)
    return float(np.mean(np.abs(np.percentile(aa, qs) - np.percentile(bb, qs))))


def background_percentile(score: float, background_scores: np.ndarray) -> float:
    if len(background_scores) == 0:
        return 0.0
    return float(100.0 * np.mean(background_scores <= score))


def background_rank_equivalent(score: float, background_scores_desc: np.ndarray) -> int:
    # 1-based insertion rank in descending background scores.
    return int(np.searchsorted(-background_scores_desc, -score, side="left") + 1)


def feature_delta_table(background_rows: List[Dict[str, Any]], redteam_rows: List[Dict[str, Any]], feature_names: Sequence[str]) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for f in feature_names:
        bg = np.asarray([safe_float(r.get(f)) for r in background_rows], dtype=np.float64)
        rt = np.asarray([safe_float(r.get(f)) for r in redteam_rows], dtype=np.float64)
        pooled = np.std(np.concatenate([bg, rt])) if len(bg) and len(rt) else 0.0
        bg_mean = float(np.mean(bg)) if len(bg) else 0.0
        rt_mean = float(np.mean(rt)) if len(rt) else 0.0
        std_delta = 0.0 if pooled == 0.0 else (rt_mean - bg_mean) / pooled
        rows.append({
            "feature": f,
            "background_R2_mean": bg_mean,
            "redteam_same_score_mean": rt_mean,
            "delta_redteam_minus_background_R2": rt_mean - bg_mean,
            "standardized_delta": std_delta,
            "background_R2_std": float(np.std(bg)) if len(bg) else 0.0,
            "redteam_std": float(np.std(rt)) if len(rt) else 0.0,
        })
    out = pd.DataFrame(rows)
    out = out.sort_values("standardized_delta", key=lambda s: s.abs(), ascending=False)
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


def write_text_report(path: Path, report: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("SRIA RT v1.2.3 Same-Score Redteam Contrast Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Purpose:")
    lines.append("  Apply the same learned ranker to redteam-associated v036 accepted episodes and compare against Tier B background.")
    lines.append("")
    lines.append("Boundary:")
    for k, v in report["boundary"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Inputs:")
    for k, v in report["inputs"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Counts:")
    for k, v in report["counts"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Redteam association:")
    for k, v in report["redteam_association"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Same-score summaries:")
    for group in ["background_all", "background_R2", "redteam_associated_v036_same_score"]:
        lines.append(f"  {group}:")
        for k, v in report["score_summary"][group].items():
            lines.append(f"    {k}: {v}")
    lines.append("")
    lines.append("Score contrast:")
    for k, v in report["score_contrast"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Background threshold placement:")
    for k, v in report["background_threshold_placement"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Top feature deltas:")
    for r in report["top_feature_deltas"]:
        lines.append(
            f"  {r['feature']}: "
            f"bg_R2_mean={r['background_R2_mean']:.8g}, "
            f"rt_mean={r['redteam_same_score_mean']:.8g}, "
            f"std_delta={r['standardized_delta']:.8g}"
        )
    lines.append("")
    lines.append("Interpretation boundary:")
    lines.append("  Same-score comparison is valid for learned-ranker placement.")
    lines.append("  Redteam labels are used only to select the contrast subset.")
    lines.append("  This does not establish production precision or intrinsic manifolds.")
    lines.append("")
    lines.append("Outputs:")
    for k, v in report["outputs"].items():
        lines.append(f"  {k}: {v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v1.2.3 Same-Score Redteam Contrast")
    p.add_argument("--background-ranked", required=True, help="v064 aggregate_deployment_queue_all_ranked.csv")
    p.add_argument("--accepted-jsonl", required=True, help="v036 accepted episodes JSONL")
    p.add_argument("--matches-jsonl", required=True, help="v036 redteam matches JSONL")
    p.add_argument("--model-artifact", required=True, help="Existing learned ranker joblib with feature_names")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--background-r2-top", type=int, default=100, help="Background R2 top-N size")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    background_ranked_path = Path(args.background_ranked)
    accepted_jsonl_path = Path(args.accepted_jsonl)
    matches_jsonl_path = Path(args.matches_jsonl)
    model_artifact_path = Path(args.model_artifact)
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    print("=" * 80)
    print("SRIA RT v1.2.3 - Same-Score Redteam Contrast")
    print("=" * 80)
    print(f"Background ranked: {background_ranked_path}")
    print(f"Accepted JSONL:    {accepted_jsonl_path}")
    print(f"Matches JSONL:     {matches_jsonl_path}")
    print(f"Model artifact:    {model_artifact_path}")
    print(f"Output dir:        {out_dir}")
    print("=" * 80)

    model, feature_names, artifact_meta = unpack_model_artifact(model_artifact_path)
    signal_names = [n.replace("sig__", "") for n in feature_names if n.startswith("sig__")]
    if not signal_names:
        signal_names = list(DEFAULT_SIGNAL_NAMES)

    background_df = load_background_ranked(background_ranked_path, signal_names)
    background_scores = background_df["same_score"].to_numpy(dtype=np.float64)
    background_scores_desc = np.asarray(sorted(background_scores, reverse=True), dtype=np.float64)

    background_r2_df = background_df[background_df["same_score_rank"] <= args.background_r2_top].copy()
    background_r2_dicts_raw = background_r2_df.to_dict(orient="records")
    background_r2_rows = [add_sig_columns_to_ranked_row(r, signal_names) for r in background_r2_dicts_raw]

    accepted_df_flat = jsonl_to_df(accepted_jsonl_path)
    matches_df_flat = jsonl_to_df(matches_jsonl_path)
    redteam_mask, assoc_diag = infer_redteam_mask(accepted_df_flat, matches_df_flat)

    accepted_objects = list(load_jsonl(accepted_jsonl_path))
    if len(accepted_objects) != len(accepted_df_flat):
        raise ValueError("Accepted JSONL object count does not match flattened DataFrame count.")

    redteam_objects = [obj for obj, keep in zip(accepted_objects, redteam_mask.tolist()) if keep]
    if not redteam_objects:
        raise ValueError("No redteam-associated accepted episodes were inferred.")

    redteam_rows = [
        row_from_episode(obj, window_id="v036_redteam", signal_names=signal_names)
        for obj in redteam_objects
    ]

    X_rt = matrix_from_rows(redteam_rows, feature_names)
    rt_scores_np = model_scores(model, X_rt)
    rt_scores = [float(x) for x in rt_scores_np]

    for i, (row, score) in enumerate(zip(redteam_rows, rt_scores), start=1):
        row["same_score_redteam_score"] = float(score)
        row["same_score_severity"] = severity_from_score(float(score))
        row["same_score_background_percentile"] = background_percentile(float(score), background_scores)
        row["same_score_background_rank_equivalent"] = background_rank_equivalent(float(score), background_scores_desc)

    redteam_order = np.argsort(-np.asarray(rt_scores, dtype=np.float64))
    ranked_redteam_rows: List[Dict[str, Any]] = []
    for rank, idx in enumerate(redteam_order, start=1):
        r = dict(redteam_rows[int(idx)])
        r["rank"] = rank
        r["same_score_rank_within_redteam"] = rank
        ranked_redteam_rows.append(r)

    # Threshold placement against background aggregate ranking.
    def threshold_score_at(rank: int) -> float:
        if len(background_scores_desc) < rank:
            return float(background_scores_desc[-1])
        return float(background_scores_desc[rank - 1])

    thresholds = {
        "background_top100_min_score": threshold_score_at(100),
        "background_top500_min_score": threshold_score_at(500),
        "background_top1000_min_score": threshold_score_at(1000),
        "background_top5000_min_score": threshold_score_at(5000),
    }

    rt_arr = np.asarray(rt_scores, dtype=np.float64)
    placement = {
        **thresholds,
        "redteam_count_ge_background_top100_min": int(np.sum(rt_arr >= thresholds["background_top100_min_score"])),
        "redteam_count_ge_background_top500_min": int(np.sum(rt_arr >= thresholds["background_top500_min_score"])),
        "redteam_count_ge_background_top1000_min": int(np.sum(rt_arr >= thresholds["background_top1000_min_score"])),
        "redteam_count_ge_background_top5000_min": int(np.sum(rt_arr >= thresholds["background_top5000_min_score"])),
        "redteam_share_ge_background_top100_min": float(np.mean(rt_arr >= thresholds["background_top100_min_score"])),
        "redteam_share_ge_background_top500_min": float(np.mean(rt_arr >= thresholds["background_top500_min_score"])),
        "redteam_share_ge_background_top1000_min": float(np.mean(rt_arr >= thresholds["background_top1000_min_score"])),
        "redteam_share_ge_background_top5000_min": float(np.mean(rt_arr >= thresholds["background_top5000_min_score"])),
        "redteam_median_background_percentile": float(np.median([r["same_score_background_percentile"] for r in redteam_rows])),
        "redteam_min_background_percentile": float(np.min([r["same_score_background_percentile"] for r in redteam_rows])),
        "redteam_max_background_percentile": float(np.max([r["same_score_background_percentile"] for r in redteam_rows])),
    }

    bg_r2_scores = background_r2_df["same_score"].to_numpy(dtype=np.float64)

    feature_delta = feature_delta_table(background_r2_rows, redteam_rows, feature_names)
    feature_delta_path = out_dir / "same_score_background_R2_vs_redteam_feature_delta.csv"
    feature_delta.to_csv(feature_delta_path, index=False)

    redteam_scored_csv = out_dir / "redteam_same_score_ranked.csv"
    redteam_scored_jsonl = out_dir / "redteam_same_score_ranked.jsonl"
    write_csv(redteam_scored_csv, ranked_redteam_rows, OUTPUT_FIELDS)
    write_jsonl(redteam_scored_jsonl, ranked_redteam_rows)

    score_contrast_rows = [
        {
            "metric": "wasserstein_background_R2_vs_redteam_same_score",
            "value": wasserstein(bg_r2_scores, rt_scores),
        },
        {
            "metric": "wasserstein_background_all_vs_redteam_same_score",
            "value": wasserstein(background_scores, rt_scores),
        },
        {
            "metric": "redteam_mean_minus_background_R2_mean",
            "value": float(np.mean(rt_arr) - np.mean(bg_r2_scores)),
        },
        {
            "metric": "redteam_mean_minus_background_all_mean",
            "value": float(np.mean(rt_arr) - np.mean(background_scores)),
        },
    ]
    score_contrast_path = out_dir / "same_score_distribution_contrast.csv"
    write_csv(score_contrast_path, score_contrast_rows, ["metric", "value"])

    report: Dict[str, Any] = {
        "version": VERSION,
        "purpose": "same_score_redteam_contrast_against_background_R2",
        "inputs": {
            "background_ranked": str(background_ranked_path),
            "accepted_jsonl": str(accepted_jsonl_path),
            "matches_jsonl": str(matches_jsonl_path),
            "model_artifact": str(model_artifact_path),
        },
        "boundary": {
            "no_retraining": True,
            "no_feature_changes": True,
            "no_gate_changes": True,
            "no_auth_txt_scan": True,
            "no_new_detection_logic": True,
            "redteam_labels_used_only_for_subset_selection": True,
        },
        "counts": {
            "background_all_count": int(len(background_df)),
            "background_R2_count": int(len(background_r2_df)),
            "redteam_associated_count": int(len(redteam_rows)),
            "model_feature_count": int(len(feature_names)),
        },
        "redteam_association": assoc_diag,
        "score_summary": {
            "background_all": score_summary(background_scores),
            "background_R2": score_summary(bg_r2_scores),
            "redteam_associated_v036_same_score": score_summary(rt_scores),
        },
        "score_contrast": {
            "wasserstein_background_R2_vs_redteam_same_score": wasserstein(bg_r2_scores, rt_scores),
            "wasserstein_background_all_vs_redteam_same_score": wasserstein(background_scores, rt_scores),
            "redteam_mean_minus_background_R2_mean": float(np.mean(rt_arr) - np.mean(bg_r2_scores)),
            "redteam_mean_minus_background_all_mean": float(np.mean(rt_arr) - np.mean(background_scores)),
        },
        "background_threshold_placement": placement,
        "top_feature_deltas": feature_delta.head(20).to_dict(orient="records"),
        "artifact_meta": artifact_meta,
        "outputs": {
            "redteam_same_score_ranked_csv": str(redteam_scored_csv),
            "redteam_same_score_ranked_jsonl": str(redteam_scored_jsonl),
            "same_score_distribution_contrast_csv": str(score_contrast_path),
            "feature_delta_csv": str(feature_delta_path),
        },
    }

    json_path = out_dir / "v1_2_3_same_score_redteam_contrast_report.json"
    txt_path = out_dir / "v1_2_3_same_score_redteam_contrast_report.txt"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_text_report(txt_path, report)

    print("Run complete.")
    print(f"Background all count:      {len(background_df):,}")
    print(f"Background R2 count:       {len(background_r2_df):,}")
    print(f"Redteam-associated count:  {len(redteam_rows):,}")
    print(f"Model feature count:       {len(feature_names):,}")
    print(f"Wrote JSON report:         {json_path}")
    print(f"Wrote text report:         {txt_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()
