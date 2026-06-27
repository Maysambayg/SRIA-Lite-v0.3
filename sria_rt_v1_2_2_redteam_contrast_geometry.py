#!/usr/bin/env python3
r"""
sria_rt_v1_2_2_redteam_contrast_geometry.py

SRIA RT v1.2.2 - Redteam Contrast Geometry

Purpose:
- Compare rare background R2 geometry against known redteam-associated accepted v036 episode geometry.
- Determine whether redteam-associated episodes occupy the same high-curvature tail geometry as rare background episodes,
  or whether they form a distinguishable subregion within or adjacent to that tail.

Inputs:
  1. v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv
  2. v036_batches\episodes_v036_accepted.jsonl
  3. v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl

Boundary:
- No model loading.
- No retraining.
- No feature changes.
- No gate changes.
- No auth.txt scan.
- No new detection logic.
- This is an interpretation/measurement layer only.

Recommended CMD command:

  py sria_rt_v1_2_2_redteam_contrast_geometry.py ^
    --background-ranked v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv ^
    --accepted-jsonl v036_batches\episodes_v036_accepted.jsonl ^
    --matches-jsonl v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl ^
    --out-dir v1_2_2_redteam_contrast_results

One-line CMD version:

  py sria_rt_v1_2_2_redteam_contrast_geometry.py --background-ranked v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv --accepted-jsonl v036_batches\episodes_v036_accepted.jsonl --matches-jsonl v036_batches\redteam_matches_v036_FINAL_SPARSE.jsonl --out-dir v1_2_2_redteam_contrast_results
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
    from scipy.stats import wasserstein_distance, entropy as scipy_entropy
except Exception:
    wasserstein_distance = None
    scipy_entropy = None


VERSION = "v1.2.2"

SCORE_COLUMNS = [
    "sria_rt_model_score",
    "model_score",
    "score",
    "legacy_sria_score",
    "legacy_raw_score",
]

RANK_COLUMNS = [
    "rank_global",
    "rank",
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

GATE_COLUMNS = [
    "candidate_gate",
    "gate",
    "dominant_gate",
]

BASE_PHI_COLUMNS = [
    "duration",
    "destination_count",
    "events_count",
    "user_count",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
    "first_time_signal_hits",
    "first_time_event_count",
    "new_destination_event_count",
    "legacy_sria_score",
    "legacy_raw_score",
    "raw_score",
    "score",
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


def safe_float(x: Any, default: float = 0.0) -> float:
    try:
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


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_jsonl(path: Path, limit: int = 0) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"JSONL file not found: {path}")

    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if limit and len(rows) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
                else:
                    rows.append({"value": obj})
            except Exception as e:
                raise ValueError(f"Failed to parse JSONL at {path}, line {i}: {e}") from e
    return rows


def flatten_dict(d: Dict[str, Any], prefix: str = "", max_depth: int = 2) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    def _walk(obj: Any, p: str, depth: int) -> None:
        if isinstance(obj, dict) and depth < max_depth:
            for k, v in obj.items():
                key = f"{p}.{k}" if p else str(k)
                _walk(v, key, depth + 1)
        else:
            out[p] = obj

    _walk(d, prefix, 0)
    return out


def jsonl_to_df(path: Path, limit: int = 0) -> pd.DataFrame:
    rows = read_jsonl(path, limit=limit)
    flat = [flatten_dict(r) for r in rows]
    df = pd.DataFrame(flat)
    return df


def normalize_signals(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, float) and math.isnan(value):
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    text = str(value).strip()
    if not text:
        return []
    if ";" in text:
        return [x.strip() for x in text.split(";") if x.strip()]
    if "," in text:
        return [x.strip() for x in text.split(",") if x.strip()]
    return [text]


def find_first_existing(df: pd.DataFrame, cols: Sequence[str]) -> Optional[str]:
    for c in cols:
        if c in df.columns:
            return c
    return None


def find_all_matching_columns(df: pd.DataFrame, candidates: Sequence[str]) -> List[str]:
    found: List[str] = []
    cols = set(df.columns)

    for c in candidates:
        if c in cols:
            found.append(c)

    # Also support flattened nested fields like match.episode_id or episode.episode_id.
    for col in df.columns:
        last = col.split(".")[-1]
        if last in candidates and col not in found:
            found.append(col)

    return found


def detect_score_column(df: pd.DataFrame) -> Optional[str]:
    return find_first_existing(df, SCORE_COLUMNS)


def detect_rank_column(df: pd.DataFrame) -> Optional[str]:
    return find_first_existing(df, RANK_COLUMNS)


def load_background_r2(background_ranked: Path, top_n: int) -> pd.DataFrame:
    if not background_ranked.exists():
        raise FileNotFoundError(f"Background ranked CSV not found: {background_ranked}")

    df = pd.read_csv(background_ranked)
    if df.empty:
        raise ValueError(f"Background ranked CSV is empty: {background_ranked}")

    score_col = detect_score_column(df)
    if not score_col:
        raise ValueError(
            f"No score column found in background ranked CSV. Available columns: {list(df.columns)}"
        )

    rank_col = detect_rank_column(df)

    df = df.copy()
    df["geom_score"] = pd.to_numeric(df[score_col], errors="coerce").fillna(0.0)

    if rank_col:
        df["geom_rank"] = pd.to_numeric(df[rank_col], errors="coerce").fillna(0).astype(int)
        if df["geom_rank"].max() <= 0:
            df = df.sort_values("geom_score", ascending=False).reset_index(drop=True)
            df["geom_rank"] = np.arange(1, len(df) + 1)
    else:
        df = df.sort_values("geom_score", ascending=False).reset_index(drop=True)
        df["geom_rank"] = np.arange(1, len(df) + 1)

    df = df.sort_values("geom_rank", ascending=True).reset_index(drop=True)
    r2 = df[df["geom_rank"] <= top_n].copy()
    r2["contrast_group"] = "background_R2"
    return r2


def add_signal_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    signal_col = None
    for c in ["signals", "signal_names", "explanation_signals"]:
        if c in df.columns:
            signal_col = c
            break

    if signal_col is None:
        for sig in SIGNAL_NAMES:
            df[f"sig__{sig}"] = 0.0
        return df

    signal_sets = df[signal_col].apply(lambda x: set(normalize_signals(x)))
    for sig in SIGNAL_NAMES:
        df[f"sig__{sig}"] = signal_sets.apply(lambda s: 1.0 if sig in s else 0.0)

    return df


def build_phi_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = add_signal_columns(df)

    # Include direct feature columns if present.
    phi = pd.DataFrame(index=df.index)

    for c in BASE_PHI_COLUMNS:
        if c in df.columns:
            phi[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    # Also support flattened episode fields, e.g., episode.duration.
    for c in df.columns:
        last = c.split(".")[-1]
        if last in BASE_PHI_COLUMNS and last not in phi.columns:
            phi[last] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    for sig in SIGNAL_NAMES:
        c = f"sig__{sig}"
        if c in df.columns:
            phi[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    # Derived first-time density if possible.
    if "first_time_signal_hits" in phi.columns and "events_count" in phi.columns:
        events = phi["events_count"].replace(0, np.nan)
        phi["derived_first_time_density"] = (phi["first_time_signal_hits"] / events).replace(
            [np.inf, -np.inf], 0.0
        ).fillna(0.0)

    # Derived temporal density if possible.
    if "events_count" in phi.columns and "duration" in phi.columns:
        dur = phi["duration"].replace(0, np.nan)
        phi["derived_temporal_density"] = (phi["events_count"] / dur).replace(
            [np.inf, -np.inf], 0.0
        ).fillna(0.0)

    if phi.empty:
        raise ValueError(
            f"No usable Phi columns found. Available columns: {list(df.columns)}"
        )

    return phi


def collect_identifier_values(df: pd.DataFrame, candidates: Sequence[str]) -> Set[str]:
    cols = find_all_matching_columns(df, candidates)
    values: Set[str] = set()

    for c in cols:
        for x in df[c].dropna().tolist():
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

    # If it looks like a non-empty list string or identifier string, treat as positive.
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        return True

    return False


def infer_redteam_mask_from_accepted(
    accepted_df: pd.DataFrame,
    matches_df: pd.DataFrame,
) -> Tuple[pd.Series, Dict[str, Any]]:
    """
    Attempts robust redteam association detection.

    Priority:
    1. Positive/redteam-like columns directly in accepted episodes.
    2. Episode IDs from matches file.
    3. Episode keys from matches file.
    """

    diagnostics: Dict[str, Any] = {
        "method": None,
        "accepted_columns": list(accepted_df.columns),
        "matches_columns": list(matches_df.columns),
        "matched_count": 0,
        "notes": [],
    }

    # 1. Direct positive/redteam columns in accepted episodes.
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

    direct_masks: List[pd.Series] = []
    used_direct_cols: List[str] = []
    for c in direct_cols:
        vals = accepted_df[c].apply(positive_like_value)
        if vals.sum() > 0:
            direct_masks.append(vals)
            used_direct_cols.append(c)

    if direct_masks:
        mask = direct_masks[0].copy()
        for m in direct_masks[1:]:
            mask = mask | m
        diagnostics["method"] = "direct_positive_columns_in_accepted"
        diagnostics["used_columns"] = used_direct_cols
        diagnostics["matched_count"] = int(mask.sum())
        return mask, diagnostics

    # 2. Match by numeric/string episode IDs.
    match_id_values = collect_identifier_values(matches_df, ID_COLUMNS)
    accepted_id_cols = find_all_matching_columns(accepted_df, ID_COLUMNS)

    for c in accepted_id_cols:
        vals = accepted_df[c].astype(str)
        mask = vals.isin(match_id_values)
        if mask.sum() > 0:
            diagnostics["method"] = "episode_id_match"
            diagnostics["accepted_id_column"] = c
            diagnostics["match_id_count"] = len(match_id_values)
            diagnostics["matched_count"] = int(mask.sum())
            return mask, diagnostics

    # 3. Match by episode keys.
    match_key_values = collect_identifier_values(matches_df, KEY_COLUMNS)
    accepted_key_cols = find_all_matching_columns(accepted_df, KEY_COLUMNS)

    for c in accepted_key_cols:
        vals = accepted_df[c].astype(str)
        mask = vals.isin(match_key_values)
        if mask.sum() > 0:
            diagnostics["method"] = "episode_key_match"
            diagnostics["accepted_key_column"] = c
            diagnostics["match_key_count"] = len(match_key_values)
            diagnostics["matched_count"] = int(mask.sum())
            return mask, diagnostics

    diagnostics["method"] = "failed_to_infer_redteam_mask"
    diagnostics["notes"].append(
        "No usable direct redteam columns or shared episode identifiers were found."
    )
    mask = pd.Series([False] * len(accepted_df), index=accepted_df.index)
    return mask, diagnostics


def load_redteam_episodes(
    accepted_jsonl: Path,
    matches_jsonl: Path,
    limit: int = 0,
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    accepted_df = jsonl_to_df(accepted_jsonl, limit=limit)
    matches_df = jsonl_to_df(matches_jsonl, limit=0)

    if accepted_df.empty:
        raise ValueError(f"Accepted episodes JSONL is empty: {accepted_jsonl}")

    if matches_df.empty:
        raise ValueError(f"Redteam matches JSONL is empty: {matches_jsonl}")

    mask, diagnostics = infer_redteam_mask_from_accepted(accepted_df, matches_df)
    redteam_df = accepted_df[mask].copy()

    if redteam_df.empty:
        diag_path_hint = (
            "Could not infer redteam-associated episodes automatically. "
            "Inspect the first few lines of both JSONL files and adjust identifier mapping."
        )
        raise ValueError(diag_path_hint + "\nDiagnostics:\n" + json.dumps(diagnostics, indent=2))

    redteam_df["contrast_group"] = "redteam_associated_v036"

    score_col = detect_score_column(redteam_df)
    if score_col:
        redteam_df["geom_score"] = pd.to_numeric(redteam_df[score_col], errors="coerce").fillna(0.0)
    else:
        redteam_df["geom_score"] = 0.0

    return redteam_df, diagnostics


def common_phi_matrices(
    background_df: pd.DataFrame,
    redteam_df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    phi_bg = build_phi_dataframe(background_df)
    phi_rt = build_phi_dataframe(redteam_df)

    common = sorted(set(phi_bg.columns).intersection(set(phi_rt.columns)))
    if not common:
        raise ValueError(
            "No common Phi columns between background R2 and redteam-associated episodes."
        )

    return phi_bg[common].copy(), phi_rt[common].copy(), common


def centroid_distance_l2(a: pd.DataFrame, b: pd.DataFrame) -> float:
    if len(a) == 0 or len(b) == 0:
        return 0.0
    ca = a.mean(axis=0).values
    cb = b.mean(axis=0).values
    return safe_float(np.linalg.norm(ca - cb))


def standardized_centroid_distance(a: pd.DataFrame, b: pd.DataFrame) -> float:
    if len(a) == 0 or len(b) == 0:
        return 0.0

    ca = a.mean(axis=0)
    cb = b.mean(axis=0)
    pooled = pd.concat([a, b], axis=0).std(axis=0).replace(0, np.nan)
    z = ((ca - cb) / pooled).replace([np.inf, -np.inf], 0.0).fillna(0.0)
    return safe_float(np.linalg.norm(z.values))


def wasserstein_featurewise(a: pd.DataFrame, b: pd.DataFrame) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for c in a.columns:
        av = a[c].to_numpy(dtype=float)
        bv = b[c].to_numpy(dtype=float)
        if len(av) == 0 or len(bv) == 0:
            out[c] = 0.0
            continue

        if wasserstein_distance is not None:
            out[c] = safe_float(wasserstein_distance(av, bv))
        else:
            qs = np.linspace(0, 100, 101)
            aq = np.percentile(av, qs)
            bq = np.percentile(bv, qs)
            out[c] = safe_float(np.mean(np.abs(aq - bq)))

    return out


def kl_divergence_hist(a: np.ndarray, b: np.ndarray, bins: int = 30) -> float:
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)

    if len(a) == 0 or len(b) == 0:
        return 0.0

    lo = min(float(np.min(a)), float(np.min(b)))
    hi = max(float(np.max(a)), float(np.max(b)))

    if hi <= lo:
        return 0.0

    edges = np.linspace(lo, hi, bins + 1)
    pa, _ = np.histogram(a, bins=edges, density=False)
    pb, _ = np.histogram(b, bins=edges, density=False)

    eps = 1e-12
    pa = pa.astype(float) + eps
    pb = pb.astype(float) + eps
    pa = pa / pa.sum()
    pb = pb / pb.sum()

    if scipy_entropy is not None:
        return safe_float(scipy_entropy(pa, pb))

    return safe_float(np.sum(pa * np.log(pa / pb)))


def feature_delta_table(a: pd.DataFrame, b: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    for c in a.columns:
        bg_mean = safe_float(a[c].mean())
        rt_mean = safe_float(b[c].mean())
        bg_std = safe_float(a[c].std())
        rt_std = safe_float(b[c].std())

        pooled = pd.concat([a[c], b[c]], axis=0).std()
        if not pooled or math.isnan(float(pooled)):
            z_delta = 0.0
        else:
            z_delta = (rt_mean - bg_mean) / float(pooled)

        rows.append({
            "feature": c,
            "background_R2_mean": bg_mean,
            "redteam_mean": rt_mean,
            "delta_redteam_minus_background_R2": safe_float(rt_mean - bg_mean),
            "background_R2_std": bg_std,
            "redteam_std": rt_std,
            "standardized_delta": safe_float(z_delta),
        })

    out = pd.DataFrame(rows)
    out = out.sort_values("standardized_delta", key=lambda s: s.abs(), ascending=False)
    return out


def gate_distribution(df: pd.DataFrame, group_name: str) -> pd.DataFrame:
    gate_col = None
    for c in GATE_COLUMNS:
        if c in df.columns:
            gate_col = c
            break

    if gate_col is None:
        # Try flattened endings.
        for c in df.columns:
            if c.split(".")[-1] in GATE_COLUMNS:
                gate_col = c
                break

    if gate_col is None:
        return pd.DataFrame([
            {
                "group": group_name,
                "gate": "__NO_GATE_COLUMN_FOUND__",
                "count": len(df),
                "share": 1.0 if len(df) else 0.0,
            }
        ])

    counts = Counter(str(x) for x in df[gate_col].fillna("__MISSING__").tolist())
    total = sum(counts.values()) or 1

    rows = []
    for gate, count in counts.most_common():
        rows.append({
            "group": group_name,
            "gate": gate,
            "count": int(count),
            "share": safe_float(count / total),
        })

    return pd.DataFrame(rows)


def score_summary(df: pd.DataFrame) -> Dict[str, Any]:
    if "geom_score" not in df.columns:
        return {"available": False}

    s = pd.to_numeric(df["geom_score"], errors="coerce").fillna(0.0).to_numpy(dtype=float)
    if len(s) == 0:
        return {"available": False}

    return {
        "available": True,
        "count": int(len(s)),
        "min": safe_float(np.min(s)),
        "p50": safe_float(np.percentile(s, 50)),
        "p90": safe_float(np.percentile(s, 90)),
        "p95": safe_float(np.percentile(s, 95)),
        "p99": safe_float(np.percentile(s, 99)),
        "max": safe_float(np.max(s)),
        "mean": safe_float(np.mean(s)),
        "std": safe_float(np.std(s)),
    }


def write_assignments(
    out_dir: Path,
    background_df: pd.DataFrame,
    redteam_df: pd.DataFrame,
) -> str:
    bg = background_df.copy()
    rt = redteam_df.copy()

    bg["contrast_group"] = "background_R2"
    rt["contrast_group"] = "redteam_associated_v036"

    combined = pd.concat([bg, rt], ignore_index=True, sort=False)

    preferred = [
        "contrast_group",
        "geom_rank",
        "geom_score",
        "rank_global",
        "rank",
        "severity",
        "review_priority",
        "window_id",
        "band",
        "background_episode_key",
        "episode_key",
        "episode_id",
        "start_time",
        "end_time",
        "duration",
        "source",
        "user",
        "destination_count",
        "events_count",
        "candidate_gate",
        "gate",
        "legacy_sria_score",
        "legacy_raw_score",
        "novelty_ratio",
        "compactness_score",
        "fanout_velocity_score",
        "first_time_signal_hits",
        "signals",
    ]

    cols = [c for c in preferred if c in combined.columns]
    if not cols:
        cols = list(combined.columns)

    p = out_dir / "redteam_geometry_assignments.csv"
    combined[cols].to_csv(p, index=False)
    return str(p)


def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text_report(path: Path, report: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("SRIA RT v1.2.2 Redteam Contrast Geometry Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Purpose:")
    lines.append("  Compare rare background R2 geometry against known redteam-associated v036 episode geometry.")
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
    lines.append(f"  background_R2_count: {report['counts']['background_R2_count']:,}")
    lines.append(f"  redteam_associated_count: {report['counts']['redteam_associated_count']:,}")
    lines.append(f"  common_phi_feature_count: {report['counts']['common_phi_feature_count']:,}")
    lines.append("")
    lines.append("Redteam association inference:")
    for k, v in report["redteam_association_diagnostics"].items():
        if k in {"accepted_columns", "matches_columns"}:
            continue
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Score summary:")
    lines.append("  background_R2:")
    for k, v in report["score_summary"]["background_R2"].items():
        lines.append(f"    {k}: {v}")
    lines.append("  redteam_associated_v036:")
    for k, v in report["score_summary"]["redteam_associated_v036"].items():
        lines.append(f"    {k}: {v}")
    lines.append("")
    lines.append("Phi-space contrast:")
    phi = report["phi_space_contrast"]
    lines.append(f"  centroid_distance_l2: {phi['centroid_distance_l2']}")
    lines.append(f"  standardized_centroid_distance: {phi['standardized_centroid_distance']}")
    lines.append(f"  mean_featurewise_wasserstein: {phi['mean_featurewise_wasserstein']}")
    lines.append(f"  max_featurewise_wasserstein: {phi['max_featurewise_wasserstein']}")
    lines.append("")
    lines.append("Top feature deltas by absolute standardized delta:")
    for row in report["top_feature_deltas"]:
        lines.append(
            f"  {row['feature']}: "
            f"bg_mean={row['background_R2_mean']:.8g}, "
            f"rt_mean={row['redteam_mean']:.8g}, "
            f"std_delta={row['standardized_delta']:.8g}"
        )
    lines.append("")
    lines.append("Interpretation boundary:")
    lines.append("  This report does not classify background R2 as benign or malicious.")
    lines.append("  This report does not prove intrinsic manifolds.")
    lines.append("  It measures whether known redteam-associated episodes differ from rare background R2 in observed Phi-space.")
    lines.append("")
    lines.append("Outputs:")
    for k, v in report["outputs"].items():
        lines.append(f"  {k}: {v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_report(
    background_ranked: Path,
    accepted_jsonl: Path,
    matches_jsonl: Path,
    out_dir: Path,
    background_r2: pd.DataFrame,
    redteam_df: pd.DataFrame,
    phi_bg: pd.DataFrame,
    phi_rt: pd.DataFrame,
    common_cols: List[str],
    diagnostics: Dict[str, Any],
) -> Dict[str, Any]:
    feature_w = wasserstein_featurewise(phi_bg, phi_rt)
    feature_delta = feature_delta_table(phi_bg, phi_rt)

    mean_w = safe_float(np.mean(list(feature_w.values()))) if feature_w else 0.0
    max_w = safe_float(np.max(list(feature_w.values()))) if feature_w else 0.0

    top_deltas = feature_delta.head(20).to_dict(orient="records")

    score_bg = score_summary(background_r2)
    score_rt = score_summary(redteam_df)

    gate_bg = gate_distribution(background_r2, "background_R2")
    gate_rt = gate_distribution(redteam_df, "redteam_associated_v036")
    gate_combined = pd.concat([gate_bg, gate_rt], ignore_index=True)

    feature_delta_path = out_dir / "background_R2_vs_redteam_feature_delta.csv"
    gate_path = out_dir / "background_R2_vs_redteam_gate_distribution.csv"
    centroid_path = out_dir / "background_R2_vs_redteam_phi_centroids.csv"

    feature_delta.to_csv(feature_delta_path, index=False)
    gate_combined.to_csv(gate_path, index=False)

    centroid_rows = []
    for c in common_cols:
        centroid_rows.append({
            "feature": c,
            "background_R2_centroid": safe_float(phi_bg[c].mean()),
            "redteam_centroid": safe_float(phi_rt[c].mean()),
            "delta_redteam_minus_background_R2": safe_float(phi_rt[c].mean() - phi_bg[c].mean()),
        })
    pd.DataFrame(centroid_rows).to_csv(centroid_path, index=False)

    assignments_path = write_assignments(out_dir, background_r2, redteam_df)

    report = {
        "version": VERSION,
        "purpose": "redteam_contrast_geometry_against_background_R2",
        "inputs": {
            "background_ranked": str(background_ranked),
            "accepted_jsonl": str(accepted_jsonl),
            "matches_jsonl": str(matches_jsonl),
        },
        "boundary": {
            "no_model_loading": True,
            "no_retraining": True,
            "no_feature_changes": True,
            "no_gate_changes": True,
            "no_auth_txt_scan": True,
            "no_new_detection_logic": True,
        },
        "counts": {
            "background_R2_count": int(len(background_r2)),
            "redteam_associated_count": int(len(redteam_df)),
            "common_phi_feature_count": int(len(common_cols)),
        },
        "redteam_association_diagnostics": diagnostics,
        "score_summary": {
            "background_R2": score_bg,
            "redteam_associated_v036": score_rt,
            "note": (
                "Background R2 uses v0.6.4 learned ranker scores. "
                "Redteam v036 score availability depends on fields present in accepted JSONL; "
                "primary comparison is Phi-space, not score calibration."
            ),
        },
        "phi_space_contrast": {
            "centroid_distance_l2": centroid_distance_l2(phi_bg, phi_rt),
            "standardized_centroid_distance": standardized_centroid_distance(phi_bg, phi_rt),
            "mean_featurewise_wasserstein": mean_w,
            "max_featurewise_wasserstein": max_w,
            "featurewise_wasserstein": feature_w,
        },
        "top_feature_deltas": top_deltas,
        "outputs": {
            "feature_delta_csv": str(feature_delta_path),
            "gate_distribution_csv": str(gate_path),
            "phi_centroids_csv": str(centroid_path),
            "assignments_csv": assignments_path,
        },
    }

    return report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SRIA RT v1.2.2 Redteam Contrast Geometry"
    )
    p.add_argument(
        "--background-ranked",
        required=True,
        help="Path to v064 aggregate_deployment_queue_all_ranked.csv",
    )
    p.add_argument(
        "--accepted-jsonl",
        required=True,
        help="Path to v036 accepted episodes JSONL",
    )
    p.add_argument(
        "--matches-jsonl",
        required=True,
        help="Path to v036 final sparse redteam matches JSONL",
    )
    p.add_argument(
        "--out-dir",
        required=True,
        help="Output directory",
    )
    p.add_argument(
        "--background-top",
        type=int,
        default=100,
        help="Background R2 size; default 100",
    )
    p.add_argument(
        "--accepted-limit",
        type=int,
        default=0,
        help="Optional debug/smoke limit for accepted JSONL; 0 means full file",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    background_ranked = Path(args.background_ranked)
    accepted_jsonl = Path(args.accepted_jsonl)
    matches_jsonl = Path(args.matches_jsonl)
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    print("=" * 80)
    print("SRIA RT v1.2.2 - Redteam Contrast Geometry")
    print("=" * 80)
    print(f"Background ranked: {background_ranked}")
    print(f"Accepted JSONL:     {accepted_jsonl}")
    print(f"Matches JSONL:      {matches_jsonl}")
    print(f"Output dir:         {out_dir}")
    print(f"Background R2 top:  {args.background_top}")
    print("=" * 80)

    background_r2 = load_background_r2(background_ranked, top_n=args.background_top)
    redteam_df, diagnostics = load_redteam_episodes(
        accepted_jsonl=accepted_jsonl,
        matches_jsonl=matches_jsonl,
        limit=args.accepted_limit,
    )

    phi_bg, phi_rt, common_cols = common_phi_matrices(background_r2, redteam_df)

    report = build_report(
        background_ranked=background_ranked,
        accepted_jsonl=accepted_jsonl,
        matches_jsonl=matches_jsonl,
        out_dir=out_dir,
        background_r2=background_r2,
        redteam_df=redteam_df,
        phi_bg=phi_bg,
        phi_rt=phi_rt,
        common_cols=common_cols,
        diagnostics=diagnostics,
    )

    json_path = out_dir / "v1_2_2_redteam_contrast_report.json"
    txt_path = out_dir / "v1_2_2_redteam_contrast_report.txt"

    write_json(json_path, report)
    write_text_report(txt_path, report)

    print("Run complete.")
    print(f"Background R2 count:        {len(background_r2):,}")
    print(f"Redteam-associated count:   {len(redteam_df):,}")
    print(f"Common Phi feature count:   {len(common_cols):,}")
    print(f"Wrote JSON report:          {json_path}")
    print(f"Wrote text report:          {txt_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()
