#!/usr/bin/env python3
r"""
sria_rt_v1_2_4_tail_stratification_report.py

SRIA RT v1.2.4 - Tail Stratification Report

Purpose:
- Stratify SRIA's high-score tail into interpretable structural subtypes.
- Compare rare background tail episodes against same-score redteam-associated v036 episodes.
- Identify whether the tail is homogeneous or decomposes into distinct structural modes.

Inputs:
  1. v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv
  2. v1_2_3_same_score_redteam_contrast_results\redteam_same_score_ranked.csv

Boundary:
- No model loading.
- No retraining.
- No feature changes.
- No gate changes.
- No auth.txt scan.
- No new detection logic.
- This is a post-hoc measurement / interpretation report.

Recommended CMD:

  py sria_rt_v1_2_4_tail_stratification_report.py --background-ranked v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv --redteam-same-score v1_2_3_same_score_redteam_contrast_results\redteam_same_score_ranked.csv --out-dir v1_2_4_tail_stratification_results

Optional:

  py sria_rt_v1_2_4_tail_stratification_report.py --background-ranked v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv --redteam-same-score v1_2_3_same_score_redteam_contrast_results\redteam_same_score_ranked.csv --out-dir v1_2_4_tail_stratification_results --background-tail 5000 --background-r2 100 --margin 0.35
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd


VERSION = "v1.2.4"

BACKGROUND_SCORE_COLUMNS = [
    "sria_rt_model_score",
    "same_score",
    "model_score",
    "score",
]

BACKGROUND_RANK_COLUMNS = [
    "rank_global",
    "rank",
    "same_score_rank",
]

REDTEAM_SCORE_COLUMNS = [
    "same_score_redteam_score",
    "same_score",
    "sria_rt_model_score",
    "model_score",
    "score",
]

SIGNAL_NAMES = [
    "source_user_fanout_rescue_bonus",
    "entropy_soft_duration",
    "compact_lateral_burst",
    "propagation_convergence_bonus",
    "user_fanout",
    "source_fanout",
    "first_time_source_to_dest",
    "first_time_user_to_dest",
    "first_time_source_user_to_dest",
    "source_user_fanout",
    "compact_rescue_bonus",
    "entropy_low_novelty",
]

RESCUE_FEATURES = [
    "sig__source_user_fanout_rescue_bonus",
    "sig__entropy_soft_duration",
    "duration",
    "first_time_signal_hits",
    "novelty_ratio",
]

COMPACT_PROPAGATION_FEATURES = [
    "compactness_score",
    "derived_temporal_density",
    "sig__user_fanout",
    "sig__propagation_convergence_bonus",
    "sig__compact_lateral_burst",
    "sig__source_fanout",
]

NEUTRAL_FEATURES = [
    "destination_count",
    "events_count",
    "new_destination_event_count",
    "first_time_event_count",
    "fanout_velocity_score",
    "peak_velocity_new_dests",
]

PREFERRED_OUTPUT_COLUMNS = [
    "tail_group",
    "tail_subtype",
    "tail_index_delta",
    "fanout_rescue_index",
    "compact_propagation_index",
    "score",
    "rank",
    "background_percentile",
    "source",
    "user",
    "episode_id",
    "background_episode_key",
    "window_id",
    "band",
    "candidate_gate",
    "duration",
    "events_count",
    "destination_count",
    "novelty_ratio",
    "compactness_score",
    "fanout_velocity_score",
    "first_time_signal_hits",
    "first_time_event_count",
    "new_destination_event_count",
    "derived_temporal_density",
    "signals",
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


def find_first_existing(df: pd.DataFrame, candidates: Sequence[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def add_signal_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    if "signals" in df.columns:
        signal_sets = df["signals"].apply(lambda x: set(normalize_signals(x)))
    else:
        signal_sets = pd.Series([set()] * len(df), index=df.index)

    for sig in SIGNAL_NAMES:
        col = f"sig__{sig}"
        if col not in df.columns:
            df[col] = signal_sets.apply(lambda s: 1.0 if sig in s else 0.0)
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(
                signal_sets.apply(lambda s: 1.0 if sig in s else 0.0)
            )

    return df


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    for c in [
        "duration",
        "events_count",
        "destination_count",
        "new_destination_event_count",
        "first_time_event_count",
        "first_time_signal_hits",
        "novelty_ratio",
        "compactness_score",
        "fanout_velocity_score",
        "peak_velocity_new_dests",
    ]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
        else:
            df[c] = 0.0

    duration = df["duration"].replace(0, np.nan)
    df["derived_temporal_density"] = (df["events_count"] / duration).replace(
        [np.inf, -np.inf], 0.0
    ).fillna(0.0)

    events = df["events_count"].replace(0, np.nan)
    df["derived_first_time_density"] = (df["first_time_signal_hits"] / events).replace(
        [np.inf, -np.inf], 0.0
    ).fillna(0.0)

    return df


def load_background_tail(path: Path, background_tail: int, background_r2: int) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Background ranked CSV not found: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"Background ranked CSV is empty: {path}")

    score_col = find_first_existing(df, BACKGROUND_SCORE_COLUMNS)
    if score_col is None:
        raise ValueError(f"No background score column found. Available columns: {list(df.columns)}")

    rank_col = find_first_existing(df, BACKGROUND_RANK_COLUMNS)

    df = df.copy()
    df["score"] = pd.to_numeric(df[score_col], errors="coerce").fillna(0.0)

    if rank_col:
        df["rank"] = pd.to_numeric(df[rank_col], errors="coerce").fillna(0).astype(int)
        if df["rank"].max() <= 0:
            df = df.sort_values("score", ascending=False).reset_index(drop=True)
            df["rank"] = np.arange(1, len(df) + 1)
    else:
        df = df.sort_values("score", ascending=False).reset_index(drop=True)
        df["rank"] = np.arange(1, len(df) + 1)

    df = df.sort_values("rank", ascending=True).reset_index(drop=True)

    background_scores = df["score"].to_numpy(dtype=float)
    df["background_percentile"] = df["score"].apply(lambda s: 100.0 * float(np.mean(background_scores <= s)))

    tail = df[df["rank"] <= background_tail].copy()
    tail["tail_group"] = "background_tail"
    tail.loc[tail["rank"] <= background_r2, "tail_group"] = "background_R2"
    tail.loc[tail["rank"] > background_r2, "tail_group"] = "background_R1_tail"

    tail = add_signal_columns(tail)
    tail = add_derived_features(tail)
    return tail


def load_redteam_same_score(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Redteam same-score CSV not found: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"Redteam same-score CSV is empty: {path}")

    score_col = find_first_existing(df, REDTEAM_SCORE_COLUMNS)
    if score_col is None:
        raise ValueError(f"No redteam same-score column found. Available columns: {list(df.columns)}")

    df = df.copy()
    df["score"] = pd.to_numeric(df[score_col], errors="coerce").fillna(0.0)

    if "same_score_background_percentile" in df.columns:
        df["background_percentile"] = pd.to_numeric(
            df["same_score_background_percentile"], errors="coerce"
        ).fillna(0.0)
    else:
        df["background_percentile"] = 0.0

    if "same_score_background_rank_equivalent" in df.columns:
        df["rank"] = pd.to_numeric(
            df["same_score_background_rank_equivalent"], errors="coerce"
        ).fillna(0).astype(int)
    elif "rank" in df.columns:
        df["rank"] = pd.to_numeric(df["rank"], errors="coerce").fillna(0).astype(int)
    else:
        df = df.sort_values("score", ascending=False).reset_index(drop=True)
        df["rank"] = np.arange(1, len(df) + 1)

    df["tail_group"] = "redteam_associated"

    df = add_signal_columns(df)
    df = add_derived_features(df)
    return df


def zscore_columns(df: pd.DataFrame, cols: Sequence[str]) -> pd.DataFrame:
    z = pd.DataFrame(index=df.index)

    for c in cols:
        if c not in df.columns:
            z[c] = 0.0
            continue

        vals = pd.to_numeric(df[c], errors="coerce").fillna(0.0).astype(float)
        mean = float(vals.mean())
        std = float(vals.std())

        if std == 0.0 or math.isnan(std):
            z[c] = 0.0
        else:
            z[c] = (vals - mean) / std

    return z


def stratify_tail(df: pd.DataFrame, margin: float) -> pd.DataFrame:
    df = df.copy()

    all_index_features = sorted(set(RESCUE_FEATURES + COMPACT_PROPAGATION_FEATURES))
    z = zscore_columns(df, all_index_features)

    for c in RESCUE_FEATURES:
        if c not in z.columns:
            z[c] = 0.0

    for c in COMPACT_PROPAGATION_FEATURES:
        if c not in z.columns:
            z[c] = 0.0

    df["fanout_rescue_index"] = z[RESCUE_FEATURES].mean(axis=1)
    df["compact_propagation_index"] = z[COMPACT_PROPAGATION_FEATURES].mean(axis=1)
    df["tail_index_delta"] = df["compact_propagation_index"] - df["fanout_rescue_index"]

    def classify(delta: float) -> str:
        if delta >= margin:
            return "compact_propagation_tail"
        if delta <= -margin:
            return "fanout_rescue_tail"
        return "mixed_tail"

    df["tail_subtype"] = df["tail_index_delta"].apply(classify)
    return df


def summary_stats(values: Sequence[float]) -> Dict[str, Any]:
    arr = np.asarray(list(values), dtype=float)
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


def group_subtype_table(df: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    for group, g in df.groupby("tail_group", sort=True):
        total = len(g)
        for subtype, s in g.groupby("tail_subtype", sort=True):
            rows.append({
                "tail_group": group,
                "tail_subtype": subtype,
                "count": int(len(s)),
                "share": float(len(s) / total) if total else 0.0,
                "score_mean": float(s["score"].mean()) if len(s) else 0.0,
                "background_percentile_mean": float(s["background_percentile"].mean()) if len(s) else 0.0,
                "fanout_rescue_index_mean": float(s["fanout_rescue_index"].mean()) if len(s) else 0.0,
                "compact_propagation_index_mean": float(s["compact_propagation_index"].mean()) if len(s) else 0.0,
                "tail_index_delta_mean": float(s["tail_index_delta"].mean()) if len(s) else 0.0,
            })

    return pd.DataFrame(rows)


def feature_centroid_table(df: pd.DataFrame) -> pd.DataFrame:
    features = sorted(set(RESCUE_FEATURES + COMPACT_PROPAGATION_FEATURES + NEUTRAL_FEATURES))
    rows: List[Dict[str, Any]] = []

    for group, g in df.groupby("tail_group", sort=True):
        for subtype, s in g.groupby("tail_subtype", sort=True):
            row: Dict[str, Any] = {
                "tail_group": group,
                "tail_subtype": subtype,
                "count": int(len(s)),
            }
            for f in features:
                if f in s.columns:
                    row[f"{f}_mean"] = float(pd.to_numeric(s[f], errors="coerce").fillna(0.0).mean())
            rows.append(row)

    return pd.DataFrame(rows)


def gate_distribution_table(df: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    if "candidate_gate" not in df.columns:
        return pd.DataFrame([{
            "tail_group": "__ALL__",
            "tail_subtype": "__NO_GATE_COLUMN__",
            "candidate_gate": "__NO_GATE_COLUMN__",
            "count": len(df),
            "share": 1.0 if len(df) else 0.0,
        }])

    for (group, subtype), g in df.groupby(["tail_group", "tail_subtype"], sort=True):
        counts = Counter(str(x) for x in g["candidate_gate"].fillna("__MISSING__").tolist())
        total = sum(counts.values()) or 1
        for gate, count in counts.most_common():
            rows.append({
                "tail_group": group,
                "tail_subtype": subtype,
                "candidate_gate": gate,
                "count": int(count),
                "share": float(count / total),
            })

    return pd.DataFrame(rows)


def contrast_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compare redteam-associated subtype composition against background_R2 and background_R1_tail.
    """
    rows: List[Dict[str, Any]] = []

    groups = sorted(df["tail_group"].unique().tolist())
    subtypes = sorted(df["tail_subtype"].unique().tolist())

    shares: Dict[Tuple[str, str], float] = {}
    counts: Dict[Tuple[str, str], int] = {}

    for group in groups:
        g = df[df["tail_group"] == group]
        total = len(g) or 1
        for subtype in subtypes:
            c = int((g["tail_subtype"] == subtype).sum())
            counts[(group, subtype)] = c
            shares[(group, subtype)] = c / total

    for subtype in subtypes:
        rt_share = shares.get(("redteam_associated", subtype), 0.0)
        r2_share = shares.get(("background_R2", subtype), 0.0)
        r1_share = shares.get(("background_R1_tail", subtype), 0.0)

        rows.append({
            "tail_subtype": subtype,
            "redteam_share": rt_share,
            "background_R2_share": r2_share,
            "background_R1_tail_share": r1_share,
            "redteam_minus_background_R2_share": rt_share - r2_share,
            "redteam_minus_background_R1_tail_share": rt_share - r1_share,
            "redteam_count": counts.get(("redteam_associated", subtype), 0),
            "background_R2_count": counts.get(("background_R2", subtype), 0),
            "background_R1_tail_count": counts.get(("background_R1_tail", subtype), 0),
        })

    return pd.DataFrame(rows)


def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text_report(path: Path, report: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("SRIA RT v1.2.4 Tail Stratification Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Purpose:")
    lines.append("  Stratify SRIA's high-score tail into structural subtypes.")
    lines.append("")
    lines.append("Boundary:")
    for k, v in report["boundary"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Inputs:")
    for k, v in report["inputs"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Configuration:")
    for k, v in report["configuration"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Counts:")
    for k, v in report["counts"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Score summaries:")
    for group, stats in report["score_summary_by_group"].items():
        lines.append(f"  {group}:")
        for k, v in stats.items():
            lines.append(f"    {k}: {v}")
    lines.append("")
    lines.append("Subtype composition:")
    for row in report["subtype_composition"]:
        lines.append(
            f"  {row['tail_group']} / {row['tail_subtype']}: "
            f"count={row['count']}, share={row['share']:.6f}, "
            f"delta_mean={row['tail_index_delta_mean']:.6f}, "
            f"rescue_mean={row['fanout_rescue_index_mean']:.6f}, "
            f"compact_mean={row['compact_propagation_index_mean']:.6f}"
        )
    lines.append("")
    lines.append("Redteam-vs-background subtype contrast:")
    for row in report["subtype_contrast"]:
        lines.append(
            f"  {row['tail_subtype']}: "
            f"redteam_share={row['redteam_share']:.6f}, "
            f"background_R2_share={row['background_R2_share']:.6f}, "
            f"background_R1_tail_share={row['background_R1_tail_share']:.6f}, "
            f"redteam_minus_R2={row['redteam_minus_background_R2_share']:.6f}"
        )
    lines.append("")
    lines.append("Interpretation boundary:")
    lines.append("  Tail subtypes are post-hoc diagnostic strata, not new detection labels.")
    lines.append("  This report does not classify background tail events as benign or malicious.")
    lines.append("  This report does not establish production precision or intrinsic manifolds.")
    lines.append("")
    lines.append("Outputs:")
    for k, v in report["outputs"].items():
        lines.append(f"  {k}: {v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v1.2.4 Tail Stratification Report")
    p.add_argument("--background-ranked", required=True, help="v064 aggregate_deployment_queue_all_ranked.csv")
    p.add_argument("--redteam-same-score", required=True, help="v1.2.3 redteam_same_score_ranked.csv")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--background-tail", type=int, default=5000, help="Background tail size for stratification")
    p.add_argument("--background-r2", type=int, default=100, help="Background R2 top-N boundary")
    p.add_argument("--margin", type=float, default=0.35, help="Subtype margin on compact-minus-rescue index")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    background_path = Path(args.background_ranked)
    redteam_path = Path(args.redteam_same_score)
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    print("=" * 80)
    print("SRIA RT v1.2.4 - Tail Stratification Report")
    print("=" * 80)
    print(f"Background ranked:      {background_path}")
    print(f"Redteam same-score:     {redteam_path}")
    print(f"Output dir:             {out_dir}")
    print(f"Background tail:        top {args.background_tail}")
    print(f"Background R2 boundary: top {args.background_r2}")
    print(f"Subtype margin:         {args.margin}")
    print("=" * 80)

    background_tail = load_background_tail(
        background_path,
        background_tail=args.background_tail,
        background_r2=args.background_r2,
    )

    redteam = load_redteam_same_score(redteam_path)

    combined = pd.concat([background_tail, redteam], ignore_index=True, sort=False)
    combined = add_signal_columns(combined)
    combined = add_derived_features(combined)
    combined = stratify_tail(combined, margin=args.margin)

    # Outputs
    assignments_path = out_dir / "tail_stratification_assignments.csv"
    subtype_summary_path = out_dir / "tail_subtype_summary.csv"
    centroid_path = out_dir / "tail_subtype_feature_centroids.csv"
    gate_path = out_dir / "tail_subtype_gate_distribution.csv"
    contrast_path = out_dir / "tail_subtype_redteam_vs_background_contrast.csv"

    output_cols = [c for c in PREFERRED_OUTPUT_COLUMNS if c in combined.columns]
    combined[output_cols].to_csv(assignments_path, index=False)

    subtype_summary = group_subtype_table(combined)
    subtype_summary.to_csv(subtype_summary_path, index=False)

    centroids = feature_centroid_table(combined)
    centroids.to_csv(centroid_path, index=False)

    gates = gate_distribution_table(combined)
    gates.to_csv(gate_path, index=False)

    contrast = contrast_table(combined)
    contrast.to_csv(contrast_path, index=False)

    score_summary_by_group: Dict[str, Dict[str, Any]] = {}
    for group, g in combined.groupby("tail_group", sort=True):
        score_summary_by_group[group] = summary_stats(g["score"].tolist())

    report: Dict[str, Any] = {
        "version": VERSION,
        "purpose": "tail_stratification_into_fanout_rescue_vs_compact_propagation_subtypes",
        "inputs": {
            "background_ranked": str(background_path),
            "redteam_same_score": str(redteam_path),
        },
        "boundary": {
            "no_model_loading": True,
            "no_retraining": True,
            "no_feature_changes": True,
            "no_gate_changes": True,
            "no_auth_txt_scan": True,
            "no_new_detection_logic": True,
            "tail_subtypes_are_posthoc_diagnostics": True,
        },
        "configuration": {
            "background_tail": args.background_tail,
            "background_R2_boundary": args.background_r2,
            "subtype_margin": args.margin,
            "fanout_rescue_features": RESCUE_FEATURES,
            "compact_propagation_features": COMPACT_PROPAGATION_FEATURES,
            "subtype_rule": "tail_index_delta = compact_propagation_index - fanout_rescue_index; compact if >= margin; rescue if <= -margin; else mixed",
        },
        "counts": {
            "background_tail_count": int(len(background_tail)),
            "background_R2_count": int((combined["tail_group"] == "background_R2").sum()),
            "background_R1_tail_count": int((combined["tail_group"] == "background_R1_tail").sum()),
            "redteam_associated_count": int((combined["tail_group"] == "redteam_associated").sum()),
            "combined_count": int(len(combined)),
        },
        "score_summary_by_group": score_summary_by_group,
        "subtype_composition": subtype_summary.to_dict(orient="records"),
        "subtype_contrast": contrast.to_dict(orient="records"),
        "outputs": {
            "assignments_csv": str(assignments_path),
            "subtype_summary_csv": str(subtype_summary_path),
            "feature_centroids_csv": str(centroid_path),
            "gate_distribution_csv": str(gate_path),
            "redteam_vs_background_contrast_csv": str(contrast_path),
        },
    }

    json_path = out_dir / "v1_2_4_tail_stratification_report.json"
    txt_path = out_dir / "v1_2_4_tail_stratification_report.txt"

    write_json(json_path, report)
    write_text_report(txt_path, report)

    print("Run complete.")
    print(f"Background tail count:   {report['counts']['background_tail_count']:,}")
    print(f"Background R2 count:     {report['counts']['background_R2_count']:,}")
    print(f"Background R1 tail count:{report['counts']['background_R1_tail_count']:,}")
    print(f"Redteam count:           {report['counts']['redteam_associated_count']:,}")
    print(f"Combined count:          {report['counts']['combined_count']:,}")
    print(f"Wrote JSON report:       {json_path}")
    print(f"Wrote text report:       {txt_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()
