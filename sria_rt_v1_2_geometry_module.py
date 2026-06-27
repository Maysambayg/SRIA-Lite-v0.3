#!/usr/bin/env python3
r"""
sria_rt_v1_2_geometry_module.py

SRIA RT v1.2 - Geometry Measurement Layer

Purpose:
- Measure empirical geometry over existing v0.6.4 ranked background outputs.
- Use current SRIA outputs only.
- No model loading.
- No retraining.
- No feature changes.
- No gate changes.
- No auth.txt scan.
- No red-team validation.

Primary expected input:
  v064_background_ranked_tierB\aggregate_deployment_queue_all_ranked.csv

Recommended CMD use from F:\SRIA\SRIA_RT_v01:

  py sria_rt_v1_2_geometry_module.py --ranked-dir v064_background_ranked_tierB --out-dir v1_2_geometry_results

Optional:
  py sria_rt_v1_2_geometry_module.py --ranked-dir v064_background_ranked_tierB --out-dir v1_2_geometry_results --top-r2 100 --r1-end 5000 --bins 50 --write-phi-matrices

Regime defaults:
  R2 = top 100 ranked background episodes
  R1 = ranks 101 through 5000
  R0 = ranks > 5000

This is intentionally ranking-grounded, because v0.6.4 already produced the
current primary learned-ranker ordering.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

try:
    from scipy.stats import wasserstein_distance, entropy as scipy_entropy
except Exception:
    wasserstein_distance = None
    scipy_entropy = None


VERSION = "v1.2"

DEFAULT_ALL_RANKED = "aggregate_deployment_queue_all_ranked.csv"
DEFAULT_SUMMARY = "v064_background_ranker_summary.csv"

SCORE_COLUMNS = [
    "sria_rt_model_score",
    "model_score",
    "score",
    "legacy_sria_score",
]

RANK_COLUMNS = [
    "rank_global",
    "rank",
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


def find_existing_column(df: pd.DataFrame, candidates: Sequence[str], label: str) -> str:
    for c in candidates:
        if c in df.columns:
            return c
    raise ValueError(
        f"No {label} column found. Tried {list(candidates)}. "
        f"Available columns: {list(df.columns)}"
    )


def normalize_signals(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, float) and math.isnan(value):
        return []
    text = str(value).strip()
    if not text:
        return []
    if ";" in text:
        return [x.strip() for x in text.split(";") if x.strip()]
    if "," in text:
        return [x.strip() for x in text.split(",") if x.strip()]
    return [text]


def load_ranked_csv(path: Path, sample_limit: int = 0) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Ranked CSV not found: {path}")

    if sample_limit and sample_limit > 0:
        df = pd.read_csv(path, nrows=sample_limit)
    else:
        df = pd.read_csv(path)

    if df.empty:
        raise ValueError(f"Ranked CSV is empty: {path}")

    score_col = find_existing_column(df, SCORE_COLUMNS, "score")
    rank_col = find_existing_column(df, RANK_COLUMNS, "rank")

    df = df.copy()
    df["geom_score"] = pd.to_numeric(df[score_col], errors="coerce").fillna(0.0)
    df["geom_rank"] = pd.to_numeric(df[rank_col], errors="coerce").fillna(0).astype(int)

    # If rank_global is absent or zeroed, rebuild rank by descending score.
    if df["geom_rank"].max() <= 0:
        df = df.sort_values("geom_score", ascending=False).reset_index(drop=True)
        df["geom_rank"] = np.arange(1, len(df) + 1)

    df = df.sort_values("geom_rank", ascending=True).reset_index(drop=True)
    return df


def assign_regimes_by_rank(df: pd.DataFrame, top_r2: int, r1_end: int) -> pd.DataFrame:
    if top_r2 < 1:
        raise ValueError("--top-r2 must be >= 1")
    if r1_end <= top_r2:
        raise ValueError("--r1-end must be greater than --top-r2")

    df = df.copy()
    df["geom_regime"] = "R0"
    df.loc[(df["geom_rank"] > top_r2) & (df["geom_rank"] <= r1_end), "geom_regime"] = "R1"
    df.loc[df["geom_rank"] <= top_r2, "geom_regime"] = "R2"
    return df


def add_signal_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "signals" not in df.columns:
        for sig in SIGNAL_NAMES:
            df[f"sig__{sig}"] = 0.0
        return df

    signal_sets = df["signals"].apply(lambda x: set(normalize_signals(x)))
    for sig in SIGNAL_NAMES:
        df[f"sig__{sig}"] = signal_sets.apply(lambda s: 1.0 if sig in s else 0.0)
    return df


def build_phi_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = add_signal_columns(df)

    available_base = [c for c in BASE_PHI_COLUMNS if c in df.columns]
    signal_cols = [f"sig__{sig}" for sig in SIGNAL_NAMES if f"sig__{sig}" in df.columns]

    phi_cols = available_base + signal_cols

    if not phi_cols:
        raise ValueError("No usable Phi columns found.")

    phi = pd.DataFrame(index=df.index)
    for c in phi_cols:
        phi[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    # Derived density-like features from existing columns only.
    if "first_time_signal_hits" in df.columns and "events_count" in df.columns:
        hits = pd.to_numeric(df["first_time_signal_hits"], errors="coerce").fillna(0.0)
        events = pd.to_numeric(df["events_count"], errors="coerce").fillna(0.0)
        phi["derived_first_time_density"] = hits / events.replace(0, np.nan)
        phi["derived_first_time_density"] = phi["derived_first_time_density"].fillna(0.0)

    if "events_count" in df.columns and "duration" in df.columns:
        events = pd.to_numeric(df["events_count"], errors="coerce").fillna(0.0)
        dur = pd.to_numeric(df["duration"], errors="coerce").fillna(0.0)
        phi["derived_temporal_density"] = events / dur.replace(0, np.nan)
        phi["derived_temporal_density"] = phi["derived_temporal_density"].replace([np.inf, -np.inf], 0.0).fillna(0.0)

    return phi


def density_report(scores: np.ndarray, bins: int) -> Dict[str, Any]:
    scores = np.asarray(scores, dtype=float)
    if len(scores) == 0:
        return {
            "count": 0,
            "hist": [],
            "edges": [],
        }

    hist, edges = np.histogram(scores, bins=bins, density=False)
    hist_density, _ = np.histogram(scores, bins=edges, density=True)

    return {
        "count": int(len(scores)),
        "hist_count": hist.astype(int).tolist(),
        "hist_density": [safe_float(x) for x in hist_density.tolist()],
        "edges": [safe_float(x) for x in edges.tolist()],
        "min": safe_float(np.min(scores)),
        "p50": safe_float(np.percentile(scores, 50)),
        "p90": safe_float(np.percentile(scores, 90)),
        "p95": safe_float(np.percentile(scores, 95)),
        "p99": safe_float(np.percentile(scores, 99)),
        "max": safe_float(np.max(scores)),
        "mean": safe_float(np.mean(scores)),
        "std": safe_float(np.std(scores)),
    }


def kl_divergence_hist(a: np.ndarray, b: np.ndarray, bins: int) -> float:
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


def wasserstein(a: np.ndarray, b: np.ndarray) -> float:
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    if len(a) == 0 or len(b) == 0:
        return 0.0

    if wasserstein_distance is not None:
        return safe_float(wasserstein_distance(a, b))

    # Simple fallback approximation by comparing sorted quantiles.
    qs = np.linspace(0, 100, 101)
    aq = np.percentile(a, qs)
    bq = np.percentile(b, qs)
    return safe_float(np.mean(np.abs(aq - bq)))


def curvature_report(scores: np.ndarray) -> Dict[str, Any]:
    scores = np.asarray(scores, dtype=float)
    if len(scores) < 5:
        return {
            "count": int(len(scores)),
            "mean_curvature": 0.0,
            "std_curvature": 0.0,
            "mean_abs_curvature": 0.0,
            "max_abs_curvature": 0.0,
        }

    s = np.sort(scores)
    grad = np.gradient(s)
    kappa = np.gradient(grad)

    return {
        "count": int(len(scores)),
        "mean_curvature": safe_float(np.mean(kappa)),
        "std_curvature": safe_float(np.std(kappa)),
        "mean_abs_curvature": safe_float(np.mean(np.abs(kappa))),
        "max_abs_curvature": safe_float(np.max(np.abs(kappa))),
        "p95_abs_curvature": safe_float(np.percentile(np.abs(kappa), 95)),
        "p99_abs_curvature": safe_float(np.percentile(np.abs(kappa), 99)),
    }


def phi_separation_report(phi: pd.DataFrame, regimes: pd.Series) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for a, b in [("R0", "R1"), ("R1", "R2"), ("R0", "R2")]:
        pa = phi.loc[regimes == a]
        pb = phi.loc[regimes == b]
        if len(pa) == 0 or len(pb) == 0:
            out[f"{a}_vs_{b}"] = {
                "centroid_distance_l2": 0.0,
                "available": False,
            }
            continue

        ca = pa.mean(axis=0).values
        cb = pb.mean(axis=0).values
        dist = float(np.linalg.norm(ca - cb))
        out[f"{a}_vs_{b}"] = {
            "centroid_distance_l2": safe_float(dist),
            "available": True,
            "n_a": int(len(pa)),
            "n_b": int(len(pb)),
        }
    return out


def window_stability_report(df: pd.DataFrame) -> Dict[str, Any]:
    if "window_id" not in df.columns:
        return {"available": False, "reason": "window_id column not found"}

    rows: List[Dict[str, Any]] = []
    for wid, g in df.groupby("window_id", sort=True):
        scores = g["geom_score"].to_numpy(dtype=float)
        rows.append({
            "window_id": str(wid),
            "rows": int(len(g)),
            "score_mean": safe_float(np.mean(scores)) if len(scores) else 0.0,
            "score_std": safe_float(np.std(scores)) if len(scores) else 0.0,
            "score_p99": safe_float(np.percentile(scores, 99)) if len(scores) else 0.0,
            "score_max": safe_float(np.max(scores)) if len(scores) else 0.0,
            "r0_count": int((g["geom_regime"] == "R0").sum()),
            "r1_count": int((g["geom_regime"] == "R1").sum()),
            "r2_count": int((g["geom_regime"] == "R2").sum()),
        })

    means = np.array([r["score_mean"] for r in rows], dtype=float)
    p99s = np.array([r["score_p99"] for r in rows], dtype=float)
    maxs = np.array([r["score_max"] for r in rows], dtype=float)

    return {
        "available": True,
        "windows": rows,
        "score_mean_variance_across_windows": safe_float(np.var(means)) if len(means) else 0.0,
        "score_p99_variance_across_windows": safe_float(np.var(p99s)) if len(p99s) else 0.0,
        "score_max_variance_across_windows": safe_float(np.var(maxs)) if len(maxs) else 0.0,
        "score_mean_std_across_windows": safe_float(np.std(means)) if len(means) else 0.0,
        "score_p99_std_across_windows": safe_float(np.std(p99s)) if len(p99s) else 0.0,
        "score_max_std_across_windows": safe_float(np.std(maxs)) if len(maxs) else 0.0,
    }


def gate_distribution(df: pd.DataFrame) -> Dict[str, Any]:
    if "candidate_gate" not in df.columns:
        return {}
    out: Dict[str, Any] = {}
    for regime, g in df.groupby("geom_regime", sort=True):
        c = Counter(str(x) for x in g["candidate_gate"].fillna(""))
        total = sum(c.values()) or 1
        out[regime] = [
            {"candidate_gate": k, "count": int(v), "share": safe_float(v / total)}
            for k, v in c.most_common()
        ]
    return out


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fields), extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_phi_matrices(out_dir: Path, phi: pd.DataFrame, regimes: pd.Series) -> Dict[str, str]:
    paths: Dict[str, str] = {}
    for regime in ["R0", "R1", "R2"]:
        p = out_dir / f"phi_matrix_{regime}.csv"
        phi.loc[regimes == regime].to_csv(p, index=False)
        paths[regime] = str(p)
    return paths


def write_regime_assignments(out_dir: Path, df: pd.DataFrame) -> str:
    fields = [
        "geom_rank",
        "geom_score",
        "geom_regime",
        "rank_scope",
        "rank_global",
        "rank_in_window",
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
        "candidate_gate",
        "legacy_sria_score",
        "legacy_raw_score",
        "novelty_ratio",
        "compactness_score",
        "fanout_velocity_score",
        "first_time_signal_hits",
        "signals",
    ]
    available = [f for f in fields if f in df.columns]
    p = out_dir / "v1_2_regime_assignments.csv"
    df[available].to_csv(p, index=False)
    return str(p)


def build_report(
    df: pd.DataFrame,
    phi: pd.DataFrame,
    ranked_file: Path,
    out_dir: Path,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    regimes = df["geom_regime"]

    scores = {
        "R0": df.loc[regimes == "R0", "geom_score"].to_numpy(dtype=float),
        "R1": df.loc[regimes == "R1", "geom_score"].to_numpy(dtype=float),
        "R2": df.loc[regimes == "R2", "geom_score"].to_numpy(dtype=float),
        "ALL": df["geom_score"].to_numpy(dtype=float),
    }

    density = {
        k: density_report(v, args.bins)
        for k, v in scores.items()
    }

    curvature = {
        k: curvature_report(v)
        for k, v in scores.items()
    }

    boundary = {
        "R1_R2_wasserstein": wasserstein(scores["R1"], scores["R2"]),
        "R0_R1_wasserstein": wasserstein(scores["R0"], scores["R1"]),
        "R0_R2_wasserstein": wasserstein(scores["R0"], scores["R2"]),
        "R1_R2_kl": kl_divergence_hist(scores["R1"], scores["R2"], args.bins),
        "R0_R1_kl": kl_divergence_hist(scores["R0"], scores["R1"], args.bins),
        "R0_R2_kl": kl_divergence_hist(scores["R0"], scores["R2"], args.bins),
    }

    counts = {
        "R0": int((regimes == "R0").sum()),
        "R1": int((regimes == "R1").sum()),
        "R2": int((regimes == "R2").sum()),
        "ALL": int(len(df)),
    }

    phi_sep = phi_separation_report(phi, regimes)
    stability = window_stability_report(df)
    gates = gate_distribution(df)

    regime_assignments = write_regime_assignments(out_dir, df)

    phi_paths: Dict[str, str] = {}
    if args.write_phi_matrices:
        phi_paths = write_phi_matrices(out_dir, phi, regimes)

    report = {
        "version": VERSION,
        "purpose": "empirical_geometry_measurement_over_existing_v064_ranked_background_outputs",
        "ranked_file": str(ranked_file),
        "out_dir": str(out_dir),
        "boundary": {
            "no_model_loading": True,
            "no_retraining": True,
            "no_feature_changes": True,
            "no_gate_changes": True,
            "no_auth_txt_scan": True,
            "no_redteam_validation": True,
        },
        "regime_definition": {
            "mode": "rank_based",
            "R2": f"geom_rank <= {args.top_r2}",
            "R1": f"{args.top_r2} < geom_rank <= {args.r1_end}",
            "R0": f"geom_rank > {args.r1_end}",
            "note": "Regimes are empirical diagnostic partitions over existing v0.6.4 ranking, not new model labels.",
        },
        "counts": counts,
        "score_density": density,
        "boundary_thickness": boundary,
        "curvature_proxy": curvature,
        "phi_centroid_separation": phi_sep,
        "stability": stability,
        "gate_distribution_by_regime": gates,
        "outputs": {
            "regime_assignments_csv": regime_assignments,
            "phi_matrices": phi_paths,
        },
    }

    return report


def write_text_report(path: Path, report: Dict[str, Any]) -> None:
    counts = report["counts"]
    boundary = report["boundary_thickness"]
    curv = report["curvature_proxy"]
    stability = report["stability"]

    lines: List[str] = []
    lines.append("SRIA RT v1.2 Geometry Measurement Report")
    lines.append("=" * 80)
    lines.append(f"ranked_file: {report['ranked_file']}")
    lines.append("scope: empirical diagnostics over existing v0.6.4 ranked background outputs")
    lines.append("boundary: no model loading, no retraining, no feature/gate changes, no auth.txt scan")
    lines.append("")
    lines.append("Regime definition:")
    for k, v in report["regime_definition"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Counts:")
    lines.append(f"  R0: {counts['R0']:,}")
    lines.append(f"  R1: {counts['R1']:,}")
    lines.append(f"  R2: {counts['R2']:,}")
    lines.append(f"  ALL: {counts['ALL']:,}")
    lines.append("")
    lines.append("Boundary thickness / distribution separation:")
    for k, v in boundary.items():
        lines.append(f"  {k}: {v:.12g}")
    lines.append("")
    lines.append("Curvature proxy:")
    for regime in ["R0", "R1", "R2", "ALL"]:
        c = curv.get(regime, {})
        lines.append(
            f"  {regime}: mean_abs={safe_float(c.get('mean_abs_curvature')):.12g} "
            f"max_abs={safe_float(c.get('max_abs_curvature')):.12g} "
            f"p99_abs={safe_float(c.get('p99_abs_curvature')):.12g}"
        )
    lines.append("")
    lines.append("Window stability:")
    if stability.get("available"):
        lines.append(f"  score_mean_std_across_windows: {safe_float(stability.get('score_mean_std_across_windows')):.12g}")
        lines.append(f"  score_p99_std_across_windows: {safe_float(stability.get('score_p99_std_across_windows')):.12g}")
        lines.append(f"  score_max_std_across_windows: {safe_float(stability.get('score_max_std_across_windows')):.12g}")
    else:
        lines.append(f"  unavailable: {stability.get('reason', '')}")
    lines.append("")
    lines.append("Outputs:")
    for k, v in report["outputs"].items():
        lines.append(f"  {k}: {v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v1.2 geometry measurement over v0.6.4 ranked outputs")
    p.add_argument("--ranked-dir", required=True, help="Directory containing v064 ranked outputs")
    p.add_argument("--out-dir", required=True, help="Output directory for geometry measurement")
    p.add_argument("--all-ranked-file", default=DEFAULT_ALL_RANKED, help="All-ranked aggregate CSV filename")
    p.add_argument("--top-r2", type=int, default=100, help="R2 = ranks <= this value")
    p.add_argument("--r1-end", type=int, default=5000, help="R1 = ranks > top-r2 and <= r1-end")
    p.add_argument("--bins", type=int, default=50, help="Histogram bins for density/KL")
    p.add_argument("--sample-limit", type=int, default=0, help="Optional row limit for smoke testing; 0 means all")
    p.add_argument("--write-phi-matrices", action="store_true", help="Write phi_matrix_R0/R1/R2 CSV files")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    ranked_dir = Path(args.ranked_dir)
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    ranked_file = ranked_dir / args.all_ranked_file
    df = load_ranked_csv(ranked_file, sample_limit=args.sample_limit)
    df = assign_regimes_by_rank(df, top_r2=args.top_r2, r1_end=args.r1_end)
    phi = build_phi_dataframe(df)

    report = build_report(df, phi, ranked_file, out_dir, args)

    json_path = out_dir / "v1_2_geometry_report.json"
    txt_path = out_dir / "v1_2_geometry_report.txt"

    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_text_report(txt_path, report)

    print("=" * 80)
    print("SRIA RT v1.2 Geometry Measurement Complete")
    print("=" * 80)
    print(f"Ranked file: {ranked_file}")
    print(f"Rows measured: {len(df):,}")
    print(f"R0 count: {report['counts']['R0']:,}")
    print(f"R1 count: {report['counts']['R1']:,}")
    print(f"R2 count: {report['counts']['R2']:,}")
    print(f"Wrote JSON report: {json_path}")
    print(f"Wrote text report: {txt_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()
