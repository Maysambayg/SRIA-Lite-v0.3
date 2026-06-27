#!/usr/bin/env python3
r"""
sria_rt_v1_2_5_tail_triage_policy_simulation.py

SRIA RT v1.2.5 - Tail Triage Policy Simulation

Purpose:
- Simulate analyst review-order policies using existing v1.2.4 tail stratification assignments.
- Test whether subtype-aware ordering improves redteam-associated recovery at early review depths.
- Preserve the full high-tail queue. No subtype is suppressed or discarded.

Inputs:
  v1_2_4_tail_stratification_results\tail_stratification_assignments.csv

Boundary:
- No model loading.
- No retraining.
- No feature changes.
- No gate changes.
- No auth.txt scan.
- No new detection logic.
- Redteam labels are used only for evaluation of queue placement.
- Tail subtypes remain post-hoc diagnostic strata, not detection labels.

Recommended CMD:

  py sria_rt_v1_2_5_tail_triage_policy_simulation.py --assignments v1_2_4_tail_stratification_results\tail_stratification_assignments.csv --out-dir v1_2_5_tail_triage_policy_results
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
import pandas as pd


VERSION = "v1.2.5"

DEFAULT_DEPTHS = [25, 50, 100, 250, 500, 1000, 2500, 5000]

SUBTYPE_COMPACT = "compact_propagation_tail"
SUBTYPE_MIXED = "mixed_tail"
SUBTYPE_RESCUE = "fanout_rescue_tail"

POLICY_NAMES = [
    "A_score_only",
    "B_compact_first",
    "C_balanced_70_20_10",
    "D_compact_mixed_then_extreme_rescue",
    "E_two_lane_compact_plus_rescue",
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


def parse_depths(text: str) -> List[int]:
    if not text:
        return list(DEFAULT_DEPTHS)
    vals = []
    for part in text.split(","):
        part = part.strip()
        if part:
            vals.append(int(part))
    return sorted(set(vals))


def load_assignments(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Assignments CSV not found: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"Assignments CSV is empty: {path}")

    required = ["tail_group", "tail_subtype", "score"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Assignments CSV missing required columns: {missing}")

    df = df.copy()
    df["score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0.0)
    df["tail_group"] = df["tail_group"].astype(str)
    df["tail_subtype"] = df["tail_subtype"].astype(str)

    if "rank" in df.columns:
        df["rank"] = pd.to_numeric(df["rank"], errors="coerce").fillna(0).astype(int)
    else:
        df = df.sort_values("score", ascending=False).reset_index(drop=True)
        df["rank"] = np.arange(1, len(df) + 1)

    if "background_percentile" in df.columns:
        df["background_percentile"] = pd.to_numeric(
            df["background_percentile"], errors="coerce"
        ).fillna(0.0)
    else:
        df["background_percentile"] = 0.0

    df["is_redteam_eval"] = df["tail_group"].eq("redteam_associated")

    # Stable row id for traceability.
    df["triage_input_row"] = np.arange(1, len(df) + 1)
    return df


def sort_score_only(df: pd.DataFrame) -> pd.DataFrame:
    return df.sort_values(
        ["score", "background_percentile"],
        ascending=[False, False],
        kind="mergesort",
    ).reset_index(drop=True)


def sort_compact_first(df: pd.DataFrame) -> pd.DataFrame:
    priority = {
        SUBTYPE_COMPACT: 0,
        SUBTYPE_MIXED: 1,
        SUBTYPE_RESCUE: 2,
    }
    out = df.copy()
    out["_subtype_priority"] = out["tail_subtype"].map(priority).fillna(9).astype(int)
    out = out.sort_values(
        ["_subtype_priority", "score", "background_percentile"],
        ascending=[True, False, False],
        kind="mergesort",
    ).drop(columns=["_subtype_priority"])
    return out.reset_index(drop=True)


def proportional_round_robin(
    df: pd.DataFrame,
    proportions: Dict[str, int],
) -> pd.DataFrame:
    """
    Build full queue using weighted subtype slots.
    Does not drop any rows. If a subtype is exhausted, uses remaining highest score rows.
    """
    pools: Dict[str, deque] = {}
    for subtype in [SUBTYPE_COMPACT, SUBTYPE_MIXED, SUBTYPE_RESCUE]:
        g = df[df["tail_subtype"] == subtype].copy()
        g = sort_score_only(g)
        pools[subtype] = deque(g.to_dict(orient="records"))

    other = df[~df["tail_subtype"].isin(pools.keys())].copy()
    pools["__OTHER__"] = deque(sort_score_only(other).to_dict(orient="records"))

    pattern: List[str] = []
    for subtype, n in proportions.items():
        pattern.extend([subtype] * int(n))

    output: List[Dict[str, Any]] = []
    used_ids = set()
    total = len(df)

    while len(output) < total:
        progressed = False

        for subtype in pattern:
            if len(output) >= total:
                break

            q = pools.get(subtype)
            if q is not None:
                while q and q[0]["triage_input_row"] in used_ids:
                    q.popleft()
                if q:
                    row = q.popleft()
                    output.append(row)
                    used_ids.add(row["triage_input_row"])
                    progressed = True

        if len(output) >= total:
            break

        if not progressed:
            remaining = df[~df["triage_input_row"].isin(used_ids)].copy()
            if remaining.empty:
                break
            remaining = sort_score_only(remaining)
            for row in remaining.to_dict(orient="records"):
                if row["triage_input_row"] not in used_ids:
                    output.append(row)
                    used_ids.add(row["triage_input_row"])

    return pd.DataFrame(output).reset_index(drop=True)


def sort_compact_mixed_then_extreme_rescue(df: pd.DataFrame, rescue_override_threshold: float) -> pd.DataFrame:
    """
    Presentation policy:
      1. compact-propagation rows by score
      2. mixed rows by score
      3. fanout-rescue rows above override threshold by score
      4. remaining fanout-rescue rows by score
      5. any other remaining rows by score

    Nothing is dropped.
    """
    compact = sort_score_only(df[df["tail_subtype"] == SUBTYPE_COMPACT])
    mixed = sort_score_only(df[df["tail_subtype"] == SUBTYPE_MIXED])
    rescue = df[df["tail_subtype"] == SUBTYPE_RESCUE].copy()

    rescue_extreme = sort_score_only(rescue[rescue["score"] >= rescue_override_threshold])
    rescue_rest = sort_score_only(rescue[rescue["score"] < rescue_override_threshold])

    known = {SUBTYPE_COMPACT, SUBTYPE_MIXED, SUBTYPE_RESCUE}
    other = sort_score_only(df[~df["tail_subtype"].isin(known)])

    out = pd.concat([compact, mixed, rescue_extreme, rescue_rest, other], ignore_index=True)
    out = out.drop_duplicates(subset=["triage_input_row"], keep="first")
    return out.reset_index(drop=True)


def sort_two_lane(df: pd.DataFrame) -> pd.DataFrame:
    """
    Two-lane queue:
      Lane 1: compact-propagation + mixed, score ordered
      Lane 2: fanout-rescue, score ordered

    Interleave 2 from Lane 1, then 1 from Lane 2.
    Nothing is dropped.
    """
    lane1 = sort_score_only(df[df["tail_subtype"].isin([SUBTYPE_COMPACT, SUBTYPE_MIXED])])
    lane2 = sort_score_only(df[df["tail_subtype"] == SUBTYPE_RESCUE])
    other = sort_score_only(df[~df["tail_subtype"].isin([SUBTYPE_COMPACT, SUBTYPE_MIXED, SUBTYPE_RESCUE])])

    q1 = deque(lane1.to_dict(orient="records"))
    q2 = deque(lane2.to_dict(orient="records"))
    q3 = deque(other.to_dict(orient="records"))

    output: List[Dict[str, Any]] = []
    used = set()
    total = len(df)

    while len(output) < total:
        progressed = False

        for _ in range(2):
            if q1:
                row = q1.popleft()
                if row["triage_input_row"] not in used:
                    output.append(row)
                    used.add(row["triage_input_row"])
                    progressed = True

        if q2:
            row = q2.popleft()
            if row["triage_input_row"] not in used:
                output.append(row)
                used.add(row["triage_input_row"])
                progressed = True

        if not progressed:
            while q1:
                row = q1.popleft()
                if row["triage_input_row"] not in used:
                    output.append(row)
                    used.add(row["triage_input_row"])
            while q2:
                row = q2.popleft()
                if row["triage_input_row"] not in used:
                    output.append(row)
                    used.add(row["triage_input_row"])
            while q3:
                row = q3.popleft()
                if row["triage_input_row"] not in used:
                    output.append(row)
                    used.add(row["triage_input_row"])

        if len(output) >= total:
            break

    return pd.DataFrame(output).reset_index(drop=True)


def build_policy_queue(df: pd.DataFrame, policy: str, rescue_override_threshold: float) -> pd.DataFrame:
    if policy == "A_score_only":
        q = sort_score_only(df)
    elif policy == "B_compact_first":
        q = sort_compact_first(df)
    elif policy == "C_balanced_70_20_10":
        q = proportional_round_robin(
            df,
            proportions={
                SUBTYPE_COMPACT: 7,
                SUBTYPE_MIXED: 2,
                SUBTYPE_RESCUE: 1,
            },
        )
    elif policy == "D_compact_mixed_then_extreme_rescue":
        q = sort_compact_mixed_then_extreme_rescue(df, rescue_override_threshold)
    elif policy == "E_two_lane_compact_plus_rescue":
        q = sort_two_lane(df)
    else:
        raise ValueError(f"Unknown policy: {policy}")

    q = q.copy()
    q["policy"] = policy
    q["policy_rank"] = np.arange(1, len(q) + 1)
    return q


def summarize_prefix(q: pd.DataFrame, depth: int, total_redteam: int) -> Dict[str, Any]:
    top = q.head(depth).copy()
    red_count = int(top["is_redteam_eval"].sum())
    bg_count = int(len(top) - red_count)

    subtype_counts = Counter(top["tail_subtype"].astype(str).tolist())
    group_counts = Counter(top["tail_group"].astype(str).tolist())

    unique_sources = int(top["source"].nunique()) if "source" in top.columns else 0
    unique_users = int(top["user"].nunique()) if "user" in top.columns else 0

    out: Dict[str, Any] = {
        "policy": str(q["policy"].iloc[0]) if len(q) else "",
        "depth": int(depth),
        "rows": int(len(top)),
        "redteam_count": red_count,
        "redteam_recall": float(red_count / total_redteam) if total_redteam else 0.0,
        "background_count": bg_count,
        "background_share": float(bg_count / len(top)) if len(top) else 0.0,
        "mean_score": safe_float(top["score"].mean()) if len(top) else 0.0,
        "min_score": safe_float(top["score"].min()) if len(top) else 0.0,
        "max_score": safe_float(top["score"].max()) if len(top) else 0.0,
        "unique_sources": unique_sources,
        "unique_users": unique_users,
        "compact_count": int(subtype_counts.get(SUBTYPE_COMPACT, 0)),
        "mixed_count": int(subtype_counts.get(SUBTYPE_MIXED, 0)),
        "fanout_rescue_count": int(subtype_counts.get(SUBTYPE_RESCUE, 0)),
        "compact_share": float(subtype_counts.get(SUBTYPE_COMPACT, 0) / len(top)) if len(top) else 0.0,
        "mixed_share": float(subtype_counts.get(SUBTYPE_MIXED, 0) / len(top)) if len(top) else 0.0,
        "fanout_rescue_share": float(subtype_counts.get(SUBTYPE_RESCUE, 0) / len(top)) if len(top) else 0.0,
        "group_counts": dict(group_counts),
    }

    return out


def redteam_rank_stats(q: pd.DataFrame) -> Dict[str, Any]:
    rt = q[q["is_redteam_eval"]].copy()
    if rt.empty:
        return {
            "redteam_count": 0,
        }

    ranks = rt["policy_rank"].to_numpy(dtype=float)
    return {
        "redteam_count": int(len(rt)),
        "first_redteam_rank": int(np.min(ranks)),
        "median_redteam_rank": float(np.percentile(ranks, 50)),
        "p75_redteam_rank": float(np.percentile(ranks, 75)),
        "p90_redteam_rank": float(np.percentile(ranks, 90)),
        "last_redteam_rank": int(np.max(ranks)),
        "mean_redteam_rank": float(np.mean(ranks)),
    }


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(fields), extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text_report(path: Path, report: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("SRIA RT v1.2.5 Tail Triage Policy Simulation Report")
    lines.append("=" * 80)
    lines.append("")
    lines.append("Purpose:")
    lines.append("  Simulate subtype-aware analyst queue ordering over the existing v1.2.4 high-tail assignments.")
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
    lines.append("Configuration:")
    for k, v in report["configuration"].items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Policy rank statistics:")
    for policy, stats in report["redteam_rank_stats_by_policy"].items():
        lines.append(f"  {policy}:")
        for k, v in stats.items():
            lines.append(f"    {k}: {v}")
    lines.append("")
    lines.append("Depth results:")
    for row in report["depth_results"]:
        lines.append(
            f"  {row['policy']} @ {row['depth']}: "
            f"redteam={row['redteam_count']}, "
            f"recall={row['redteam_recall']:.6f}, "
            f"background={row['background_count']}, "
            f"compact={row['compact_count']}, "
            f"mixed={row['mixed_count']}, "
            f"fanout_rescue={row['fanout_rescue_count']}, "
            f"mean_score={row['mean_score']:.8g}"
        )
    lines.append("")
    lines.append("Interpretation boundary:")
    lines.append("  These policies change presentation order only.")
    lines.append("  No episodes are removed.")
    lines.append("  Tail subtypes remain post-hoc diagnostics, not detection labels.")
    lines.append("  Redteam labels are used only for evaluation.")
    lines.append("  This does not establish production precision.")
    lines.append("")
    lines.append("Outputs:")
    for k, v in report["outputs"].items():
        lines.append(f"  {k}: {v}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SRIA RT v1.2.5 Tail Triage Policy Simulation")
    p.add_argument("--assignments", required=True, help="v1.2.4 tail_stratification_assignments.csv")
    p.add_argument("--out-dir", required=True, help="Output directory")
    p.add_argument("--depths", default="25,50,100,250,500,1000,2500,5000", help="Comma-separated review depths")
    p.add_argument("--rescue-override-threshold", type=float, default=0.0757536001303672, help="Extreme rescue override threshold; default background Top100 min score")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    assignments_path = Path(args.assignments)
    out_dir = Path(args.out_dir)
    ensure_dir(out_dir)

    depths = parse_depths(args.depths)

    print("=" * 80)
    print("SRIA RT v1.2.5 - Tail Triage Policy Simulation")
    print("=" * 80)
    print(f"Assignments:               {assignments_path}")
    print(f"Output dir:                {out_dir}")
    print(f"Depths:                    {depths}")
    print(f"Rescue override threshold: {args.rescue_override_threshold}")
    print("=" * 80)

    df = load_assignments(assignments_path)
    total_redteam = int(df["is_redteam_eval"].sum())

    if total_redteam <= 0:
        raise ValueError("No redteam_associated rows found in assignments file.")

    policy_queues: Dict[str, pd.DataFrame] = {}
    depth_rows: List[Dict[str, Any]] = []
    rank_stats: Dict[str, Any] = {}

    queue_dir = out_dir / "policy_queues"
    ensure_dir(queue_dir)

    for policy in POLICY_NAMES:
        q = build_policy_queue(df, policy, rescue_override_threshold=args.rescue_override_threshold)
        policy_queues[policy] = q

        queue_path = queue_dir / f"{policy}_queue.csv"
        q.to_csv(queue_path, index=False)

        rank_stats[policy] = redteam_rank_stats(q)

        for depth in depths:
            depth_rows.append(summarize_prefix(q, depth, total_redteam))

    depth_csv = out_dir / "tail_triage_depth_results.csv"
    fields = [
        "policy",
        "depth",
        "rows",
        "redteam_count",
        "redteam_recall",
        "background_count",
        "background_share",
        "mean_score",
        "min_score",
        "max_score",
        "unique_sources",
        "unique_users",
        "compact_count",
        "mixed_count",
        "fanout_rescue_count",
        "compact_share",
        "mixed_share",
        "fanout_rescue_share",
        "group_counts",
    ]
    write_csv(depth_csv, depth_rows, fields)

    rank_csv = out_dir / "tail_triage_redteam_rank_stats.csv"
    rank_rows = []
    for policy, stats in rank_stats.items():
        row = {"policy": policy}
        row.update(stats)
        rank_rows.append(row)
    write_csv(
        rank_csv,
        rank_rows,
        [
            "policy",
            "redteam_count",
            "first_redteam_rank",
            "median_redteam_rank",
            "p75_redteam_rank",
            "p90_redteam_rank",
            "last_redteam_rank",
            "mean_redteam_rank",
        ],
    )

    subtype_counts = (
        df.groupby(["tail_group", "tail_subtype"], sort=True)
        .size()
        .reset_index(name="count")
        .to_dict(orient="records")
    )

    report: Dict[str, Any] = {
        "version": VERSION,
        "purpose": "tail_triage_policy_simulation_over_existing_v124_assignments",
        "inputs": {
            "assignments": str(assignments_path),
        },
        "boundary": {
            "no_model_loading": True,
            "no_retraining": True,
            "no_feature_changes": True,
            "no_gate_changes": True,
            "no_auth_txt_scan": True,
            "no_new_detection_logic": True,
            "policies_change_presentation_order_only": True,
            "no_episode_suppression": True,
            "redteam_labels_used_only_for_evaluation": True,
        },
        "configuration": {
            "depths": depths,
            "policies": POLICY_NAMES,
            "rescue_override_threshold": args.rescue_override_threshold,
            "policy_A": "pure score descending",
            "policy_B": "compact-propagation first, then mixed, then fanout-rescue; score descending within subtype",
            "policy_C": "70 compact / 20 mixed / 10 fanout-rescue proportional interleave",
            "policy_D": "compact, mixed, extreme fanout-rescue above override threshold, remaining fanout-rescue",
            "policy_E": "two-lane interleave: 2 compact_or_mixed then 1 fanout-rescue",
        },
        "counts": {
            "input_rows": int(len(df)),
            "redteam_eval_rows": total_redteam,
            "background_rows": int(len(df) - total_redteam),
            "subtype_group_counts": subtype_counts,
        },
        "redteam_rank_stats_by_policy": rank_stats,
        "depth_results": depth_rows,
        "outputs": {
            "depth_results_csv": str(depth_csv),
            "redteam_rank_stats_csv": str(rank_csv),
            "policy_queues_dir": str(queue_dir),
        },
    }

    json_path = out_dir / "v1_2_5_tail_triage_policy_report.json"
    txt_path = out_dir / "v1_2_5_tail_triage_policy_report.txt"

    write_json(json_path, report)
    write_text_report(txt_path, report)

    print("Run complete.")
    print(f"Input rows:        {len(df):,}")
    print(f"Redteam rows:      {total_redteam:,}")
    print(f"Background rows:   {len(df) - total_redteam:,}")
    print(f"Wrote JSON report: {json_path}")
    print(f"Wrote text report: {txt_path}")
    print(f"Wrote depth CSV:   {depth_csv}")
    print("=" * 80)


if __name__ == "__main__":
    main()
