#!/usr/bin/env python3
r"""
SRIA RT v0.6.1b - Profile-Based Background Window Selection

Purpose:
  Select auditable negative-background windows from the compact auth-time
  profile created by v0.6.1a, without scanning auth.txt.

Typical CMD use from F:\SRIA\SRIA_RT_v01:
  py sria_rt_v061b_select_background_windows_from_profile.py --profile-csv v061a_auth_time_profile_full\v061a_auth_time_profile.csv --redteam-file redteam.txt --out-dir v061b_background_windows --tier B --window-duration 3600 --exclusion-margin 3600 --min-auth-lines 1000

Design rules:
  - No auth.txt scan.
  - No SRIA detection.
  - No model loading.
  - Deterministic selection.
  - Exclude red-team neighborhoods.
  - Select windows across early / middle / late profile bands.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


BANDS = ("early", "middle", "late")


@dataclass
class ProfileBucket:
    bucket_start: int
    bucket_end: int
    bucket_size: int
    auth_line_count: int


@dataclass
class RedteamEvent:
    event_time: int
    raw: str


@dataclass
class ExcludedNeighborhood:
    redteam_time: int
    excluded_start: int
    excluded_end: int
    exclusion_margin: int


@dataclass
class CandidateWindow:
    window_id: str
    tier: str
    band: str
    start_time: int
    end_time: int
    duration: int
    auth_line_count: int
    bucket_count: int
    nearest_redteam_distance: Optional[int]
    selection_reason: str
    profile_source: str
    status: str
    density_rank_in_band: Optional[int]
    density_percentile_in_band: Optional[float]


@dataclass
class Manifest:
    script: str
    version: str
    profile_csv: str
    redteam_file: str
    out_dir: str
    tier: str
    window_duration: int
    stride: int
    exclusion_margin: int
    min_auth_lines: int
    windows_per_band: Dict[str, int]
    profile_time_min: Optional[int]
    profile_time_max: Optional[int]
    profile_buckets_loaded: int
    redteam_events_loaded: int
    excluded_neighborhoods: int
    candidates_considered: int
    candidates_eligible: int
    windows_selected: int
    band_counts_selected: Dict[str, int]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select auditable SRIA RT negative-background windows from a compact auth-time profile."
    )
    parser.add_argument("--profile-csv", required=True, help="v061a auth time profile CSV")
    parser.add_argument("--redteam-file", required=True, help="LANL redteam.txt file")
    parser.add_argument("--out-dir", required=True, help="Output directory")
    parser.add_argument("--tier", choices=["A", "B", "custom"], default="B", help="Tier A selects 1 per band, Tier B selects 3 per band")
    parser.add_argument("--window-duration", type=int, default=3600, help="Window duration in seconds")
    parser.add_argument("--stride", type=int, default=3600, help="Candidate window stride in seconds")
    parser.add_argument("--exclusion-margin", type=int, default=3600, help="Seconds around redteam events to exclude")
    parser.add_argument("--min-auth-lines", type=int, default=1000, help="Minimum auth lines required in a selected window")
    parser.add_argument("--windows-per-band", default=None, help="For --tier custom, comma list like early:2,middle:2,late:2")
    parser.add_argument("--density-target-quantile", type=float, default=0.75, help="Prefer moderate-high density near this quantile within each band")
    parser.add_argument("--min-center-separation", type=int, default=3600, help="Minimum center-time separation between selected windows in same band")
    return parser.parse_args()


def parse_int(value: str) -> Optional[int]:
    try:
        return int(value.strip())
    except Exception:
        return None


def load_profile(path: Path) -> List[ProfileBucket]:
    buckets: List[ProfileBucket] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        required = {"bucket_start", "bucket_end", "bucket_size", "auth_line_count"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"Profile CSV must contain columns: {sorted(required)}")
        for row in reader:
            start = parse_int(row.get("bucket_start", ""))
            end = parse_int(row.get("bucket_end", ""))
            size = parse_int(row.get("bucket_size", ""))
            count = parse_int(row.get("auth_line_count", ""))
            if start is None or end is None or size is None or count is None:
                continue
            buckets.append(ProfileBucket(start, end, size, count))
    buckets.sort(key=lambda b: (b.bucket_start, b.bucket_end))
    return buckets


def load_redteam_events(path: Path) -> List[RedteamEvent]:
    events: List[RedteamEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            if not raw:
                continue
            first = raw.split(",", 1)[0]
            t = parse_int(first)
            if t is None:
                continue
            events.append(RedteamEvent(event_time=t, raw=raw))
    events.sort(key=lambda e: e.event_time)
    return events


def build_exclusions(events: Sequence[RedteamEvent], margin: int) -> List[ExcludedNeighborhood]:
    return [
        ExcludedNeighborhood(
            redteam_time=e.event_time,
            excluded_start=e.event_time - margin,
            excluded_end=e.event_time + margin,
            exclusion_margin=margin,
        )
        for e in events
    ]


def overlaps_exclusion(start: int, end: int, exclusions: Sequence[ExcludedNeighborhood]) -> bool:
    # Half-open window [start, end). Exclusion is inclusive-ish [excluded_start, excluded_end].
    for ex in exclusions:
        if start < ex.excluded_end and end > ex.excluded_start:
            return True
    return False


def nearest_redteam_distance(start: int, end: int, events: Sequence[RedteamEvent]) -> Optional[int]:
    if not events:
        return None
    best: Optional[int] = None
    for e in events:
        t = e.event_time
        if start <= t < end:
            d = 0
        elif t < start:
            d = start - t
        else:
            d = t - end
        if best is None or d < best:
            best = d
    return best


def band_for_center(center: float, t_min: int, t_max: int) -> str:
    if t_max <= t_min:
        return "middle"
    a = t_min + (t_max - t_min) / 3.0
    b = t_min + 2.0 * (t_max - t_min) / 3.0
    if center < a:
        return "early"
    if center < b:
        return "middle"
    return "late"


def windows_per_band_from_args(args: argparse.Namespace) -> Dict[str, int]:
    if args.tier == "A":
        return {"early": 1, "middle": 1, "late": 1}
    if args.tier == "B":
        return {"early": 3, "middle": 3, "late": 3}
    if not args.windows_per_band:
        raise ValueError("--tier custom requires --windows-per-band early:N,middle:N,late:N")
    out = {"early": 0, "middle": 0, "late": 0}
    for part in args.windows_per_band.split(","):
        key, value = part.split(":", 1)
        key = key.strip().lower()
        if key not in out:
            raise ValueError(f"Unknown band in --windows-per-band: {key}")
        out[key] = int(value.strip())
    return out


def count_profile_lines_for_window(start: int, end: int, buckets: Sequence[ProfileBucket]) -> Tuple[int, int]:
    total = 0
    used = 0
    for b in buckets:
        if b.bucket_end <= start:
            continue
        if b.bucket_start >= end:
            break
        overlap_start = max(start, b.bucket_start)
        overlap_end = min(end, b.bucket_end)
        if overlap_end <= overlap_start:
            continue
        # If a candidate slices through a bucket, prorate by overlap fraction.
        fraction = (overlap_end - overlap_start) / max(1, (b.bucket_end - b.bucket_start))
        total += int(round(b.auth_line_count * fraction))
        used += 1
    return total, used


def percentile_rank(value: int, sorted_values: Sequence[int]) -> float:
    if not sorted_values:
        return 0.0
    less_or_equal = 0
    for v in sorted_values:
        if v <= value:
            less_or_equal += 1
        else:
            break
    return less_or_equal / len(sorted_values)


def build_candidates(
    buckets: Sequence[ProfileBucket],
    events: Sequence[RedteamEvent],
    exclusions: Sequence[ExcludedNeighborhood],
    profile_source: str,
    tier: str,
    window_duration: int,
    stride: int,
    min_auth_lines: int,
) -> Tuple[List[CandidateWindow], int]:
    if not buckets:
        return [], 0
    t_min = min(b.bucket_start for b in buckets)
    t_max = max(b.bucket_end for b in buckets)
    raw_considered = 0
    raw: List[CandidateWindow] = []
    start = t_min
    while start + window_duration <= t_max:
        end = start + window_duration
        raw_considered += 1
        count, bucket_count = count_profile_lines_for_window(start, end, buckets)
        center = (start + end) / 2.0
        band = band_for_center(center, t_min, t_max)
        nearest = nearest_redteam_distance(start, end, events)
        excluded = overlaps_exclusion(start, end, exclusions)
        status = "eligible"
        reason_parts = ["profile_based_selection", f"band={band}"]
        if excluded:
            status = "excluded_redteam_neighborhood"
            reason_parts.append("excluded_by_redteam_margin")
        elif count < min_auth_lines:
            status = "below_min_auth_lines"
            reason_parts.append("below_min_auth_lines")
        else:
            reason_parts.append("outside_redteam_margin")
            reason_parts.append("sufficient_auth_volume")
        raw.append(
            CandidateWindow(
                window_id="",
                tier=tier,
                band=band,
                start_time=start,
                end_time=end,
                duration=window_duration,
                auth_line_count=count,
                bucket_count=bucket_count,
                nearest_redteam_distance=nearest,
                selection_reason=";".join(reason_parts),
                profile_source=profile_source,
                status=status,
                density_rank_in_band=None,
                density_percentile_in_band=None,
            )
        )
        start += stride

    # Populate density percentile/rank among eligible candidates per band.
    for band in BANDS:
        elig = [c for c in raw if c.band == band and c.status == "eligible"]
        values = sorted([c.auth_line_count for c in elig])
        ranked_desc = sorted(elig, key=lambda c: (-c.auth_line_count, c.start_time))
        rank_by_key = {(c.start_time, c.end_time): i + 1 for i, c in enumerate(ranked_desc)}
        for c in elig:
            c.density_rank_in_band = rank_by_key[(c.start_time, c.end_time)]
            c.density_percentile_in_band = percentile_rank(c.auth_line_count, values)
    return raw, raw_considered


def select_windows(
    candidates: Sequence[CandidateWindow],
    per_band: Dict[str, int],
    density_target_quantile: float,
    min_center_separation: int,
) -> List[CandidateWindow]:
    selected: List[CandidateWindow] = []
    sequence = 1
    for band in BANDS:
        needed = per_band.get(band, 0)
        elig = [c for c in candidates if c.band == band and c.status == "eligible"]
        # Prefer moderate-high density, not necessarily absolute densest.
        # Tie-breakers: higher auth volume, earlier time for reproducibility.
        elig.sort(
            key=lambda c: (
                abs((c.density_percentile_in_band or 0.0) - density_target_quantile),
                -c.auth_line_count,
                c.start_time,
            )
        )
        chosen_for_band: List[CandidateWindow] = []
        for c in elig:
            if len(chosen_for_band) >= needed:
                break
            center = (c.start_time + c.end_time) / 2.0
            ok = True
            for prev in chosen_for_band:
                prev_center = (prev.start_time + prev.end_time) / 2.0
                if abs(center - prev_center) < min_center_separation:
                    ok = False
                    break
            if not ok:
                continue
            c.window_id = f"bg_{sequence:03d}"
            c.selection_reason += f";density_target_quantile={density_target_quantile};deterministic_band_selection"
            chosen_for_band.append(c)
            selected.append(c)
            sequence += 1
        # If separation prevented filling, fill deterministically regardless of separation.
        if len(chosen_for_band) < needed:
            already = {(c.start_time, c.end_time) for c in chosen_for_band}
            for c in elig:
                if len(chosen_for_band) >= needed:
                    break
                if (c.start_time, c.end_time) in already:
                    continue
                c.window_id = f"bg_{sequence:03d}"
                c.selection_reason += f";density_target_quantile={density_target_quantile};deterministic_band_fill"
                chosen_for_band.append(c)
                selected.append(c)
                sequence += 1
    return selected


def write_windows_csv(path: Path, windows: Sequence[CandidateWindow]) -> None:
    fieldnames = list(asdict(windows[0]).keys()) if windows else [
        "window_id", "tier", "band", "start_time", "end_time", "duration",
        "auth_line_count", "bucket_count", "nearest_redteam_distance",
        "selection_reason", "profile_source", "status", "density_rank_in_band",
        "density_percentile_in_band",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for w in windows:
            writer.writerow(asdict(w))


def write_exclusions_csv(path: Path, exclusions: Sequence[ExcludedNeighborhood]) -> None:
    fieldnames = ["redteam_time", "excluded_start", "excluded_end", "exclusion_margin"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for ex in exclusions:
            writer.writerow(asdict(ex))


def format_int(value: Optional[int]) -> str:
    if value is None:
        return "NA"
    return f"{value:,}"


def write_report(path: Path, manifest: Manifest, windows: Sequence[CandidateWindow], candidates: Sequence[CandidateWindow]) -> None:
    by_band: Dict[str, List[CandidateWindow]] = {band: [] for band in BANDS}
    for w in windows:
        by_band.setdefault(w.band, []).append(w)
    eligible_by_band = {band: len([c for c in candidates if c.band == band and c.status == "eligible"]) for band in BANDS}
    excluded_count = len([c for c in candidates if c.status == "excluded_redteam_neighborhood"])
    below_min_count = len([c for c in candidates if c.status == "below_min_auth_lines"])

    lines: List[str] = []
    lines.append("SRIA RT v0.6.1b Profile-Based Background Window Selection")
    lines.append("=" * 80)
    lines.append(f"profile_csv: {manifest.profile_csv}")
    lines.append(f"redteam_file: {manifest.redteam_file}")
    lines.append(f"out_dir: {manifest.out_dir}")
    lines.append(f"tier: {manifest.tier}")
    lines.append(f"window_duration: {manifest.window_duration}")
    lines.append(f"stride: {manifest.stride}")
    lines.append(f"exclusion_margin: {manifest.exclusion_margin}")
    lines.append(f"min_auth_lines: {manifest.min_auth_lines}")
    lines.append("analysis_scope: compact profile only; no auth.txt scan")
    lines.append("exclusions: no SRIA detection, no model loading, no scoring")
    lines.append("")
    lines.append("Profile summary:")
    lines.append(f"  profile_time_range: {manifest.profile_time_min} to {manifest.profile_time_max}")
    lines.append(f"  profile_buckets_loaded: {manifest.profile_buckets_loaded:,}")
    lines.append(f"  redteam_events_loaded: {manifest.redteam_events_loaded:,}")
    lines.append(f"  excluded_neighborhoods: {manifest.excluded_neighborhoods:,}")
    lines.append("")
    lines.append("Candidate summary:")
    lines.append(f"  candidates_considered: {manifest.candidates_considered:,}")
    lines.append(f"  candidates_eligible: {manifest.candidates_eligible:,}")
    lines.append(f"  excluded_redteam_neighborhood: {excluded_count:,}")
    lines.append(f"  below_min_auth_lines: {below_min_count:,}")
    lines.append(f"  eligible_by_band: {eligible_by_band}")
    lines.append("")
    lines.append("Selected windows:")
    if not windows:
        lines.append("  none")
    for w in windows:
        lines.append(
            f"  {w.window_id}: tier={w.tier} band={w.band} {w.start_time}-{w.end_time} "
            f"duration={w.duration} auth_lines={format_int(w.auth_line_count)} "
            f"buckets={w.bucket_count} nearest_redteam_distance={format_int(w.nearest_redteam_distance)} "
            f"density_percentile={w.density_percentile_in_band}"
        )
    lines.append("")
    lines.append("Selection policy:")
    lines.append("  Deterministic profile-based selection from early/middle/late bands.")
    lines.append("  Windows overlapping red-team exclusion neighborhoods are excluded.")
    lines.append("  Windows below minimum auth volume are excluded.")
    lines.append("  Within each band, selection prefers moderate-high density near the configured target quantile, not simply the densest windows.")
    lines.append("")
    lines.append("Outputs:")
    lines.append("  v061b_background_windows.csv")
    lines.append("  v061b_excluded_redteam_neighborhoods.csv")
    lines.append("  v061b_background_windows_manifest.json")
    lines.append("  v061b_background_window_selection_report.txt")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    profile_path = Path(args.profile_csv)
    redteam_path = Path(args.redteam_file)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SRIA RT v0.6.1b - Profile-Based Background Window Selection")
    print("=" * 80)
    print(f"Profile CSV: {profile_path}")
    print(f"Redteam file: {redteam_path}")
    print(f"Output dir: {out_dir}")
    print(f"Tier: {args.tier}")
    print(f"Window duration: {args.window_duration}")
    print(f"Stride: {args.stride}")
    print(f"Exclusion margin: {args.exclusion_margin}")
    print("NOTE: This script reads the compact profile only. It does not scan auth.txt.")
    print("NOTE: It does not run SRIA detection, load models, or score episodes.")
    print("=" * 80)

    per_band = windows_per_band_from_args(args)
    buckets = load_profile(profile_path)
    redteam_events = load_redteam_events(redteam_path)
    exclusions = build_exclusions(redteam_events, args.exclusion_margin)

    candidates, considered = build_candidates(
        buckets=buckets,
        events=redteam_events,
        exclusions=exclusions,
        profile_source=str(profile_path),
        tier=args.tier,
        window_duration=args.window_duration,
        stride=args.stride,
        min_auth_lines=args.min_auth_lines,
    )
    eligible = [c for c in candidates if c.status == "eligible"]
    selected = select_windows(
        candidates=candidates,
        per_band=per_band,
        density_target_quantile=args.density_target_quantile,
        min_center_separation=args.min_center_separation,
    )

    profile_time_min = min((b.bucket_start for b in buckets), default=None)
    profile_time_max = max((b.bucket_end for b in buckets), default=None)
    band_counts = {band: len([w for w in selected if w.band == band]) for band in BANDS}

    manifest = Manifest(
        script="sria_rt_v061b_select_background_windows_from_profile.py",
        version="0.6.1b",
        profile_csv=str(profile_path),
        redteam_file=str(redteam_path),
        out_dir=str(out_dir),
        tier=args.tier,
        window_duration=args.window_duration,
        stride=args.stride,
        exclusion_margin=args.exclusion_margin,
        min_auth_lines=args.min_auth_lines,
        windows_per_band=per_band,
        profile_time_min=profile_time_min,
        profile_time_max=profile_time_max,
        profile_buckets_loaded=len(buckets),
        redteam_events_loaded=len(redteam_events),
        excluded_neighborhoods=len(exclusions),
        candidates_considered=considered,
        candidates_eligible=len(eligible),
        windows_selected=len(selected),
        band_counts_selected=band_counts,
    )

    windows_path = out_dir / "v061b_background_windows.csv"
    exclusions_path = out_dir / "v061b_excluded_redteam_neighborhoods.csv"
    manifest_path = out_dir / "v061b_background_windows_manifest.json"
    report_path = out_dir / "v061b_background_window_selection_report.txt"

    write_windows_csv(windows_path, selected)
    write_exclusions_csv(exclusions_path, exclusions)
    manifest_path.write_text(json.dumps(asdict(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(report_path, manifest, selected, candidates)

    print("SRIA RT v0.6.1b Profile-Based Background Window Selection")
    print("=" * 80)
    print(f"profile_time_range: {profile_time_min} to {profile_time_max}")
    print(f"profile_buckets_loaded: {len(buckets):,}")
    print(f"redteam_events_loaded: {len(redteam_events):,}")
    print(f"candidates_considered: {considered:,}")
    print(f"candidates_eligible: {len(eligible):,}")
    print(f"windows_selected: {len(selected):,}")
    print("Selected windows:")
    for w in selected:
        print(
            f"  {w.window_id}: tier={w.tier} band={w.band} {w.start_time}-{w.end_time} "
            f"auth_lines={w.auth_line_count:,} nearest_redteam_distance={format_int(w.nearest_redteam_distance)}"
        )
    print("")
    print(f"Wrote windows: {windows_path}")
    print(f"Wrote exclusions: {exclusions_path}")
    print(f"Wrote manifest: {manifest_path}")
    print(f"Wrote report: {report_path}")


if __name__ == "__main__":
    main()
