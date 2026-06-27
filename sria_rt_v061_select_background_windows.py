#!/usr/bin/env python3
"""
SRIA RT v0.6.1 - Auditable Background Window Selection

Purpose:
  Select candidate non-red-team background windows for SRIA RT negative-background
  characterization. This script does not run SRIA detection, does not load models,
  and does not score episodes. It produces an auditable manifest of background
  windows and excluded red-team neighborhoods.

Typical CMD use from F:\SRIA\SRIA_RT_v01:

  py sria_rt_v061_select_background_windows.py --auth-file auth.txt --redteam-file redteam.txt --out-dir v061_background_windows --window-duration 3600 --exclusion-margin 3600 --target-windows 5 --stride 3600

Notes:
  - LANL auth-like rows are expected to start with integer time in the first CSV field.
  - redteam.txt rows are expected to include integer time in the first CSV field.
  - Estimated auth-line counts are based on a streaming pass over auth.txt.
  - Windows overlapping red-team exclusion neighborhoods are rejected.
"""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


@dataclass
class RedteamEvent:
    time: int
    raw: str


@dataclass
class ExcludedNeighborhood:
    redteam_time: int
    start_time: int
    end_time: int
    margin: int


@dataclass
class CandidateWindow:
    window_id: str
    start_time: int
    end_time: int
    duration: int
    selection_reason: str
    distance_from_nearest_redteam_event: Optional[int]
    estimated_auth_line_count: int
    redteam_exclusion_margin: int
    status: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Select auditable non-red-team background windows for SRIA RT v0.6.1."
    )
    parser.add_argument("--auth-file", required=True, help="Path to auth.txt or auth-like file.")
    parser.add_argument("--redteam-file", required=True, help="Path to LANL redteam.txt or equivalent.")
    parser.add_argument("--out-dir", required=True, help="Output directory for manifest and CSV files.")
    parser.add_argument("--window-duration", type=int, default=3600, help="Window duration in seconds.")
    parser.add_argument("--exclusion-margin", type=int, default=3600, help="Seconds to exclude around each red-team event.")
    parser.add_argument("--target-windows", type=int, default=5, help="Number of background windows to select.")
    parser.add_argument("--stride", type=int, default=3600, help="Candidate window stride in seconds.")
    parser.add_argument("--min-auth-lines", type=int, default=1000, help="Minimum estimated auth lines required for selected windows.")
    parser.add_argument("--max-auth-lines", type=int, default=0, help="Optional max auth lines per window; 0 disables.")
    parser.add_argument("--sample-limit-lines", type=int, default=0, help="Optional auth line scan limit for smoke testing; 0 scans full file.")
    return parser.parse_args()


def parse_first_int(line: str) -> Optional[int]:
    if not line:
        return None
    first = line.split(",", 1)[0].strip()
    try:
        return int(first)
    except ValueError:
        return None


def load_redteam_events(path: Path) -> List[RedteamEvent]:
    events: List[RedteamEvent] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            t = parse_first_int(raw)
            if t is not None:
                events.append(RedteamEvent(time=t, raw=raw))
    events.sort(key=lambda e: e.time)
    return events


def build_excluded_neighborhoods(events: List[RedteamEvent], margin: int) -> List[ExcludedNeighborhood]:
    return [
        ExcludedNeighborhood(
            redteam_time=e.time,
            start_time=max(0, e.time - margin),
            end_time=e.time + margin,
            margin=margin,
        )
        for e in events
    ]


def overlaps_any_exclusion(start: int, end: int, neighborhoods: List[ExcludedNeighborhood]) -> bool:
    for n in neighborhoods:
        if start < n.end_time and end > n.start_time:
            return True
    return False


def nearest_redteam_distance(start: int, end: int, events: List[RedteamEvent]) -> Optional[int]:
    if not events:
        return None
    best: Optional[int] = None
    for e in events:
        if start <= e.time <= end:
            d = 0
        elif e.time < start:
            d = start - e.time
        else:
            d = e.time - end
        if best is None or d < best:
            best = d
    return best


def scan_auth_times(path: Path, sample_limit_lines: int = 0) -> Tuple[Optional[int], Optional[int], List[int]]:
    min_time: Optional[int] = None
    max_time: Optional[int] = None
    times: List[int] = []
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            count += 1
            if sample_limit_lines and count > sample_limit_lines:
                break
            t = parse_first_int(line)
            if t is None:
                continue
            times.append(t)
            if min_time is None or t < min_time:
                min_time = t
            if max_time is None or t > max_time:
                max_time = t
    return min_time, max_time, times


def count_times_in_window(times: List[int], start: int, end: int) -> int:
    # Straight scan is acceptable for Tier A/Tier B selection. This is not the detector run.
    return sum(1 for t in times if start <= t < end)


def select_windows(
    min_time: int,
    max_time: int,
    times: List[int],
    redteam_events: List[RedteamEvent],
    neighborhoods: List[ExcludedNeighborhood],
    window_duration: int,
    stride: int,
    target_windows: int,
    min_auth_lines: int,
    max_auth_lines: int,
    exclusion_margin: int,
) -> List[CandidateWindow]:
    selected: List[CandidateWindow] = []
    candidate_start = min_time
    candidate_index = 0

    while candidate_start + window_duration <= max_time and len(selected) < target_windows:
        candidate_end = candidate_start + window_duration
        candidate_index += 1

        if overlaps_any_exclusion(candidate_start, candidate_end, neighborhoods):
            candidate_start += stride
            continue

        auth_count = count_times_in_window(times, candidate_start, candidate_end)
        if auth_count < min_auth_lines:
            candidate_start += stride
            continue
        if max_auth_lines and auth_count > max_auth_lines:
            candidate_start += stride
            continue

        distance = nearest_redteam_distance(candidate_start, candidate_end, redteam_events)
        window_id = f"bg_{len(selected) + 1:03d}"
        reason = "non-red-team background window; outside exclusion neighborhoods; meets auth-line density constraint"
        selected.append(
            CandidateWindow(
                window_id=window_id,
                start_time=candidate_start,
                end_time=candidate_end,
                duration=window_duration,
                selection_reason=reason,
                distance_from_nearest_redteam_event=distance,
                estimated_auth_line_count=auth_count,
                redteam_exclusion_margin=exclusion_margin,
                status="selected",
            )
        )
        candidate_start += stride

    return selected


def write_csv(path: Path, rows: List[dict], fieldnames: List[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    args = parse_args()
    auth_path = Path(args.auth_file)
    redteam_path = Path(args.redteam_file)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("SRIA RT v0.6.1 - Auditable Background Window Selection")
    print("=" * 80)
    print(f"Auth file: {auth_path}")
    print(f"Redteam file: {redteam_path}")
    print(f"Output dir: {out_dir}")
    print(f"Window duration: {args.window_duration}")
    print(f"Exclusion margin: {args.exclusion_margin}")
    print(f"Target windows: {args.target_windows}")
    print(f"Stride: {args.stride}")
    print("NOTE: This script only selects auditable background windows.")
    print("NOTE: It does not run SRIA detection, load models, or score episodes.")
    print("=" * 80)

    if not auth_path.exists():
        raise FileNotFoundError(f"Auth file not found: {auth_path}")
    if not redteam_path.exists():
        raise FileNotFoundError(f"Redteam file not found: {redteam_path}")

    redteam_events = load_redteam_events(redteam_path)
    neighborhoods = build_excluded_neighborhoods(redteam_events, args.exclusion_margin)
    print(f"Loaded redteam events: {len(redteam_events):,}")
    print(f"Built excluded neighborhoods: {len(neighborhoods):,}")

    min_time, max_time, times = scan_auth_times(auth_path, args.sample_limit_lines)
    if min_time is None or max_time is None:
        raise RuntimeError("Could not parse auth times from auth file.")
    print(f"Scanned auth timestamps: {len(times):,}")
    print(f"Auth time range: {min_time} to {max_time}")

    selected = select_windows(
        min_time=min_time,
        max_time=max_time,
        times=times,
        redteam_events=redteam_events,
        neighborhoods=neighborhoods,
        window_duration=args.window_duration,
        stride=args.stride,
        target_windows=args.target_windows,
        min_auth_lines=args.min_auth_lines,
        max_auth_lines=args.max_auth_lines,
        exclusion_margin=args.exclusion_margin,
    )

    window_rows = [asdict(w) for w in selected]
    exclusion_rows = [asdict(n) for n in neighborhoods]

    windows_csv = out_dir / "v061_background_windows.csv"
    exclusions_csv = out_dir / "v061_excluded_redteam_neighborhoods.csv"
    manifest_json = out_dir / "v061_background_windows_manifest.json"
    report_txt = out_dir / "v061_background_window_selection_report.txt"

    write_csv(
        windows_csv,
        window_rows,
        [
            "window_id",
            "start_time",
            "end_time",
            "duration",
            "selection_reason",
            "distance_from_nearest_redteam_event",
            "estimated_auth_line_count",
            "redteam_exclusion_margin",
            "status",
        ],
    )
    write_csv(
        exclusions_csv,
        exclusion_rows,
        ["redteam_time", "start_time", "end_time", "margin"],
    )

    manifest = {
        "version": "v0.6.1",
        "purpose": "auditable non-red-team background window selection",
        "auth_file": str(auth_path),
        "redteam_file": str(redteam_path),
        "window_duration": args.window_duration,
        "exclusion_margin": args.exclusion_margin,
        "target_windows": args.target_windows,
        "stride": args.stride,
        "min_auth_lines": args.min_auth_lines,
        "max_auth_lines": args.max_auth_lines,
        "sample_limit_lines": args.sample_limit_lines,
        "redteam_events_loaded": len(redteam_events),
        "excluded_neighborhoods": len(neighborhoods),
        "auth_timestamps_scanned": len(times),
        "auth_time_min": min_time,
        "auth_time_max": max_time,
        "selected_windows": window_rows,
        "outputs": {
            "windows_csv": str(windows_csv),
            "excluded_neighborhoods_csv": str(exclusions_csv),
            "manifest_json": str(manifest_json),
            "report_txt": str(report_txt),
        },
    }

    manifest_json.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    lines: List[str] = []
    lines.append("SRIA RT v0.6.1 Auditable Background Window Selection")
    lines.append("=" * 80)
    lines.append(f"auth_file: {auth_path}")
    lines.append(f"redteam_file: {redteam_path}")
    lines.append(f"auth_time_range: {min_time} to {max_time}")
    lines.append(f"redteam_events_loaded: {len(redteam_events):,}")
    lines.append(f"exclusion_margin: {args.exclusion_margin}")
    lines.append(f"target_windows: {args.target_windows}")
    lines.append(f"selected_windows: {len(selected)}")
    lines.append("")
    lines.append("Selected windows:")
    for w in selected:
        lines.append(
            f"  {w.window_id}: {w.start_time}-{w.end_time} duration={w.duration} "
            f"auth_lines={w.estimated_auth_line_count:,} "
            f"nearest_redteam_distance={w.distance_from_nearest_redteam_event}"
        )
    lines.append("")
    lines.append("Outputs:")
    lines.append(f"  {windows_csv.name}")
    lines.append(f"  {exclusions_csv.name}")
    lines.append(f"  {manifest_json.name}")
    report_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))
    print(f"\nWrote windows: {windows_csv}")
    print(f"Wrote exclusions: {exclusions_csv}")
    print(f"Wrote manifest: {manifest_json}")
    print(f"Wrote report: {report_txt}")


if __name__ == "__main__":
    main()
