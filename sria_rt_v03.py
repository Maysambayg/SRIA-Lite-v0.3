#!/usr/bin/env python3
"""
sria_rt_v03.py

SRIA RT v0.3 - Precision-Shaped Lateral Propagation Detector

Goal:
- Preserve the real blind red-team overlap found in v0.2.9.
- Reduce broad enterprise authentication fanout noise.
- Reward compact, novel, high-velocity lateral propagation.
- Penalize oversized, long-duration, repetitive, infrastructure-like auth spread.
- Separate accepted episodes from entropy-suppressed episodes for tuning.

IMPORTANT:
- redteam.txt is used ONLY for sparse evaluation windows and post-hoc validation.
- Detection/scoring uses auth.txt only.
- redteam source/destination/user labels are NEVER used by the detector scoring path.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict, deque, Counter
from typing import Dict, Set, Tuple, List, Optional, Any


# ============================================================
# CONFIG
# ============================================================

FIRST_TIME_SIGNALS = {
    "first_time_source_to_dest",
    "first_time_user_to_dest",
    "first_time_source_user_to_dest",
}

FANOUT_SIGNALS = {
    "source_fanout",
    "user_fanout",
    "source_user_fanout",
}


@dataclass
class Config:
    episode_window: int = 300
    validation_window: int = 600
    warmup_events: int = 50_000
    report_interval: int = 5_000_000

    min_events_per_episode: int = 3
    min_score: float = 0.75

    min_source_fanout: int = 5
    min_user_fanout: int = 5
    min_source_user_fanout: int = 3

    # Compact propagation shaping
    compactness_ref: float = 0.03              # destinations / second; ~3 new destinations per 100s
    fanout_velocity_ref: float = 3.0           # new destinations / minute
    compact_event_min: int = 3
    compact_event_max: int = 35
    compact_destination_max: int = 12
    dense_burst_window: int = 600

    # Enterprise entropy penalties
    excessive_event_count: int = 80
    extreme_event_count: int = 200
    excessive_duration: int = 1800
    excessive_destination_count: int = 40
    excessive_user_count: int = 8
    low_novelty_ratio: float = 0.25
    entropy_penalty_cap: float = 0.65

    # Candidate gates
    gate_b_velocity_threshold: float = 0.65
    gate_c_novelty_threshold: float = 0.50
    gate_c_min_destinations: int = 3
    gate_c_max_duration: int = 600

    # Output controls
    ranked_limit: int = 0                      # 0 = write all ranked episodes


@dataclass
class Episode:
    id: int
    source: str
    user: str
    start_time: int
    end_time: int
    events_count: int = 0
    destinations: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    signals: Set[str] = field(default_factory=set)

    # Event-level memory
    first_time_event_count: int = 0
    new_destination_event_count: int = 0
    max_risk: float = 0.0

    # v0.3 shaped metrics
    raw_score: float = 0.0
    score: float = 0.0
    compactness_score: float = 0.0
    fanout_velocity_score: float = 0.0
    novelty_ratio: float = 0.0
    entropy_penalty: float = 0.0
    candidate_gate: str = "none"
    suppression_reason: str = ""

    def duration(self) -> int:
        return max(0, self.end_time - self.start_time)

    def destination_count(self) -> int:
        return len(self.destinations)

    def user_count(self) -> int:
        return len(self.users)


# ============================================================
# PARSING
# ============================================================

def parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    parts = line.strip().split(",")
    if len(parts) < 9:
        return None

    try:
        ts = int(parts[0])
        source_user = parts[1]
        dest_user = parts[2]
        source = parts[3]
        dest = parts[4]
        auth_type = parts[5]
        logon_type = parts[6]
        auth_orientation = parts[7]
        success = parts[8]

        if success != "Success":
            return None
        if source == "?" or dest == "?":
            return None

        user = source_user if source_user != "?" else dest_user
        if user == "?":
            user = ""

        return {
            "time": ts,
            "user": user,
            "source": source,
            "dest": dest,
            "auth_type": auth_type,
            "logon_type": logon_type,
            "auth_orientation": auth_orientation,
        }
    except Exception:
        return None


def load_redteam(path: Path) -> List[dict]:
    events = []
    if not path.exists():
        return events

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 4:
                try:
                    events.append({
                        "time": int(parts[0]),
                        "user": parts[1],
                        "source": parts[2],
                        "dest": parts[3],
                    })
                except Exception:
                    pass
    return events


# ============================================================
# DETECTOR
# ============================================================

class PrecisionDetectorV03:
    def __init__(self, config: Config):
        self.c = config

        self.total_events = 0
        self.warmup_complete = False

        self.seen_user_dest: Set[Tuple[str, str]] = set()
        self.seen_source_dest: Set[Tuple[str, str]] = set()
        self.seen_source_user_dest: Set[Tuple[str, str, str]] = set()

        self.source_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.user_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.source_user_fanout: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

        self.active: Dict[Tuple[str, str], Episode] = {}
        self.expiry_queue = deque()
        self.completed: List[Episode] = []
        self.suppressed: List[Episode] = []
        self.next_id = 1

    def _episode_key(self, source: str, user: str) -> Tuple[str, str]:
        return (source, user)

    def _expire(self, current_ts: int) -> None:
        cutoff = current_ts - self.c.episode_window

        while self.expiry_queue and self.expiry_queue[0][0] <= cutoff:
            _, key = self.expiry_queue.popleft()
            ep = self.active.get(key)

            if ep is None:
                continue

            if ep.end_time <= cutoff:
                self.active.pop(key, None)
                self._finalize(ep)

    def _score_event(self, event: Dict[str, Any]) -> Tuple[float, Set[str], int]:
        source = event["source"]
        user = event["user"]
        dest = event["dest"]

        signals: Set[str] = set()
        score = 0.0
        first_time_hits = 0

        if not self.warmup_complete:
            return score, signals, first_time_hits

        if (source, dest) not in self.seen_source_dest:
            signals.add("first_time_source_to_dest")
            score += 0.16
            first_time_hits += 1

        if user and (user, dest) not in self.seen_user_dest:
            signals.add("first_time_user_to_dest")
            score += 0.18
            first_time_hits += 1

        if user and (source, user, dest) not in self.seen_source_user_dest:
            signals.add("first_time_source_user_to_dest")
            score += 0.30
            first_time_hits += 1

        sf = len(self.source_fanout[source])
        uf = len(self.user_fanout[user]) if user else 0
        suf = len(self.source_user_fanout[(source, user)]) if user else 0

        if sf >= self.c.min_source_fanout:
            signals.add("source_fanout")
            score += 0.12

        if uf >= self.c.min_user_fanout:
            signals.add("user_fanout")
            score += 0.10

        if suf >= self.c.min_source_user_fanout:
            signals.add("source_user_fanout")
            score += 0.16

        return min(score, 1.0), signals, first_time_hits

    def _update_memory(self, event: Dict[str, Any]) -> None:
        source = event["source"]
        user = event["user"]
        dest = event["dest"]

        self.seen_source_dest.add((source, dest))
        self.source_fanout[source].add(dest)

        if user:
            self.seen_user_dest.add((user, dest))
            self.seen_source_user_dest.add((source, user, dest))
            self.user_fanout[user].add(dest)
            self.source_user_fanout[(source, user)].add(dest)

    def _compute_entropy_penalty(self, ep: Episode) -> float:
        penalty = 0.0
        duration = ep.duration()
        dest_count = ep.destination_count()
        user_count = ep.user_count()

        if ep.events_count > self.c.excessive_event_count:
            penalty += 0.10
            ep.signals.add("entropy_many_events")

        if ep.events_count > self.c.extreme_event_count:
            penalty += 0.20
            ep.signals.add("entropy_extreme_events")

        if duration > self.c.excessive_duration:
            penalty += 0.15
            ep.signals.add("entropy_long_duration")

        if dest_count > self.c.excessive_destination_count:
            penalty += 0.20
            ep.signals.add("entropy_excessive_destinations")

        if user_count > self.c.excessive_user_count:
            penalty += 0.15
            ep.signals.add("entropy_many_users")

        if ep.novelty_ratio < self.c.low_novelty_ratio:
            penalty += 0.20
            ep.signals.add("entropy_low_novelty")

        return min(penalty, self.c.entropy_penalty_cap)

    def _candidate_gate(self, ep: Episode) -> str:
        has_sud = "first_time_source_user_to_dest" in ep.signals
        has_compact = "compact_lateral_burst" in ep.signals
        has_any_fanout = bool(ep.signals & FANOUT_SIGNALS)
        first_time_signal_count = len(ep.signals & FIRST_TIME_SIGNALS)

        # Gate A: Strong propagation pattern.
        if has_sud and has_compact and has_any_fanout:
            return "A_strong_propagation"

        # Gate B: High fanout velocity plus multiple first-time signal classes.
        if ep.fanout_velocity_score >= self.c.gate_b_velocity_threshold and first_time_signal_count >= 2:
            return "B_high_velocity"

        # Gate C: Dense novel burst.
        if (
            ep.novelty_ratio >= self.c.gate_c_novelty_threshold
            and ep.destination_count() >= self.c.gate_c_min_destinations
            and ep.duration() <= self.c.gate_c_max_duration
        ):
            return "C_dense_novel_burst"

        return "none"

    def _shape_episode_score(self, ep: Episode) -> None:
        duration = max(1, ep.duration())
        dest_count = ep.destination_count()

        # Compactness: how many unique destinations were reached per second.
        compactness = dest_count / duration
        ep.compactness_score = min(1.0, compactness / max(self.c.compactness_ref, 1e-9))

        # Velocity: how many unique destinations appeared per minute.
        minutes = max(duration / 60.0, 1.0)
        fanout_velocity = dest_count / minutes
        ep.fanout_velocity_score = min(1.0, fanout_velocity / max(self.c.fanout_velocity_ref, 1e-9))

        ep.novelty_ratio = ep.first_time_event_count / max(ep.events_count, 1)

        if (
            self.c.compact_event_min <= ep.events_count <= self.c.compact_event_max
            and dest_count <= self.c.compact_destination_max
            and duration <= self.c.dense_burst_window
            and dest_count >= 3
        ):
            ep.signals.add("compact_lateral_burst")

        if ep.fanout_velocity_score >= self.c.gate_b_velocity_threshold:
            ep.signals.add("fanout_velocity")

        # Weighted convergence score. This is intentionally explainable and clipped.
        score = 0.0
        if "first_time_source_user_to_dest" in ep.signals:
            score += 0.30
        if "first_time_user_to_dest" in ep.signals:
            score += 0.18
        if "first_time_source_to_dest" in ep.signals:
            score += 0.16
        if "source_user_fanout" in ep.signals:
            score += 0.16
        if "source_fanout" in ep.signals:
            score += 0.12
        if "user_fanout" in ep.signals:
            score += 0.10
        if "compact_lateral_burst" in ep.signals:
            score += 0.18
        if "fanout_velocity" in ep.signals:
            score += 0.18 * ep.fanout_velocity_score

        # Continuous compactness reward, independent of the binary compact-burst tag.
        score += 0.10 * ep.compactness_score

        signal_count = len((ep.signals & FIRST_TIME_SIGNALS) | (ep.signals & FANOUT_SIGNALS) | ({"compact_lateral_burst", "fanout_velocity"} & ep.signals))
        if signal_count < 3:
            score *= 0.50
            ep.signals.add("low_convergence_penalty")

        if (
            "first_time_source_user_to_dest" in ep.signals
            and "compact_lateral_burst" in ep.signals
            and ("source_user_fanout" in ep.signals or "source_fanout" in ep.signals)
        ):
            score += 0.12
            ep.signals.add("propagation_convergence_bonus")

        ep.raw_score = min(1.0, score)
        ep.entropy_penalty = self._compute_entropy_penalty(ep)
        ep.score = min(1.0, max(0.0, ep.raw_score - ep.entropy_penalty))
        ep.candidate_gate = self._candidate_gate(ep)

    def _finalize(self, ep: Episode) -> None:
        self._shape_episode_score(ep)

        if ep.events_count < self.c.min_events_per_episode:
            ep.suppression_reason = "too_few_events"
            self.suppressed.append(ep)
            return

        has_first_time = bool(ep.signals & FIRST_TIME_SIGNALS)
        if not has_first_time:
            ep.suppression_reason = "no_first_time_edge"
            self.suppressed.append(ep)
            return

        if ep.candidate_gate == "none":
            ep.suppression_reason = "no_candidate_gate"
            self.suppressed.append(ep)
            return

        if ep.score < self.c.min_score:
            ep.suppression_reason = "below_min_score"
            self.suppressed.append(ep)
            return

        self.completed.append(ep)

    def process(self, event: Dict[str, Any]) -> None:
        self.total_events += 1

        if not self.warmup_complete and self.total_events >= self.c.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_events:,} auth events")

        ts = event["time"]
        source = event["source"]
        user = event["user"]
        dest = event["dest"]

        self._expire(ts)

        event_score, signals, first_time_hits = self._score_event(event)
        was_new_destination_for_episode = False

        key = self._episode_key(source, user)
        ep = self.active.get(key)

        if signals:
            if ep is None:
                ep = Episode(
                    id=self.next_id,
                    source=source,
                    user=user,
                    start_time=ts,
                    end_time=ts,
                )
                self.next_id += 1
                self.active[key] = ep

            if dest not in ep.destinations:
                was_new_destination_for_episode = True

            ep.end_time = ts
            ep.events_count += 1
            ep.destinations.add(dest)
            if user:
                ep.users.add(user)
            ep.signals.update(signals)
            ep.first_time_event_count += first_time_hits
            if was_new_destination_for_episode:
                ep.new_destination_event_count += 1
            ep.max_risk = max(ep.max_risk, event_score)

            # Maintain a current shaped score for progress/debug, but final decision happens at expiry.
            self._shape_episode_score(ep)
            self.expiry_queue.append((ep.end_time + self.c.episode_window, key))

        self._update_memory(event)

    def finish(self) -> Tuple[List[Episode], List[Episode]]:
        for ep in list(self.active.values()):
            self._finalize(ep)
        self.active.clear()
        return self.completed, self.suppressed


# ============================================================
# VALIDATION
# ============================================================

def episode_to_dict(ep: Episode, sample_limit: int = 50) -> Dict[str, Any]:
    return {
        "id": ep.id,
        "source": ep.source,
        "user": ep.user,
        "start_time": ep.start_time,
        "end_time": ep.end_time,
        "duration": ep.duration(),
        "events_count": ep.events_count,
        "destination_count": ep.destination_count(),
        "user_count": ep.user_count(),
        "novelty_ratio": round(ep.novelty_ratio, 4),
        "compactness_score": round(ep.compactness_score, 4),
        "fanout_velocity_score": round(ep.fanout_velocity_score, 4),
        "entropy_penalty": round(ep.entropy_penalty, 4),
        "raw_score": round(ep.raw_score, 4),
        "score": round(ep.score, 4),
        "max_risk": round(ep.max_risk, 4),
        "candidate_gate": ep.candidate_gate,
        "suppression_reason": ep.suppression_reason,
        "signals": sorted(ep.signals),
        "destinations_sample": sorted(list(ep.destinations))[:sample_limit],
    }


def validate(episodes: List[Episode], redteam: List[dict], window: int) -> Dict[str, Any]:
    matches = []
    matched_redteam = set()
    matched_episodes = set()

    for idx, rt in enumerate(redteam):
        rt_time = rt["time"]
        rt_source = rt["source"]
        rt_dest = rt["dest"]
        rt_user = rt["user"]

        for ep in episodes:
            if ep.source != rt_source:
                continue

            if rt_dest not in ep.destinations:
                continue

            if not (ep.start_time - window <= rt_time <= ep.end_time + window):
                continue

            matched_redteam.add((rt_time, rt_source, rt_dest, rt_user))
            matched_episodes.add(ep.id)

            matches.append({
                "redteam_index": idx,
                "redteam": rt,
                "episode": episode_to_dict(ep, sample_limit=30),
                "delta_start": rt_time - ep.start_time,
                "delta_end": rt_time - ep.end_time,
                "exact_start_match": rt_time == ep.start_time,
            })

    return {
        "total_redteam": len(redteam),
        "matched_redteam": len(matched_redteam),
        "recall": len(matched_redteam) / len(redteam) if redteam else 0.0,
        "total_episodes": len(episodes),
        "matched_episodes": len(matched_episodes),
        "episode_overlap_rate": len(matched_episodes) / len(episodes) if episodes else 0.0,
        "matches": matches,
    }


# ============================================================
# SPARSE WINDOW SUPPORT
# ============================================================

def merge_windows(redteam: List[dict], radius: int) -> List[Tuple[int, int]]:
    windows = []
    for rt in redteam:
        windows.append((rt["time"] - radius, rt["time"] + radius))

    windows.sort()
    merged = []

    for start, end in windows:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    return [(a, b) for a, b in merged]


def in_windows(ts: int, windows: List[Tuple[int, int]], pointer: int) -> Tuple[bool, int]:
    while pointer < len(windows) and ts > windows[pointer][1]:
        pointer += 1

    if pointer >= len(windows):
        return False, pointer

    start, end = windows[pointer]
    return start <= ts <= end, pointer


# ============================================================
# OUTPUT
# ============================================================

def summarize_episodes(episodes: List[Episode]) -> Dict[str, Any]:
    signal_counts = Counter()
    gate_counts = Counter()
    suppression_counts = Counter()
    entropy_signal_counts = Counter()

    for ep in episodes:
        gate_counts[ep.candidate_gate] += 1
        if ep.suppression_reason:
            suppression_counts[ep.suppression_reason] += 1
        for sig in ep.signals:
            signal_counts[sig] += 1
            if sig.startswith("entropy_"):
                entropy_signal_counts[sig] += 1

    return {
        "signals": signal_counts,
        "gates": gate_counts,
        "suppression_reasons": suppression_counts,
        "entropy_signals": entropy_signal_counts,
    }


def save_outputs(
    out_dir: Path,
    episodes: List[Episode],
    suppressed: List[Episode],
    results: Dict[str, Any],
    stats: Dict[str, Any],
    config: Config,
) -> Tuple[Path, Path, Path, Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    all_file = out_dir / "episodes_v03_all.jsonl"
    ranked_file = out_dir / "episodes_v03_ranked.jsonl"
    suppressed_file = out_dir / "episodes_v03_suppressed_entropy.jsonl"
    matches_file = out_dir / "redteam_matches_v03.jsonl"
    report_file = out_dir / "validation_report_v03.txt"

    ranked = sorted(episodes, key=lambda e: (e.score, e.raw_score, e.fanout_velocity_score), reverse=True)
    if config.ranked_limit > 0:
        ranked_to_write = ranked[:config.ranked_limit]
    else:
        ranked_to_write = ranked

    with open(all_file, "w", encoding="utf-8") as f:
        for ep in episodes:
            f.write(json.dumps(episode_to_dict(ep)) + "\n")

    with open(ranked_file, "w", encoding="utf-8") as f:
        for ep in ranked_to_write:
            f.write(json.dumps(episode_to_dict(ep)) + "\n")

    with open(suppressed_file, "w", encoding="utf-8") as f:
        for ep in sorted(suppressed, key=lambda e: (e.score, e.raw_score, e.entropy_penalty), reverse=True):
            f.write(json.dumps(episode_to_dict(ep)) + "\n")

    with open(matches_file, "w", encoding="utf-8") as f:
        for m in results["matches"]:
            f.write(json.dumps(m) + "\n")

    accepted_summary = summarize_episodes(episodes)
    suppressed_summary = summarize_episodes(suppressed)

    precision_proxy = results["matched_episodes"] / results["total_episodes"] if results["total_episodes"] else 0.0

    lines = []
    lines.append("SRIA RT v0.3 Precision-Shaped Lateral Propagation Detector")
    lines.append("=" * 80)
    lines.append("Purpose: preserve blind red-team structural overlap while reducing enterprise auth entropy.")
    lines.append("NOTE: redteam.txt is used only for sparse evaluation windows and post-hoc validation.")
    lines.append("NOTE: Detector scoring does NOT use redteam source/destination/user labels.")
    lines.append("")

    lines.append("Run stats:")
    for k, v in stats.items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("Validation:")
    lines.append(f"  total_redteam: {results['total_redteam']}")
    lines.append(f"  matched_redteam: {results['matched_redteam']}")
    lines.append(f"  recall: {results['recall']:.4f}")
    lines.append(f"  total_episodes: {results['total_episodes']}")
    lines.append(f"  matched_episodes: {results['matched_episodes']}")
    lines.append(f"  episode_overlap_rate: {results['episode_overlap_rate']:.6f}")
    lines.append(f"  precision_proxy_matched_episodes_over_total: {precision_proxy:.8f}")

    lines.append("")
    lines.append("Episode shaping configuration:")
    lines.append(f"  min_score: {config.min_score}")
    lines.append(f"  compactness_ref: {config.compactness_ref}")
    lines.append(f"  fanout_velocity_ref: {config.fanout_velocity_ref}")
    lines.append(f"  entropy_penalty_cap: {config.entropy_penalty_cap}")
    lines.append(f"  gate_b_velocity_threshold: {config.gate_b_velocity_threshold}")
    lines.append(f"  gate_c_novelty_threshold: {config.gate_c_novelty_threshold}")

    lines.append("")
    lines.append("Accepted candidate gates:")
    for gate, count in accepted_summary["gates"].most_common():
        lines.append(f"  {gate}: {count}")

    lines.append("")
    lines.append("Accepted top signals:")
    for sig, count in accepted_summary["signals"].most_common(25):
        lines.append(f"  {sig}: {count}")

    lines.append("")
    lines.append("Suppressed episodes:")
    lines.append(f"  total_suppressed: {len(suppressed)}")
    for reason, count in suppressed_summary["suppression_reasons"].most_common(20):
        lines.append(f"  {reason}: {count}")

    lines.append("")
    lines.append("Suppressed entropy signals:")
    for sig, count in suppressed_summary["entropy_signals"].most_common(20):
        lines.append(f"  {sig}: {count}")

    lines.append("")
    lines.append("First 30 matches:")
    for m in results["matches"][:30]:
        lines.append(json.dumps(m))

    report_file.write_text("\n".join(lines), encoding="utf-8")

    return all_file, ranked_file, suppressed_file, matches_file, report_file


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-dir", default=".")
    p.add_argument("--out-dir", default="v03_output")
    p.add_argument("--max-lines", type=int, default=0)
    p.add_argument("--max-candidate-events", type=int, default=5_000_000)
    p.add_argument("--window", type=int, default=600)
    p.add_argument("--episode-window", type=int, default=300)
    p.add_argument("--validation-window", type=int, default=600)
    p.add_argument("--warmup", type=int, default=50_000)
    p.add_argument("--min-score", type=float, default=0.75)

    # Tuning knobs for v0.3 experiments.
    p.add_argument("--compactness-ref", type=float, default=0.03)
    p.add_argument("--fanout-velocity-ref", type=float, default=3.0)
    p.add_argument("--ranked-limit", type=int, default=0)
    args = p.parse_args()

    base = Path(args.base_dir)
    out = Path(args.out_dir)

    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"

    print("=" * 80)
    print("SRIA RT v0.3 - Precision-Shaped Lateral Propagation Detector")
    print("=" * 80)
    print(f"Base dir: {base}")
    print(f"Auth: {auth_file}")
    print(f"Redteam: {redteam_file}")
    print(f"Sparse redteam-window radius: +/- {args.window}s")
    print(f"Episode window: {args.episode_window}s")
    print(f"Validation window: +/- {args.validation_window}s")
    print(f"Min score: {args.min_score}")
    print("NOTE: redteam.txt is used only for sparse evaluation windows and post-hoc validation.")
    print("NOTE: Detector scoring does NOT use redteam source/destination/user labels.")
    print("=" * 80)

    if not auth_file.exists():
        raise FileNotFoundError(f"Missing auth file: {auth_file}")

    redteam = load_redteam(redteam_file)
    print(f"\n[validation] Loaded redteam events: {len(redteam)}")
    if redteam:
        print(f"[validation] Redteam time range: {min(r['time'] for r in redteam)} - {max(r['time'] for r in redteam)}")

    windows = merge_windows(redteam, args.window)
    print(f"[validation] Merged sparse windows: {len(windows)}")
    print(f"[validation] Total sparse seconds: {sum(b - a for a, b in windows):,}")

    config = Config(
        episode_window=args.episode_window,
        validation_window=args.validation_window,
        warmup_events=args.warmup,
        min_score=args.min_score,
        compactness_ref=args.compactness_ref,
        fanout_velocity_ref=args.fanout_velocity_ref,
        ranked_limit=args.ranked_limit,
    )

    detector = PrecisionDetectorV03(config)

    scanned_lines = 0
    candidate_events = 0
    pointer = 0
    observed_min_ts = None
    observed_max_ts = None

    start = time.time()

    print("\n[detection] Streaming auth.txt once...")

    with open(auth_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            scanned_lines += 1

            if args.max_lines and scanned_lines > args.max_lines:
                break

            parsed = parse_auth_line(line)
            if not parsed:
                continue

            ts = parsed["time"]
            observed_min_ts = ts if observed_min_ts is None else min(observed_min_ts, ts)
            observed_max_ts = ts if observed_max_ts is None else max(observed_max_ts, ts)

            # Sparse evaluation windows are used only to make iteration feasible.
            # They do not inject red-team labels into detector scoring.
            if windows:
                inside, pointer = in_windows(ts, windows, pointer)
                if not inside:
                    continue

            candidate_events += 1
            detector.process(parsed)

            if candidate_events % 1_000_000 == 0:
                elapsed = max(0.001, time.time() - start)
                print(
                    f"  candidate_events={candidate_events:,} "
                    f"scanned_lines={scanned_lines:,} "
                    f"rate={candidate_events / elapsed:,.0f} candidate/sec"
                )

            if args.max_candidate_events and candidate_events >= args.max_candidate_events:
                print("  Reached max candidate events. Stopping early.")
                break

    episodes, suppressed = detector.finish()

    elapsed = time.time() - start
    print("\n[detection] Finished")
    print(f"  scanned_lines: {scanned_lines:,}")
    print(f"  candidate_events_in_sparse_windows: {candidate_events:,}")
    print(f"  auth_time_observed: {observed_min_ts} - {observed_max_ts}")
    print(f"  elapsed: {elapsed:.1f}s")
    print(f"  candidate_rate: {candidate_events / elapsed:,.0f}/sec" if elapsed else "  candidate_rate: n/a")
    print(f"  episodes_detected: {len(episodes):,}")
    print(f"  episodes_suppressed: {len(suppressed):,}")

    accepted_summary = summarize_episodes(episodes)

    print("\n[detection] Accepted candidate gates:")
    for gate, count in accepted_summary["gates"].most_common(15):
        print(f"  {gate}: {count:,}")

    print("\n[detection] Top accepted signals:")
    for sig, count in accepted_summary["signals"].most_common(15):
        print(f"  {sig}: {count:,}")

    print("\n[validation] Comparing accepted episodes to redteam ground truth...")
    results = validate(episodes, redteam, args.validation_window)

    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)
    print(f"  Total redteam events: {results['total_redteam']}")
    print(f"  Matched redteam events: {results['matched_redteam']}")
    print(f"  Recall: {results['recall']:.2%}")
    print(f"  Total accepted episodes: {results['total_episodes']:,}")
    print(f"  Episodes overlapping redteam: {results['matched_episodes']}")
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.6%}")

    stats = {
        "scanned_lines": scanned_lines,
        "candidate_events_in_sparse_windows": candidate_events,
        "auth_time_observed": f"{observed_min_ts} - {observed_max_ts}",
        "elapsed_seconds": round(elapsed, 1),
        "episodes_detected": len(episodes),
        "episodes_suppressed": len(suppressed),
        "min_score": args.min_score,
        "episode_window": args.episode_window,
        "validation_window": args.validation_window,
    }

    all_file, ranked_file, suppressed_file, matches_file, report_file = save_outputs(
        out, episodes, suppressed, results, stats, config
    )

    print(f"\n[output] All accepted episodes: {all_file}")
    print(f"[output] Ranked accepted episodes: {ranked_file}")
    print(f"[output] Suppressed episodes: {suppressed_file}")
    print(f"[output] Matches: {matches_file}")
    print(f"[output] Report: {report_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
