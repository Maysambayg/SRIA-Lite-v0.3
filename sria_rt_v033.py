#!/usr/bin/env python3
"""
sria_rt_v033.py

SRIA RT v0.3.3 - Recall Recovery + Near-Match Rescue

Goal:
- Use v0.3.0-strict as the main experimental direction.
- Preserve blind validation: auth.txt is the only scoring source.
- Keep redteam.txt restricted to sparse-window selection and post-hoc validation.
- Tighten Gate A, which was too permissive in v0.3 analysis.
- Suppress low-novelty enterprise fanout unless velocity is strong.
- Add observed-time-range recall so capped partial scans are reported correctly.
- Preserve rich diagnostic outputs from v0.3 analysis.

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
from typing import Any, Deque, Dict, List, Optional, Set, Tuple


# ============================================================
# SIGNAL SETS
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

DYNAMIC_SIGNALS = {
    "compact_lateral_burst",
    "fanout_velocity",
    "propagation_convergence_bonus",
    "low_convergence_penalty",
    "entropy_many_events",
    "entropy_extreme_events",
    "entropy_soft_duration",
    "entropy_long_duration",
    "entropy_oversized_fanout",
    "entropy_excessive_destinations",
    "entropy_many_users",
    "entropy_low_novelty",
    "compact_rescue_bonus",
    "source_user_fanout_rescue_bonus",
}


# ============================================================
# CONFIG
# ============================================================

@dataclass
class Config:
    episode_window: int = 300
    validation_window: int = 600
    warmup_events: int = 50_000
    report_interval: int = 5_000_000

    min_events_per_episode: int = 3
    min_score: float = 0.78

    min_source_fanout: int = 5
    min_user_fanout: int = 5
    min_source_user_fanout: int = 3

    # Compact propagation shaping. These defaults follow the v0.3.0 strict branch.
    compact_event_min: int = 3
    compact_event_max: int = 30
    compact_destination_max: int = 12
    compact_max_duration: int = 600

    # Temporal acceleration: count distinct new destinations first seen inside a short window.
    velocity_window: int = 120
    velocity_min_new_destinations: int = 3
    gate_b_velocity_threshold: float = 0.60

    # Entropy penalties. These are intentionally stricter than v0.3 analysis.
    excessive_event_count: int = 80
    extreme_event_count: int = 200
    soft_duration_threshold: int = 420
    long_duration_threshold: int = 1200
    noisy_destination_threshold: int = 25
    excessive_destination_count: int = 40
    excessive_user_count: int = 8
    low_novelty_ratio: float = 0.25
    entropy_penalty_cap: float = 0.75

    # Candidate gates.
    gate_a_novelty_threshold: float = 0.25
    gate_a_max_duration: int = 900
    gate_a_max_destinations: int = 24
    gate_c_novelty_threshold: float = 0.30
    gate_c_min_destinations: int = 3
    gate_c_max_duration: int = 900

    # Suppression policy.
    suppress_low_novelty_without_velocity: bool = False

    # Output controls.
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
    dest_first_seen: Dict[str, int] = field(default_factory=dict)
    signals: Set[str] = field(default_factory=set)

    # Event-level memory.
    first_time_event_count: int = 0            # events with at least one first-time edge
    first_time_signal_hits: int = 0            # total first-time signal hits across events
    new_destination_event_count: int = 0
    max_risk: float = 0.0

    # Shaped metrics.
    raw_score: float = 0.0
    score: float = 0.0
    compactness_score: float = 0.0
    fanout_velocity_score: float = 0.0
    peak_velocity_new_dests: int = 0
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
    events: List[dict] = []
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

class PrecisionDetectorV033:
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
        self.expiry_queue: Deque[Tuple[int, Tuple[str, str]]] = deque()
        self.completed: List[Episode] = []
        self.suppressed: List[Episode] = []
        self.next_id = 1

    @staticmethod
    def _episode_key(source: str, user: str) -> Tuple[str, str]:
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

        # Event-level scoring follows the v0.3.0 strict branch: source-user-dest novelty dominates.
        if (source, dest) not in self.seen_source_dest:
            signals.add("first_time_source_to_dest")
            score += 0.22
            first_time_hits += 1

        if user and (user, dest) not in self.seen_user_dest:
            signals.add("first_time_user_to_dest")
            score += 0.26
            first_time_hits += 1

        if user and (source, user, dest) not in self.seen_source_user_dest:
            signals.add("first_time_source_user_to_dest")
            score += 0.42
            first_time_hits += 1

        sf = len(self.source_fanout[source])
        uf = len(self.user_fanout[user]) if user else 0
        suf = len(self.source_user_fanout[(source, user)]) if user else 0

        if sf >= self.c.min_source_fanout:
            signals.add("source_fanout")
            score += 0.10

        if uf >= self.c.min_user_fanout:
            signals.add("user_fanout")
            score += 0.10

        if suf >= self.c.min_source_user_fanout:
            signals.add("source_user_fanout")
            score += 0.20

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

    def _peak_new_destinations_in_velocity_window(self, ep: Episode) -> int:
        times = sorted(ep.dest_first_seen.values())
        if not times:
            return 0

        best = 1
        left = 0
        for right, ts in enumerate(times):
            while left <= right and ts - times[left] > self.c.velocity_window:
                left += 1
            best = max(best, right - left + 1)
        return best

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

        if duration > self.c.long_duration_threshold:
            penalty += 0.30
            ep.signals.add("entropy_long_duration")
        elif duration > self.c.soft_duration_threshold:
            penalty += 0.12
            ep.signals.add("entropy_soft_duration")

        if dest_count > self.c.noisy_destination_threshold:
            penalty += 0.35
            ep.signals.add("entropy_oversized_fanout")

        if dest_count > self.c.excessive_destination_count:
            penalty += 0.20
            ep.signals.add("entropy_excessive_destinations")

        if user_count > self.c.excessive_user_count:
            penalty += 0.15
            ep.signals.add("entropy_many_users")

        if ep.novelty_ratio < self.c.low_novelty_ratio:
            # v0.3.3 keeps low novelty as a shaping penalty, not a default hard survival rule.
            penalty += 0.06
            ep.signals.add("entropy_low_novelty")

        return min(penalty, self.c.entropy_penalty_cap)

    def _candidate_gate(self, ep: Episode) -> str:
        has_sud = "first_time_source_user_to_dest" in ep.signals
        has_compact = "compact_lateral_burst" in ep.signals
        has_source_user_fanout = "source_user_fanout" in ep.signals
        has_velocity = "fanout_velocity" in ep.signals
        first_time_signal_count = len(ep.signals & FIRST_TIME_SIGNALS)

        # Gate A is the balanced v0.3.3 midpoint. v0.3 analysis was too broad;
        # v0.3.1 was too strict and made velocity nearly mandatory. This gate keeps
        # source-user-destination novelty and compactness, but accepts either
        # source-user fanout or genuine short-window velocity as the propagation proof.
        if (
            has_sud
            and has_compact
            and (has_source_user_fanout or has_velocity)
            and ep.novelty_ratio >= self.c.gate_a_novelty_threshold
            and ep.duration() <= self.c.gate_a_max_duration
            and ep.destination_count() <= self.c.gate_a_max_destinations
        ):
            return "A_balanced_source_user_propagation"

        # Gate D: compact source-user-destination novelty rescue.
        # v0.3.1 and v0.3.2 over-selected for velocity; this path recovers
        # compact lateral bursts that show source-user-destination novelty plus
        # at least one other first-time edge, even when velocity is not dominant.
        if (
            has_sud
            and has_compact
            and first_time_signal_count >= 2
            and ep.duration() <= self.c.gate_a_max_duration
            and ep.destination_count() <= self.c.gate_a_max_destinations
            and ep.novelty_ratio >= 0.15
        ):
            return "D_compact_novelty_rescue"

        # Gate E: source-user fanout rescue.
        # This preserves the strongest non-velocity propagation primitive while
        # preventing broad enterprise spread from passing without duration/dest caps.
        if (
            has_sud
            and has_source_user_fanout
            and first_time_signal_count >= 2
            and ep.duration() <= self.c.gate_a_max_duration
            and ep.destination_count() <= max(self.c.gate_a_max_destinations, 30)
            and ep.novelty_ratio >= 0.15
        ):
            return "E_source_user_fanout_rescue"

        # Gate B: high short-window velocity plus multiple first-time signal classes.
        # Velocity remains a strong booster, not a universal survival requirement.
        if (
            has_sud
            and ep.fanout_velocity_score >= self.c.gate_b_velocity_threshold
            and first_time_signal_count >= 2
        ):
            return "B_high_velocity"

        # Gate C: dense novel burst rescue path for compact non-enterprise propagation.
        if (
            has_sud
            and ep.novelty_ratio >= self.c.gate_c_novelty_threshold
            and ep.destination_count() >= self.c.gate_c_min_destinations
            and ep.duration() <= self.c.gate_c_max_duration
        ):
            return "C_dense_novel_burst"

        return "none"

    def _shape_episode_score(self, ep: Episode) -> None:
        # Remove dynamic episode-level signals before recomputing so early low-novelty
        # or early duration tags do not remain stale as the episode evolves.
        ep.signals.difference_update(DYNAMIC_SIGNALS)

        duration = max(1, ep.duration())
        dest_count = ep.destination_count()

        # Compactness: how many unique destinations were reached per second.
        compactness = dest_count / duration
        ep.compactness_score = min(1.0, compactness / 0.03)  # ~3 destinations per 100s is strong.

        # Velocity: peak number of new destinations first seen inside a short time window.
        ep.peak_velocity_new_dests = self._peak_new_destinations_in_velocity_window(ep)
        ep.fanout_velocity_score = min(
            1.0,
            ep.peak_velocity_new_dests / max(self.c.velocity_min_new_destinations, 1),
        )

        ep.novelty_ratio = ep.first_time_event_count / max(ep.events_count, 1)

        if (
            self.c.compact_event_min <= ep.events_count <= self.c.compact_event_max
            and dest_count <= self.c.compact_destination_max
            and duration <= self.c.compact_max_duration
            and dest_count >= 3
        ):
            ep.signals.add("compact_lateral_burst")

        if ep.fanout_velocity_score >= self.c.gate_b_velocity_threshold:
            ep.signals.add("fanout_velocity")

        # Weighted convergence score. Deliberately transparent and clipped.
        score = 0.0
        if "first_time_source_user_to_dest" in ep.signals:
            score += 0.42
        if "first_time_user_to_dest" in ep.signals:
            score += 0.22
        if "first_time_source_to_dest" in ep.signals:
            score += 0.18
        if "source_user_fanout" in ep.signals:
            score += 0.20
        if "source_fanout" in ep.signals:
            score += 0.10
        if "user_fanout" in ep.signals:
            score += 0.10
        if "compact_lateral_burst" in ep.signals:
            score += 0.22
        if "fanout_velocity" in ep.signals:
            score += 0.22 * ep.fanout_velocity_score

        # Continuous compactness reward, independent of the binary compact-burst tag.
        score += 0.08 * ep.compactness_score

        signal_count = len(
            (ep.signals & FIRST_TIME_SIGNALS)
            | (ep.signals & FANOUT_SIGNALS)
            | ({"compact_lateral_burst", "fanout_velocity"} & ep.signals)
        )
        if signal_count < 3:
            score *= 0.50
            ep.signals.add("low_convergence_penalty")

        if (
            "first_time_source_user_to_dest" in ep.signals
            and "compact_lateral_burst" in ep.signals
            and ("source_user_fanout" in ep.signals or "fanout_velocity" in ep.signals)
        ):
            score += 0.10
            ep.signals.add("propagation_convergence_bonus")

        # v0.3.3 recall recovery: compact non-velocity propagation should not be
        # discarded merely because it lacks the velocity signature. This is still
        # blind; it uses only auth topology and timing.
        if (
            "first_time_source_user_to_dest" in ep.signals
            and "first_time_user_to_dest" in ep.signals
            and "compact_lateral_burst" in ep.signals
            and "fanout_velocity" not in ep.signals
        ):
            score += 0.08
            ep.signals.add("compact_rescue_bonus")

        if (
            "first_time_source_user_to_dest" in ep.signals
            and "source_user_fanout" in ep.signals
            and ep.novelty_ratio >= 0.15
        ):
            score += 0.06
            ep.signals.add("source_user_fanout_rescue_bonus")

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

        # v0.3.3 keeps the strict branch's key precision rule.
        if "first_time_source_user_to_dest" not in ep.signals:
            ep.suppression_reason = "missing_source_user_dest_novelty"
            self.suppressed.append(ep)
            return

        convergence = (
            "first_time_source_to_dest" in ep.signals
            or "first_time_user_to_dest" in ep.signals
        )
        if not convergence:
            ep.suppression_reason = "missing_first_time_convergence"
            self.suppressed.append(ep)
            return

        if ep.candidate_gate == "none":
            ep.suppression_reason = "no_candidate_gate"
            self.suppressed.append(ep)
            return

        if (
            self.c.suppress_low_novelty_without_velocity
            and ep.novelty_ratio < self.c.low_novelty_ratio
            and ep.fanout_velocity_score < self.c.gate_b_velocity_threshold
            and "compact_lateral_burst" not in ep.signals
        ):
            ep.suppression_reason = "low_novelty_without_velocity_or_compactness"
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

        if signals:
            key = self._episode_key(source, user)
            ep = self.active.get(key)

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

            is_new_dest_for_episode = dest not in ep.destinations

            ep.end_time = ts
            ep.events_count += 1
            ep.destinations.add(dest)
            if user:
                ep.users.add(user)
            if is_new_dest_for_episode:
                ep.new_destination_event_count += 1
                ep.dest_first_seen.setdefault(dest, ts)
            ep.signals.update(signals)
            if first_time_hits > 0:
                ep.first_time_event_count += 1
            ep.first_time_signal_hits += first_time_hits
            ep.max_risk = max(ep.max_risk, event_score)

            # Maintain shaped score for progress/debug; final decision happens at expiry.
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
        "first_time_event_count": ep.first_time_event_count,
        "first_time_signal_hits": ep.first_time_signal_hits,
        "new_destination_event_count": ep.new_destination_event_count,
        "novelty_ratio": round(ep.novelty_ratio, 4),
        "compactness_score": round(ep.compactness_score, 4),
        "fanout_velocity_score": round(ep.fanout_velocity_score, 4),
        "peak_velocity_new_dests": ep.peak_velocity_new_dests,
        "entropy_penalty": round(ep.entropy_penalty, 4),
        "raw_score": round(ep.raw_score, 4),
        "score": round(ep.score, 4),
        "max_risk": round(ep.max_risk, 4),
        "candidate_gate": ep.candidate_gate,
        "suppression_reason": ep.suppression_reason,
        "signals": sorted(ep.signals),
        "destinations_sample": sorted(list(ep.destinations))[:sample_limit],
    }


def _in_observed_range(rt_time: int, observed_min_ts: Optional[int], observed_max_ts: Optional[int]) -> bool:
    if observed_min_ts is None or observed_max_ts is None:
        return False
    return observed_min_ts <= rt_time <= observed_max_ts


def validate(
    episodes: List[Episode],
    redteam: List[dict],
    window: int,
    observed_min_ts: Optional[int] = None,
    observed_max_ts: Optional[int] = None,
) -> Dict[str, Any]:
    matches = []
    matched_redteam: Set[Tuple[int, str, str, str]] = set()
    matched_episodes: Set[int] = set()
    exact_start_redteam: Set[Tuple[int, str, str, str]] = set()

    for idx, rt in enumerate(redteam):
        rt_time = rt["time"]
        rt_source = rt["source"]
        rt_dest = rt["dest"]
        rt_user = rt["user"]
        rt_key = (rt_time, rt_user, rt_source, rt_dest)

        for ep in episodes:
            if ep.source != rt_source:
                continue

            if rt_dest not in ep.destinations:
                continue

            if not (ep.start_time - window <= rt_time <= ep.end_time + window):
                continue

            matched_redteam.add(rt_key)
            matched_episodes.add(ep.id)
            exact = rt_time == ep.start_time
            if exact:
                exact_start_redteam.add(rt_key)

            matches.append({
                "redteam_index": idx,
                "redteam": rt,
                "episode": episode_to_dict(ep, sample_limit=30),
                "delta_start": rt_time - ep.start_time,
                "delta_end": rt_time - ep.end_time,
                "exact_start_match": exact,
                "redteam_in_observed_time_range": _in_observed_range(rt_time, observed_min_ts, observed_max_ts),
            })

    redteam_observed = [
        rt for rt in redteam
        if _in_observed_range(rt["time"], observed_min_ts, observed_max_ts)
    ]
    matched_redteam_observed = {
        key for key in matched_redteam
        if _in_observed_range(key[0], observed_min_ts, observed_max_ts)
    }

    return {
        "total_redteam": len(redteam),
        "matched_redteam": len(matched_redteam),
        "recall": len(matched_redteam) / len(redteam) if redteam else 0.0,
        "total_redteam_in_observed_range": len(redteam_observed),
        "matched_redteam_in_observed_range": len(matched_redteam_observed),
        "recall_observed_range": (
            len(matched_redteam_observed) / len(redteam_observed)
            if redteam_observed else 0.0
        ),
        "redteam_outside_observed_range": max(0, len(redteam) - len(redteam_observed)),
        "observed_time_range": f"{observed_min_ts} - {observed_max_ts}",
        "total_episodes": len(episodes),
        "matched_episodes": len(matched_episodes),
        "episode_overlap_rate": len(matched_episodes) / len(episodes) if episodes else 0.0,
        "exact_start_matches": len(exact_start_redteam),
        "matches": matches,
    }


def find_suppressed_near_matches(
    suppressed: List[Episode],
    redteam: List[dict],
    window: int,
    observed_min_ts: Optional[int] = None,
    observed_max_ts: Optional[int] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """
    Post-hoc diagnostic only. This does not feed scoring.

    Purpose: identify red-team-overlapping episodes that were suppressed so v0.3.3
    can recover recall without blindly loosening the full detector.
    """
    by_source: Dict[str, List[Episode]] = defaultdict(list)
    for ep in suppressed:
        by_source[ep.source].append(ep)

    near_matches: List[Dict[str, Any]] = []
    for idx, rt in enumerate(redteam):
        rt_time = rt["time"]
        if observed_min_ts is not None and observed_max_ts is not None:
            if not (observed_min_ts <= rt_time <= observed_max_ts):
                continue

        for ep in by_source.get(rt["source"], []):
            if rt["dest"] not in ep.destinations:
                continue
            if not (ep.start_time - window <= rt_time <= ep.end_time + window):
                continue

            near_matches.append({
                "redteam_index": idx,
                "redteam": rt,
                "suppressed_episode": episode_to_dict(ep, sample_limit=30),
                "delta_start": rt_time - ep.start_time,
                "delta_end": rt_time - ep.end_time,
                "exact_start_match": rt_time == ep.start_time,
                "diagnostic_only": True,
            })
            if len(near_matches) >= limit:
                return near_matches

    return near_matches


# ============================================================
# SPARSE WINDOW SUPPORT
# ============================================================

def merge_windows(redteam: List[dict], radius: int) -> List[Tuple[int, int]]:
    windows = []
    for rt in redteam:
        windows.append((rt["time"] - radius, rt["time"] + radius))

    windows.sort()
    merged: List[List[int]] = []

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

def summarize_episodes(episodes: List[Episode]) -> Dict[str, Counter]:
    signal_counts: Counter = Counter()
    gate_counts: Counter = Counter()
    suppression_counts: Counter = Counter()
    entropy_signal_counts: Counter = Counter()

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
    suppressed_near_matches: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Path, Path, Path, Path, Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    all_file = out_dir / "episodes_v033_all.jsonl"
    ranked_file = out_dir / "episodes_v033_ranked.jsonl"
    suppressed_file = out_dir / "episodes_v033_suppressed_entropy.jsonl"
    matches_file = out_dir / "redteam_matches_v033.jsonl"
    suppressed_near_file = out_dir / "redteam_suppressed_near_matches_v033.jsonl"
    report_file = out_dir / "validation_report_v033.txt"

    ranked = sorted(episodes, key=lambda e: (e.score, e.raw_score, e.fanout_velocity_score), reverse=True)
    ranked_to_write = ranked[:config.ranked_limit] if config.ranked_limit > 0 else ranked

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

    suppressed_near_matches = suppressed_near_matches or []
    with open(suppressed_near_file, "w", encoding="utf-8") as f:
        for m in suppressed_near_matches:
            f.write(json.dumps(m) + "\n")

    accepted_summary = summarize_episodes(episodes)
    suppressed_summary = summarize_episodes(suppressed)

    precision_proxy = results["matched_episodes"] / results["total_episodes"] if results["total_episodes"] else 0.0

    lines: List[str] = []
    lines.append("SRIA RT v0.3.3 Recall Recovery + Near-Match Rescue")
    lines.append("=" * 80)
    lines.append("Purpose: recover recall from v0.3.1 while preserving most entropy compression.")
    lines.append("NOTE: redteam.txt is used only for sparse evaluation windows and post-hoc validation.")
    lines.append("NOTE: Detector scoring does NOT use redteam source/destination/user labels.")
    lines.append("")

    lines.append("Run stats:")
    for k, v in stats.items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("Validation - all redteam events:")
    lines.append(f"  total_redteam: {results['total_redteam']}")
    lines.append(f"  matched_redteam: {results['matched_redteam']}")
    lines.append(f"  recall_all: {results['recall']:.4f}")
    lines.append(f"  exact_start_matches: {results['exact_start_matches']}")

    lines.append("")
    lines.append("Validation - observed auth time range only:")
    lines.append(f"  observed_time_range: {results['observed_time_range']}")
    lines.append(f"  total_redteam_in_observed_range: {results['total_redteam_in_observed_range']}")
    lines.append(f"  matched_redteam_in_observed_range: {results['matched_redteam_in_observed_range']}")
    lines.append(f"  recall_observed_range: {results['recall_observed_range']:.4f}")
    lines.append(f"  redteam_outside_observed_range: {results['redteam_outside_observed_range']}")

    lines.append("")
    lines.append("Episode precision proxy:")
    lines.append(f"  total_episodes: {results['total_episodes']}")
    lines.append(f"  matched_episodes: {results['matched_episodes']}")
    lines.append(f"  episode_overlap_rate: {results['episode_overlap_rate']:.8f}")
    lines.append(f"  precision_proxy_matched_episodes_over_total: {precision_proxy:.8f}")

    lines.append("")
    lines.append("Episode shaping configuration:")
    lines.append(f"  min_score: {config.min_score}")
    lines.append(f"  gate_a_novelty_threshold: {config.gate_a_novelty_threshold}")
    lines.append(f"  gate_a_max_duration: {config.gate_a_max_duration}")
    lines.append(f"  gate_a_max_destinations: {config.gate_a_max_destinations}")
    lines.append(f"  velocity_window: {config.velocity_window}")
    lines.append(f"  velocity_min_new_destinations: {config.velocity_min_new_destinations}")
    lines.append(f"  gate_b_velocity_threshold: {config.gate_b_velocity_threshold}")
    lines.append(f"  low_novelty_ratio: {config.low_novelty_ratio}")
    lines.append(f"  suppress_low_novelty_without_velocity: {config.suppress_low_novelty_without_velocity}")
    lines.append(f"  entropy_penalty_cap: {config.entropy_penalty_cap}")

    lines.append("")
    lines.append("Accepted candidate gates:")
    for gate, count in accepted_summary["gates"].most_common():
        lines.append(f"  {gate}: {count}")

    lines.append("")
    lines.append("Accepted top signals:")
    for sig, count in accepted_summary["signals"].most_common(30):
        lines.append(f"  {sig}: {count}")

    lines.append("")
    lines.append("Suppressed episodes:")
    lines.append(f"  total_suppressed: {len(suppressed)}")
    for reason, count in suppressed_summary["suppression_reasons"].most_common(25):
        lines.append(f"  {reason}: {count}")

    lines.append("")
    lines.append("Suppressed entropy signals:")
    for sig, count in suppressed_summary["entropy_signals"].most_common(25):
        lines.append(f"  {sig}: {count}")

    lines.append("")
    lines.append("Suppressed redteam near-match diagnostics:")
    lines.append(f"  suppressed_near_matches_written: {len(suppressed_near_matches)}")
    lines.append("  NOTE: diagnostic only; redteam labels are not used by scoring.")

    lines.append("")
    lines.append("First 50 matches:")
    for m in results["matches"][:50]:
        lines.append(json.dumps(m))

    report_file.write_text("\n".join(lines), encoding="utf-8")

    return all_file, ranked_file, suppressed_file, matches_file, suppressed_near_file, report_file


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-dir", default=".")
    p.add_argument("--out-dir", default="v033_output")
    p.add_argument("--max-lines", type=int, default=0)
    p.add_argument("--max-candidate-events", type=int, default=5_000_000)
    p.add_argument("--window", type=int, default=600)
    p.add_argument("--episode-window", type=int, default=300)
    p.add_argument("--validation-window", type=int, default=600)
    p.add_argument("--warmup", type=int, default=50_000)
    p.add_argument("--min-score", type=float, default=0.78)

    # Tuning knobs for v0.3.3 experiments.
    p.add_argument("--gate-a-novelty-threshold", type=float, default=0.25)
    p.add_argument("--gate-a-max-duration", type=int, default=900)
    p.add_argument("--gate-a-max-destinations", type=int, default=24)
    p.add_argument("--velocity-window", type=int, default=120)
    p.add_argument("--velocity-min-new-destinations", type=int, default=3)
    p.add_argument("--gate-b-velocity-threshold", type=float, default=0.60)
    p.add_argument("--low-novelty-ratio", type=float, default=0.25)
    p.add_argument("--enable-low-novelty-suppression", action="store_true")
    p.add_argument("--ranked-limit", type=int, default=0)
    args = p.parse_args()

    base = Path(args.base_dir)
    out = Path(args.out_dir)

    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"

    print("=" * 80)
    print("SRIA RT v0.3.3 - Recall Recovery + Near-Match Rescue")
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
        gate_a_novelty_threshold=args.gate_a_novelty_threshold,
        gate_a_max_duration=args.gate_a_max_duration,
        gate_a_max_destinations=args.gate_a_max_destinations,
        velocity_window=args.velocity_window,
        velocity_min_new_destinations=args.velocity_min_new_destinations,
        gate_b_velocity_threshold=args.gate_b_velocity_threshold,
        low_novelty_ratio=args.low_novelty_ratio,
        suppress_low_novelty_without_velocity=args.enable_low_novelty_suppression,
        ranked_limit=args.ranked_limit,
    )

    detector = PrecisionDetectorV033(config)

    scanned_lines = 0
    candidate_events = 0
    pointer = 0
    observed_min_ts: Optional[int] = None
    observed_max_ts: Optional[int] = None

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
    results = validate(episodes, redteam, args.validation_window, observed_min_ts, observed_max_ts)
    suppressed_near_matches = find_suppressed_near_matches(
        suppressed,
        redteam,
        args.validation_window,
        observed_min_ts,
        observed_max_ts,
    )

    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)
    print(f"  Total redteam events: {results['total_redteam']}")
    print(f"  Matched redteam events: {results['matched_redteam']}")
    print(f"  Recall all: {results['recall']:.2%}")
    print(f"  Redteam in observed auth range: {results['total_redteam_in_observed_range']}")
    print(f"  Matched redteam in observed auth range: {results['matched_redteam_in_observed_range']}")
    print(f"  Recall observed range: {results['recall_observed_range']:.2%}")
    print(f"  Exact-start redteam matches: {results['exact_start_matches']}")
    print(f"  Total accepted episodes: {results['total_episodes']:,}")
    print(f"  Episodes overlapping redteam: {results['matched_episodes']}")
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.8%}")
    print(f"  Suppressed near-match diagnostics: {len(suppressed_near_matches)}")

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

    all_file, ranked_file, suppressed_file, matches_file, suppressed_near_file, report_file = save_outputs(
        out, episodes, suppressed, results, stats, config, suppressed_near_matches
    )

    print(f"\n[output] All accepted episodes: {all_file}")
    print(f"[output] Ranked accepted episodes: {ranked_file}")
    print(f"[output] Suppressed episodes: {suppressed_file}")
    print(f"[output] Matches: {matches_file}")
    print(f"[output] Suppressed near matches: {suppressed_near_file}")
    print(f"[output] Report: {report_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
