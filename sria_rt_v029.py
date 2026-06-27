#!/usr/bin/env python3
"""
sria_rt_v029.py

SRIA RT v0.2.9 - Precision-Shaped Blind Auth Detection

Goal:
- Preserve the real red-team overlap found in v0.2.8.
- Reduce massive fanout-only noise.
- Require first-time edge evidence for high-confidence episodes.
- Reward compact lateral-movement bursts.
- Penalize oversized generic enterprise fanout.

IMPORTANT:
- redteam.txt is used ONLY for post-hoc validation.
- Detection/scoring uses auth.txt only.
"""

import argparse
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict, deque, Counter
from typing import Optional, Dict, Set, Tuple, List


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
    min_score: float = 0.75

    min_source_fanout: int = 5
    min_user_fanout: int = 5
    min_source_user_fanout: int = 3

    max_compact_destinations: int = 10
    noisy_destination_penalty_threshold: int = 25


@dataclass
class Episode:
    id: int
    source: str
    user: str
    start_time: int
    end_time: int
    events_count: int = 0
    destinations: Set[str] = field(default_factory=set)
    signals: Set[str] = field(default_factory=set)
    score: float = 0.0
    max_risk: float = 0.0


# ============================================================
# PARSING
# ============================================================

def parse_auth_line(line: str):
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


def load_redteam(path: Path):
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

class PrecisionDetector:
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
        self.next_id = 1

    def _episode_key(self, source: str, user: str):
        return (source, user)

    def _expire(self, current_ts: int):
        cutoff = current_ts - self.c.episode_window

        while self.expiry_queue and self.expiry_queue[0][0] <= cutoff:
            _, key = self.expiry_queue.popleft()
            ep = self.active.get(key)

            if ep is None:
                continue

            if ep.end_time <= cutoff:
                self.active.pop(key, None)
                self._finalize(ep)

    def _finalize(self, ep: Episode):
        if ep.events_count < self.c.min_events_per_episode:
            return

        if ep.score < self.c.min_score:
            return

        # Core precision rule:
        # Fanout-only is too noisy. Require at least one first-time edge.
        has_first_time = (
            "first_time_source_to_dest" in ep.signals
            or "first_time_user_to_dest" in ep.signals
            or "first_time_source_user_to_dest" in ep.signals
        )

        if not has_first_time:
            return

        self.completed.append(ep)

    def _score_event(self, event):
        source = event["source"]
        user = event["user"]
        dest = event["dest"]

        signals = set()
        score = 0.0

        if not self.warmup_complete:
            return score, signals

        if (source, dest) not in self.seen_source_dest:
            signals.add("first_time_source_to_dest")
            score += 0.28

        if user and (user, dest) not in self.seen_user_dest:
            signals.add("first_time_user_to_dest")
            score += 0.32

        if user and (source, user, dest) not in self.seen_source_user_dest:
            signals.add("first_time_source_user_to_dest")
            score += 0.38

        sf = len(self.source_fanout[source])
        uf = len(self.user_fanout[user]) if user else 0
        suf = len(self.source_user_fanout[(source, user)]) if user else 0

        if sf >= self.c.min_source_fanout:
            signals.add("source_fanout")
            score += 0.14

        if uf >= self.c.min_user_fanout:
            signals.add("user_fanout")
            score += 0.14

        if suf >= self.c.min_source_user_fanout:
            signals.add("source_user_fanout")
            score += 0.24

        return min(score, 1.0), signals

    def _update_memory(self, event):
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

    def process(self, event):
        self.total_events += 1

        if not self.warmup_complete and self.total_events >= self.c.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_events:,} auth events")

        ts = event["time"]
        source = event["source"]
        user = event["user"]
        dest = event["dest"]

        self._expire(ts)

        score, signals = self._score_event(event)
        self._update_memory(event)

        if not signals:
            return

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

        ep.end_time = ts
        ep.events_count += 1
        ep.destinations.add(dest)
        ep.signals.update(signals)
        ep.max_risk = max(ep.max_risk, score)

        # Episode-level precision shaping
        duration = max(1, ep.end_time - ep.start_time)
        dest_count = len(ep.destinations)

        compact_bonus = 0.0
        if 3 <= ep.events_count <= 25 and dest_count <= self.c.max_compact_destinations and duration <= self.c.episode_window:
            compact_bonus = 0.18
            ep.signals.add("compact_lateral_burst")

        first_time_count = sum(
            1 for s in ep.signals
            if s in {
                "first_time_source_to_dest",
                "first_time_user_to_dest",
                "first_time_source_user_to_dest",
            }
        )

        first_time_bonus = 0.08 * first_time_count

        penalty = 0.0
        if dest_count > self.c.noisy_destination_penalty_threshold:
            penalty += 0.30
            ep.signals.add("oversized_fanout_penalty")

        if duration > self.c.episode_window:
            penalty += 0.15

        base = max(ep.score, score)
        ep.score = min(1.0, max(0.0, base + compact_bonus + first_time_bonus - penalty))

        self.expiry_queue.append((ep.end_time + self.c.episode_window, key))

    def finish(self):
        for ep in list(self.active.values()):
            self._finalize(ep)
        self.active.clear()
        return self.completed


# ============================================================
# VALIDATION
# ============================================================

def validate(episodes: List[Episode], redteam: List[dict], window: int):
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
                "episode": {
                    "id": ep.id,
                    "source": ep.source,
                    "user": ep.user,
                    "start_time": ep.start_time,
                    "end_time": ep.end_time,
                    "duration": ep.end_time - ep.start_time,
                    "events_count": ep.events_count,
                    "score": round(ep.score, 4),
                    "max_risk": round(ep.max_risk, 4),
                    "signals": sorted(ep.signals),
                    "destinations_sample": sorted(list(ep.destinations))[:30],
                    "destination_count": len(ep.destinations),
                },
                "delta_start": rt_time - ep.start_time,
                "delta_end": rt_time - ep.end_time,
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

def merge_windows(redteam, radius):
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


def in_windows(ts, windows, pointer):
    while pointer < len(windows) and ts > windows[pointer][1]:
        pointer += 1

    if pointer >= len(windows):
        return False, pointer

    start, end = windows[pointer]
    return start <= ts <= end, pointer


# ============================================================
# OUTPUT
# ============================================================

def save_outputs(out_dir: Path, episodes: List[Episode], results: dict, stats: dict):
    out_dir.mkdir(parents=True, exist_ok=True)

    episodes_file = out_dir / "detected_episodes_v029.jsonl"
    matches_file = out_dir / "redteam_matches_v029.jsonl"
    report_file = out_dir / "validation_report_v029.txt"

    with open(episodes_file, "w", encoding="utf-8") as f:
        for ep in episodes:
            f.write(json.dumps({
                "id": ep.id,
                "source": ep.source,
                "user": ep.user,
                "start_time": ep.start_time,
                "end_time": ep.end_time,
                "duration": ep.end_time - ep.start_time,
                "events_count": ep.events_count,
                "score": round(ep.score, 4),
                "max_risk": round(ep.max_risk, 4),
                "signals": sorted(ep.signals),
                "destination_count": len(ep.destinations),
                "destinations_sample": sorted(list(ep.destinations))[:50],
            }) + "\n")

    with open(matches_file, "w", encoding="utf-8") as f:
        for m in results["matches"]:
            f.write(json.dumps(m) + "\n")

    lines = []
    lines.append("SRIA RT v0.2.9 Precision-Shaped Blind Auth Detection")
    lines.append("=" * 80)
    for k, v in stats.items():
        lines.append(f"{k}: {v}")

    lines.append("")
    lines.append("Validation:")
    lines.append(f"total_redteam: {results['total_redteam']}")
    lines.append(f"matched_redteam: {results['matched_redteam']}")
    lines.append(f"recall: {results['recall']:.4f}")
    lines.append(f"total_episodes: {results['total_episodes']}")
    lines.append(f"matched_episodes: {results['matched_episodes']}")
    lines.append(f"episode_overlap_rate: {results['episode_overlap_rate']:.6f}")

    lines.append("")
    lines.append("Top episode signals:")
    signal_counts = Counter()
    for ep in episodes:
        for s in ep.signals:
            signal_counts[s] += 1

    for sig, count in signal_counts.most_common(20):
        lines.append(f"  {sig}: {count}")

    lines.append("")
    lines.append("First 30 matches:")
    for m in results["matches"][:30]:
        lines.append(json.dumps(m))

    report_file.write_text("\n".join(lines), encoding="utf-8")

    return episodes_file, matches_file, report_file


# ============================================================
# MAIN
# ============================================================

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-dir", default=".")
    p.add_argument("--out-dir", default="v029_output")
    p.add_argument("--max-lines", type=int, default=0)
    p.add_argument("--max-candidate-events", type=int, default=5_000_000)
    p.add_argument("--window", type=int, default=600)
    p.add_argument("--episode-window", type=int, default=300)
    p.add_argument("--validation-window", type=int, default=600)
    p.add_argument("--warmup", type=int, default=50_000)
    p.add_argument("--min-score", type=float, default=0.75)
    args = p.parse_args()

    base = Path(args.base_dir)
    out = Path(args.out_dir)

    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"

    print("=" * 80)
    print("SRIA RT v0.2.9 - Precision-Shaped Blind Auth Detection")
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
    )

    detector = PrecisionDetector(config)

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

    episodes = detector.finish()

    elapsed = time.time() - start
    print("\n[detection] Finished")
    print(f"  scanned_lines: {scanned_lines:,}")
    print(f"  candidate_events_in_sparse_windows: {candidate_events:,}")
    print(f"  auth_time_observed: {observed_min_ts} - {observed_max_ts}")
    print(f"  elapsed: {elapsed:.1f}s")
    print(f"  candidate_rate: {candidate_events / elapsed:,.0f}/sec" if elapsed else "  candidate_rate: n/a")
    print(f"  episodes_detected: {len(episodes):,}")

    signal_counts = Counter()
    for ep in episodes:
        for s in ep.signals:
            signal_counts[s] += 1

    print("\n[detection] Top signals:")
    for sig, count in signal_counts.most_common(15):
        print(f"  {sig}: {count:,}")

    print("\n[validation] Comparing episodes to redteam ground truth...")
    results = validate(episodes, redteam, args.validation_window)

    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)
    print(f"  Total redteam events: {results['total_redteam']}")
    print(f"  Matched redteam events: {results['matched_redteam']}")
    print(f"  Recall: {results['recall']:.2%}")
    print(f"  Total episodes: {results['total_episodes']:,}")
    print(f"  Episodes overlapping redteam: {results['matched_episodes']}")
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.6%}")

    stats = {
        "scanned_lines": scanned_lines,
        "candidate_events_in_sparse_windows": candidate_events,
        "auth_time_observed": f"{observed_min_ts} - {observed_max_ts}",
        "elapsed_seconds": round(elapsed, 1),
        "episodes_detected": len(episodes),
        "min_score": args.min_score,
        "episode_window": args.episode_window,
        "validation_window": args.validation_window,
    }

    episodes_file, matches_file, report_file = save_outputs(out, episodes, results, stats)

    print(f"\n[output] Episodes: {episodes_file}")
    print(f"[output] Matches: {matches_file}")
    print(f"[output] Report: {report_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
