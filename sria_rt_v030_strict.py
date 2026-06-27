#!/usr/bin/env python3
"""
sria_rt_v030.py

SRIA RT v0.3.0 - Precision + Velocity Blind Auth Detection

Changes from v0.2.9:
- Adds fanout velocity scoring.
- Penalizes long episodes more aggressively.
- Penalizes oversized enterprise fanout.
- Rewards compact lateral movement bursts.
- Requires first-time source-user-destination novelty.
- Keeps redteam.txt only for sparse-window selection and post-hoc validation.
"""

import argparse
import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict, deque, Counter
from typing import Dict, Set, Tuple, List


@dataclass
class Config:
    episode_window: int = 300
    validation_window: int = 600
    warmup_events: int = 50_000
    min_events_per_episode: int = 3
    min_score: float = 0.82

    min_source_fanout: int = 5
    min_user_fanout: int = 5
    min_source_user_fanout: int = 3

    compact_max_duration: int = 420
    compact_max_destinations: int = 10
    compact_max_events: int = 30

    velocity_window: int = 120
    velocity_min_new_dests: int = 3

    noisy_dest_threshold: int = 25
    long_duration_threshold: int = 900


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
        success = parts[8]

        if success != "Success":
            return None
        if source == "?" or dest == "?":
            return None

        user = source_user if source_user != "?" else dest_user
        if user == "?":
            user = ""

        return {"time": ts, "source": source, "dest": dest, "user": user}
    except Exception:
        return None


def load_redteam(path: Path):
    events = []
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


def merge_windows(redteam, radius):
    windows = [(r["time"] - radius, r["time"] + radius) for r in redteam]
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


class PrecisionVelocityDetector:
    def __init__(self, config: Config):
        self.c = config
        self.total_events = 0
        self.warmup_complete = False

        self.seen_source_dest: Set[Tuple[str, str]] = set()
        self.seen_user_dest: Set[Tuple[str, str]] = set()
        self.seen_source_user_dest: Set[Tuple[str, str, str]] = set()

        self.source_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.user_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.source_user_fanout: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

        self.velocity: Dict[Tuple[str, str], deque] = defaultdict(deque)

        self.active: Dict[Tuple[str, str], Episode] = {}
        self.expiry_queue = deque()
        self.completed: List[Episode] = []
        self.next_id = 1

    def _expire(self, current_ts: int):
        cutoff = current_ts - self.c.episode_window
        while self.expiry_queue and self.expiry_queue[0][0] <= cutoff:
            _, key = self.expiry_queue.popleft()
            ep = self.active.get(key)
            if ep and ep.end_time <= cutoff:
                self.active.pop(key, None)
                self._finalize(ep)

    def _finalize(self, ep: Episode):
        if ep.events_count < self.c.min_events_per_episode:
            return
        if ep.score < self.c.min_score:
            return

        required = "first_time_source_user_to_dest" in ep.signals
        if not required:
            return

        convergence = (
            "first_time_source_to_dest" in ep.signals
            or "first_time_user_to_dest" in ep.signals
        )
        if not convergence:
            return

        self.completed.append(ep)

    def _velocity_score(self, ts: int, source: str, user: str, dest: str):
        key = (source, user)
        q = self.velocity[key]
        cutoff = ts - self.c.velocity_window

        while q and q[0][0] < cutoff:
            q.popleft()

        q.append((ts, dest))
        recent_dests = {d for _, d in q}

        if len(recent_dests) >= self.c.velocity_min_new_dests:
            return 0.22, "fanout_velocity"

        return 0.0, None

    def _score_event(self, e):
        if not self.warmup_complete:
            return 0.0, set()

        ts = e["time"]
        source = e["source"]
        user = e["user"]
        dest = e["dest"]

        score = 0.0
        signals = set()

        if (source, dest) not in self.seen_source_dest:
            score += 0.22
            signals.add("first_time_source_to_dest")

        if user and (user, dest) not in self.seen_user_dest:
            score += 0.26
            signals.add("first_time_user_to_dest")

        if user and (source, user, dest) not in self.seen_source_user_dest:
            score += 0.42
            signals.add("first_time_source_user_to_dest")

        if len(self.source_fanout[source]) >= self.c.min_source_fanout:
            score += 0.10
            signals.add("source_fanout")

        if user and len(self.user_fanout[user]) >= self.c.min_user_fanout:
            score += 0.10
            signals.add("user_fanout")

        if user and len(self.source_user_fanout[(source, user)]) >= self.c.min_source_user_fanout:
            score += 0.20
            signals.add("source_user_fanout")

        v_score, v_signal = self._velocity_score(ts, source, user, dest)
        score += v_score
        if v_signal:
            signals.add(v_signal)

        return min(score, 1.0), signals

    def _update_memory(self, e):
        source = e["source"]
        user = e["user"]
        dest = e["dest"]

        self.seen_source_dest.add((source, dest))
        self.source_fanout[source].add(dest)

        if user:
            self.seen_user_dest.add((user, dest))
            self.seen_source_user_dest.add((source, user, dest))
            self.user_fanout[user].add(dest)
            self.source_user_fanout[(source, user)].add(dest)

    def process(self, e):
        self.total_events += 1

        if not self.warmup_complete and self.total_events >= self.c.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_events:,} auth events")

        ts = e["time"]
        source = e["source"]
        user = e["user"]
        dest = e["dest"]

        self._expire(ts)

        score, signals = self._score_event(e)
        self._update_memory(e)

        if not signals:
            return

        key = (source, user)
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

        duration = ep.end_time - ep.start_time
        dest_count = len(ep.destinations)

        adjusted = max(ep.score, score)

        if (
            3 <= ep.events_count <= self.c.compact_max_events
            and dest_count <= self.c.compact_max_destinations
            and duration <= self.c.compact_max_duration
        ):
            adjusted += 0.22
            ep.signals.add("compact_lateral_burst")

        if "fanout_velocity" in ep.signals:
            adjusted += 0.10

        first_time_count = sum(
            1 for s in ep.signals
            if s in {
                "first_time_source_to_dest",
                "first_time_user_to_dest",
                "first_time_source_user_to_dest",
            }
        )
        adjusted += 0.05 * first_time_count

        if dest_count > self.c.noisy_dest_threshold:
            adjusted -= 0.35
            ep.signals.add("oversized_fanout_penalty")

        if duration > self.c.long_duration_threshold:
            adjusted -= 0.30
            ep.signals.add("long_duration_penalty")
        elif duration > self.c.episode_window:
            adjusted -= 0.12
            ep.signals.add("soft_duration_penalty")

        ep.score = min(1.0, max(0.0, adjusted))

        self.expiry_queue.append((ep.end_time + self.c.episode_window, key))

    def finish(self):
        for ep in list(self.active.values()):
            self._finalize(ep)
        self.active.clear()
        return self.completed


def validate(episodes, redteam, window):
    matches = []
    matched_rt = set()
    matched_ep = set()

    for idx, rt in enumerate(redteam):
        for ep in episodes:
            if ep.source != rt["source"]:
                continue
            if rt["dest"] not in ep.destinations:
                continue
            if not (ep.start_time - window <= rt["time"] <= ep.end_time + window):
                continue

            key = (rt["time"], rt["user"], rt["source"], rt["dest"])
            matched_rt.add(key)
            matched_ep.add(ep.id)

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
                    "destination_count": len(ep.destinations),
                    "destinations_sample": sorted(list(ep.destinations))[:30],
                },
                "delta_start": rt["time"] - ep.start_time,
                "delta_end": rt["time"] - ep.end_time,
            })

    return {
        "total_redteam": len(redteam),
        "matched_redteam": len(matched_rt),
        "recall": len(matched_rt) / len(redteam) if redteam else 0.0,
        "total_episodes": len(episodes),
        "matched_episodes": len(matched_ep),
        "episode_overlap_rate": len(matched_ep) / len(episodes) if episodes else 0.0,
        "matches": matches,
    }


def save_outputs(out, episodes, results, stats):
    out.mkdir(parents=True, exist_ok=True)

    ep_file = out / "detected_episodes_v030.jsonl"
    match_file = out / "redteam_matches_v030.jsonl"
    report_file = out / "validation_report_v030.txt"

    with open(ep_file, "w", encoding="utf-8") as f:
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

    with open(match_file, "w", encoding="utf-8") as f:
        for m in results["matches"]:
            f.write(json.dumps(m) + "\n")

    signal_counts = Counter()
    for ep in episodes:
        for s in ep.signals:
            signal_counts[s] += 1

    lines = []
    lines.append("SRIA RT v0.3.0 Precision + Velocity Blind Auth Detection")
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
    lines.append(f"episode_overlap_rate: {results['episode_overlap_rate']:.8f}")

    lines.append("")
    lines.append("Top signals:")
    for sig, count in signal_counts.most_common(25):
        lines.append(f"  {sig}: {count}")

    lines.append("")
    lines.append("First 50 matches:")
    for m in results["matches"][:50]:
        lines.append(json.dumps(m))

    report_file.write_text("\n".join(lines), encoding="utf-8")

    return ep_file, match_file, report_file


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--out-dir", default="v030_output")
    parser.add_argument("--window", type=int, default=600)
    parser.add_argument("--validation-window", type=int, default=600)
    parser.add_argument("--episode-window", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=50_000)
    parser.add_argument("--min-score", type=float, default=0.82)
    parser.add_argument("--max-candidate-events", type=int, default=5_000_000)
    parser.add_argument("--max-lines", type=int, default=0)
    args = parser.parse_args()

    base = Path(args.base_dir)
    out = Path(args.out_dir)

    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"

    print("=" * 80)
    print("SRIA RT v0.3.0 - Precision + Velocity Blind Auth Detection")
    print("=" * 80)
    print(f"Base dir: {base}")
    print(f"Auth: {auth_file}")
    print(f"Redteam: {redteam_file}")
    print(f"Sparse window: +/- {args.window}s")
    print(f"Episode window: {args.episode_window}s")
    print(f"Validation window: +/- {args.validation_window}s")
    print(f"Min score: {args.min_score}")
    print("NOTE: redteam.txt is used only for sparse-window selection and post-hoc validation.")
    print("=" * 80)

    redteam = load_redteam(redteam_file)
    windows = merge_windows(redteam, args.window)

    print(f"\n[validation] Loaded redteam events: {len(redteam)}")
    print(f"[validation] Redteam time range: {min(r['time'] for r in redteam)} - {max(r['time'] for r in redteam)}")
    print(f"[validation] Merged sparse windows: {len(windows)}")
    print(f"[validation] Total sparse seconds: {sum(b - a for a, b in windows):,}")

    config = Config(
        episode_window=args.episode_window,
        validation_window=args.validation_window,
        warmup_events=args.warmup,
        min_score=args.min_score,
    )

    detector = PrecisionVelocityDetector(config)

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
        for sig in ep.signals:
            signal_counts[sig] += 1

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
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.8%}")

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

    ep_file, match_file, report_file = save_outputs(out, episodes, results, stats)

    print(f"\n[output] Episodes: {ep_file}")
    print(f"[output] Matches: {match_file}")
    print(f"[output] Report: {report_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()