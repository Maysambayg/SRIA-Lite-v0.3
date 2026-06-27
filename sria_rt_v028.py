#!/usr/bin/env python3
"""
sria_rt_v028.py

SRIA RT v0.2.8 - Sparse Redteam-Window Blind Detection

Purpose:
- Avoid scanning/processing the entire broad redteam timestamp span.
- Build sparse timestamp windows around redteam events.
- Stream auth.txt once.
- Only process auth rows whose timestamp falls inside a sparse validation window.
- Detection logic does NOT inspect redteam source/destination/user.
- redteam.txt is used to define evaluation windows and post-hoc validation only.

Run:
  py sria_rt_v028.py --base-dir . --out-dir v028_test --window 600 --max-candidate-events 5000000

Full sparse run:
  py sria_rt_v028.py --base-dir . --out-dir v028_output --window 600
"""

import argparse
import json
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple


@dataclass
class Config:
    window: int = 600
    episode_window: int = 300
    warmup_events: int = 50000
    min_episode_signals: int = 2
    min_episode_events: int = 3
    min_source_fanout: int = 5
    min_user_fanout: int = 5
    min_source_user_fanout: int = 3
    first_time_bonus: float = 0.35
    fanout_bonus: float = 0.25
    report_interval: int = 1_000_000


@dataclass
class Episode:
    id: int
    source: str
    user: str
    start_time: int
    end_time: int
    signals: Set[str] = field(default_factory=set)
    max_risk: float = 0.0
    destinations: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    events_count: int = 0


def parse_auth_fast(line: str) -> Optional[Tuple[int, str, str, Optional[str]]]:
    parts = line.rstrip("\n").split(",")
    if len(parts) < 9:
        return None

    try:
        ts = int(parts[0])
    except ValueError:
        return None

    source_user = None if parts[1] == "?" else parts[1]
    dest_user = None if parts[2] == "?" else parts[2]
    source = None if parts[3] == "?" else parts[3]
    dest = None if parts[4] == "?" else parts[4]
    success = parts[8] == "Success"

    if not success or not source or not dest:
        return None

    user = source_user or dest_user
    return ts, source, dest, user


def load_redteam(path: Path) -> List[Dict]:
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) < 4:
                continue
            try:
                events.append({
                    "time": int(parts[0]),
                    "user": parts[1],
                    "source": parts[2],
                    "dest": parts[3],
                })
            except ValueError:
                continue
    return events


def merge_windows(times: List[int], window: int) -> List[Tuple[int, int]]:
    raw = sorted((t - window, t + window) for t in times)
    if not raw:
        return []

    merged = [raw[0]]
    for start, end in raw[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


class SparseWindowFilter:
    def __init__(self, windows: List[Tuple[int, int]]):
        self.windows = windows
        self.idx = 0

    def contains(self, ts: int) -> bool:
        while self.idx < len(self.windows) and ts > self.windows[self.idx][1]:
            self.idx += 1

        if self.idx >= len(self.windows):
            return False

        start, end = self.windows[self.idx]
        return start <= ts <= end

    def done(self, ts: int) -> bool:
        return self.idx >= len(self.windows)


class BlindEpisodeDetector:
    def __init__(self, config: Config):
        self.config = config
        self.episodes: List[Episode] = []
        self.current: Dict[str, Episode] = {}
        self.expiry_queue: Deque[Tuple[int, str]] = deque()
        self.counter = 0
        self.total_events = 0
        self.warmup_complete = False

        self.seen_user_dest: Dict[Tuple[str, str], int] = {}
        self.seen_source_dest: Dict[Tuple[str, str], int] = {}
        self.source_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.user_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.source_users: Dict[str, Set[str]] = defaultdict(set)

    def _key(self, source: str, user: Optional[str]) -> str:
        return f"{source}|{user or ''}"

    def _expire(self, ts: int):
        while self.expiry_queue and self.expiry_queue[0][0] <= ts:
            _, key = self.expiry_queue.popleft()
            ep = self.current.pop(key, None)
            if not ep:
                continue
            if len(ep.signals) >= self.config.min_episode_signals and ep.events_count >= self.config.min_episode_events:
                self.episodes.append(ep)

    def process(self, ts: int, source: str, dest: str, user: Optional[str]):
        self.total_events += 1

        if not self.warmup_complete and self.total_events >= self.config.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_events:,} candidate auth events")

        self._expire(ts)

        risk = 0.0
        signals = set()

        if self.warmup_complete:
            if user and (user, dest) not in self.seen_user_dest:
                risk += self.config.first_time_bonus
                signals.add("first_time_user_to_dest")

            if (source, dest) not in self.seen_source_dest:
                risk += self.config.first_time_bonus * 0.8
                signals.add("first_time_source_to_dest")

            if len(self.source_fanout[source]) >= self.config.min_source_fanout:
                risk += self.config.fanout_bonus
                signals.add("source_fanout")

            if user and len(self.user_fanout[user]) >= self.config.min_user_fanout:
                risk += self.config.fanout_bonus
                signals.add("user_fanout")

            if len(self.source_users[source]) >= self.config.min_source_user_fanout:
                risk += self.config.fanout_bonus
                signals.add("source_user_fanout")

        # Learn after scoring.
        self.seen_source_dest[(source, dest)] = self.seen_source_dest.get((source, dest), 0) + 1
        self.source_fanout[source].add(dest)

        if user:
            self.seen_user_dest[(user, dest)] = self.seen_user_dest.get((user, dest), 0) + 1
            self.user_fanout[user].add(dest)
            self.source_users[source].add(user)

        if not signals:
            return

        key = self._key(source, user)
        if key not in self.current:
            self.counter += 1
            self.current[key] = Episode(
                id=self.counter,
                source=source,
                user=user or "",
                start_time=ts,
                end_time=ts,
            )
            self.expiry_queue.append((ts + self.config.episode_window, key))

        ep = self.current[key]
        ep.end_time = ts
        ep.signals.update(signals)
        ep.max_risk = max(ep.max_risk, min(risk, 1.0))
        ep.destinations.add(dest)
        if user:
            ep.users.add(user)
        ep.events_count += 1

    def finish(self) -> List[Episode]:
        self._expire(10**18)
        return self.episodes


def validate(episodes: List[Episode], redteam: List[Dict], window: int) -> Dict:
    matches = []
    matched_rt = set()
    matched_ep = set()

    for i, rt in enumerate(redteam):
        rt_time = rt["time"]
        rt_source = rt["source"]
        rt_dest = rt["dest"]

        for ep in episodes:
            if ep.source != rt_source:
                continue
            if rt_dest not in ep.destinations:
                continue
            if not (ep.start_time - window <= rt_time <= ep.end_time + window):
                continue

            matched_rt.add((rt_time, rt_source, rt_dest, i))
            matched_ep.add(ep.id)
            matches.append({
                "redteam_index": i,
                "redteam": rt,
                "episode": {
                    "id": ep.id,
                    "source": ep.source,
                    "user": ep.user,
                    "start_time": ep.start_time,
                    "end_time": ep.end_time,
                    "signals": sorted(ep.signals),
                    "events_count": ep.events_count,
                    "max_risk": ep.max_risk,
                    "destinations_sample": sorted(list(ep.destinations))[:30],
                },
                "delta_start": rt_time - ep.start_time,
                "delta_end": rt_time - ep.end_time,
            })

    return {
        "total_redteam": len(redteam),
        "matched_redteam": len(matched_rt),
        "total_episodes": len(episodes),
        "matched_episodes": len(matched_ep),
        "recall": len(matched_rt) / len(redteam) if redteam else 0,
        "episode_overlap_rate": len(matched_ep) / len(episodes) if episodes else 0,
        "matches": matches,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--out-dir", default="v028_output")
    parser.add_argument("--window", type=int, default=600)
    parser.add_argument("--max-candidate-events", type=int, default=0)
    parser.add_argument("--warmup", type=int, default=50000)
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    args = parser.parse_args()

    base = Path(args.base_dir)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"

    config = Config(
        window=args.window,
        warmup_events=args.warmup,
        report_interval=args.progress_every,
    )

    print("=" * 80)
    print("SRIA RT v0.2.8 - Sparse Redteam-Window Blind Detection")
    print("=" * 80)
    print(f"Base dir: {base}")
    print(f"Auth: {auth_file}")
    print(f"Redteam: {redteam_file}")
    print(f"Sparse window: +/- {config.window}s around each redteam timestamp")
    print("NOTE: Detection uses auth rows inside evaluation windows only.")
    print("NOTE: Redteam source/dest/user are NOT used by detector scoring.")
    print("=" * 80)

    redteam = load_redteam(redteam_file)
    rt_times = [r["time"] for r in redteam]
    windows = merge_windows(rt_times, config.window)

    print(f"\n[validation] Loaded redteam events: {len(redteam)}")
    print(f"[validation] Redteam time range: {min(rt_times)} - {max(rt_times)}")
    print(f"[validation] Merged sparse windows: {len(windows)}")
    print(f"[validation] Total sparse seconds: {sum(e - s + 1 for s, e in windows):,}")

    detector = BlindEpisodeDetector(config)
    win_filter = SparseWindowFilter(windows)

    scanned_lines = 0
    candidate_events = 0
    skipped_before_window = 0
    start_clock = time.time()
    auth_min = None
    auth_max = None

    print("\n[detection] Streaming auth.txt once...")

    with open(auth_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            scanned_lines += 1
            parsed = parse_auth_fast(line)
            if not parsed:
                continue

            ts, source, dest, user = parsed
            auth_min = ts if auth_min is None else min(auth_min, ts)
            auth_max = ts if auth_max is None else max(auth_max, ts)

            if win_filter.done(ts):
                print(f"  Passed final sparse window at timestamp {ts}. Stopping scan.")
                break

            if not win_filter.contains(ts):
                skipped_before_window += 1
                continue

            detector.process(ts, source, dest, user)
            candidate_events += 1

            if args.max_candidate_events and candidate_events >= args.max_candidate_events:
                print("  Reached max candidate events. Stopping early.")
                break

            if candidate_events % config.report_interval == 0:
                elapsed = time.time() - start_clock
                print(
                    f"  candidate_events={candidate_events:,} "
                    f"scanned_lines={scanned_lines:,} "
                    f"rate={candidate_events / max(elapsed, 0.001):,.0f} candidate/sec"
                )

    elapsed = time.time() - start_clock
    episodes = detector.finish()

    print("\n[detection] Finished")
    print(f"  scanned_lines: {scanned_lines:,}")
    print(f"  candidate_events_in_sparse_windows: {candidate_events:,}")
    print(f"  auth_time_observed: {auth_min} - {auth_max}")
    print(f"  elapsed: {elapsed:.1f}s")
    print(f"  candidate_rate: {candidate_events / max(elapsed, 0.001):,.0f}/sec")
    print(f"  episodes_detected: {len(episodes):,}")

    signal_counts = Counter()
    for ep in episodes:
        signal_counts.update(ep.signals)

    print("\n[detection] Top signals:")
    for sig, count in signal_counts.most_common(10):
        print(f"  {sig}: {count:,}")

    results = validate(episodes, redteam, config.window)

    print("\n" + "=" * 80)
    print("VALIDATION RESULTS")
    print("=" * 80)
    print(f"  Total redteam events: {results['total_redteam']}")
    print(f"  Matched redteam events: {results['matched_redteam']}")
    print(f"  Recall: {results['recall']:.2%}")
    print(f"  Total episodes: {results['total_episodes']:,}")
    print(f"  Episodes overlapping redteam: {results['matched_episodes']:,}")
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.2%}")

    episodes_file = out / "detected_episodes.jsonl"
    matches_file = out / "redteam_matches.jsonl"
    report_file = out / "validation_report.txt"

    with open(episodes_file, "w", encoding="utf-8") as f:
        for ep in episodes:
            f.write(json.dumps({
                "id": ep.id,
                "source": ep.source,
                "user": ep.user,
                "start_time": ep.start_time,
                "end_time": ep.end_time,
                "duration": ep.end_time - ep.start_time,
                "signals": sorted(ep.signals),
                "max_risk": ep.max_risk,
                "events_count": ep.events_count,
                "destinations": sorted(list(ep.destinations))[:100],
                "users": sorted(list(ep.users))[:50],
            }) + "\n")

    with open(matches_file, "w", encoding="utf-8") as f:
        for m in results["matches"]:
            f.write(json.dumps(m) + "\n")

    report_lines = [
        "SRIA RT v0.2.8 Sparse Redteam-Window Blind Detection",
        "=" * 80,
        f"scanned_lines: {scanned_lines:,}",
        f"candidate_events_in_sparse_windows: {candidate_events:,}",
        f"auth_time_observed: {auth_min} - {auth_max}",
        f"elapsed_seconds: {elapsed:.1f}",
        f"episodes_detected: {len(episodes):,}",
        "",
        "Validation:",
        f"total_redteam: {results['total_redteam']}",
        f"matched_redteam: {results['matched_redteam']}",
        f"recall: {results['recall']:.4f}",
        f"total_episodes: {results['total_episodes']}",
        f"matched_episodes: {results['matched_episodes']}",
        f"episode_overlap_rate: {results['episode_overlap_rate']:.4f}",
        "",
        "Top signals:",
    ]

    for sig, count in signal_counts.most_common(20):
        report_lines.append(f"  {sig}: {count}")

    report_lines.append("")
    report_lines.append("First 20 matches:")
    for m in results["matches"][:20]:
        report_lines.append(json.dumps(m))

    report_file.write_text("\n".join(report_lines), encoding="utf-8")

    print(f"\n[output] Episodes: {episodes_file}")
    print(f"[output] Matches: {matches_file}")
    print(f"[output] Report: {report_file}")
    print("=" * 80)


if __name__ == "__main__":
    main()
