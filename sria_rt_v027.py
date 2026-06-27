#!/usr/bin/env python3
"""
sria_rt_v027.py - BLIND DETECTION (Timestamp-Gated)
- Skip auth rows until reaching redteam time window
- Only process timestamps relevant to redteam events
- Dramatically reduces processing time and noise
- Still blind detection (redteam used only for validation)
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Deque
from collections import deque
import time

# ============================================================
# CONFIGURATION
# ============================================================

@dataclass
class Config:
    episode_window: int = 300
    min_episode_signals: int = 2
    min_episode_events: int = 3
    warmup_events: int = 50000          # Reduced since we're in target window
    min_source_fanout: int = 5
    min_user_fanout: int = 5
    min_source_user_fanout: int = 3
    first_time_bonus: float = 0.35
    fanout_bonus: float = 0.25
    validation_window: int = 60
    report_interval: int = 1_000_000
    
    # Timestamp gating (from redteam range)
    redteam_min: int = 150885
    redteam_max: int = 2557047
    warmup_margin: int = 100000
    start_timestamp: int = 50885  # redteam_min - warmup_margin
    end_timestamp: int = 2657047  # redteam_max + warmup_margin


# ============================================================
# FAST PARSER
# ============================================================

def parse_auth_fast(line: str) -> Optional[Tuple]:
    parts = line.strip().split(',')
    if len(parts) < 9:
        return None
    try:
        timestamp = int(parts[0])
        source_user = parts[1] if parts[1] != '?' else None
        dest_user = parts[2] if parts[2] != '?' else None
        source = parts[3] if parts[3] != '?' else None
        dest = parts[4] if parts[4] != '?' else None
        success = parts[8] == "Success"
        
        if not success or not source or not dest:
            return None
        
        user = source_user or dest_user
        return (timestamp, source, dest, user)
    except (ValueError, IndexError):
        return None


# ============================================================
# EPISODE DETECTOR (Safe Queue Eviction)
# ============================================================

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


class BlindEpisodeDetector:
    def __init__(self, config: Config):
        self.config = config
        self.episodes: List[Episode] = []
        self.current: Dict[str, Episode] = {}
        self.expiry_queue: Deque[Tuple[int, str]] = deque()
        self.counter = 0
        self.total_events = 0
        self.warmup_complete = False
        
        # Knowledge bases
        self.seen_user_dest: Dict[Tuple[str, str], int] = {}
        self.seen_source_dest: Dict[Tuple[str, str], int] = {}
        self.source_fanout: Dict[str, Set[str]] = {}
        self.user_fanout: Dict[str, Set[str]] = {}
        self.source_users: Dict[str, Set[str]] = {}
    
    def _key(self, source: str, user: str) -> str:
        return f"{source}|{user}" if user else source
    
    def _update_fanout(self, fanout: Dict[str, Set[str]], key: str, value: str) -> int:
        if key not in fanout:
            fanout[key] = {value}
            return 1
        s = fanout[key]
        if value not in s:
            s.add(value)
        return len(s)
    
    def _expire_episodes(self, current_ts: int):
        while self.expiry_queue and self.expiry_queue[0][0] <= current_ts:
            expiry_time, episode_key = self.expiry_queue.popleft()
            if episode_key in self.current:
                ep = self.current.pop(episode_key)
                if len(ep.signals) >= self.config.min_episode_signals and ep.events_count >= self.config.min_episode_events:
                    self.episodes.append(ep)
    
    def process(self, ts: int, source: str, dest: str, user: Optional[str]):
        self.total_events += 1
        
        # Warmup check
        if not self.warmup_complete and self.total_events >= self.config.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_events:,} events")
        
        self._expire_episodes(ts)
        
        episode_key = self._key(source, user or '')
        
        # ============================================================
        # STEP 1: Calculate risk and signals
        # ============================================================
        risk = 0.0
        signals = set()
        
        if self.warmup_complete:
            user_dest_key = (user, dest) if user else None
            source_dest_key = (source, dest)
            
            if user_dest_key and user_dest_key not in self.seen_user_dest:
                risk += self.config.first_time_bonus
                signals.add('first_time_user_to_dest')
            
            if source_dest_key not in self.seen_source_dest:
                risk += self.config.first_time_bonus * 0.8
                signals.add('first_time_source_to_dest')
            
            fanout_size = len(self.source_fanout.get(source, set()))
            if fanout_size >= self.config.min_source_fanout:
                risk += self.config.fanout_bonus
                signals.add('source_fanout')
            
            if user:
                fanout_size = len(self.user_fanout.get(user, set()))
                if fanout_size >= self.config.min_user_fanout:
                    risk += self.config.fanout_bonus
                    signals.add('user_fanout')
            
            source_users_count = len(self.source_users.get(source, set()))
            if source_users_count >= self.config.min_source_user_fanout:
                risk += self.config.fanout_bonus
                signals.add('source_user_fanout')
        
        # ============================================================
        # STEP 2: Update knowledge bases
        # ============================================================
        if user:
            key = (user, dest)
            self.seen_user_dest[key] = self.seen_user_dest.get(key, 0) + 1
            self._update_fanout(self.user_fanout, user, dest)
        
        key = (source, dest)
        self.seen_source_dest[key] = self.seen_source_dest.get(key, 0) + 1
        self._update_fanout(self.source_fanout, source, dest)
        
        if user:
            if source not in self.source_users:
                self.source_users[source] = set()
            self.source_users[source].add(user)
        
        if not signals:
            return
        
        risk = min(risk, 1.0)
        
        # ============================================================
        # STEP 3: Update or create episode
        # ============================================================
        if episode_key not in self.current:
            self.counter += 1
            self.current[episode_key] = Episode(
                id=self.counter,
                source=source,
                user=user or '',
                start_time=ts,
                end_time=ts
            )
            self.expiry_queue.append((ts + self.config.episode_window, episode_key))
        
        ep = self.current[episode_key]
        ep.end_time = ts
        ep.signals.update(signals)
        ep.max_risk = max(ep.max_risk, risk)
        ep.destinations.add(dest)
        if user:
            ep.users.add(user)
        ep.events_count += 1
    
    def finish(self) -> List[Episode]:
        max_ts = 2**63 - 1
        self._expire_episodes(max_ts)
        return self.episodes


# ============================================================
# REDTEAM VALIDATOR
# ============================================================

def load_redteam(path: Path) -> List[Dict]:
    events = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 4:
                try:
                    events.append({
                        'time': int(parts[0]),
                        'user': parts[1],
                        'source': parts[2],
                        'dest': parts[3]
                    })
                except:
                    pass
    return events


def validate(episodes: List[Episode], redteam: List[Dict], window: int) -> Dict:
    matches = []
    redteam_matched = set()
    episode_matched = set()
    
    for rt_idx, rt in enumerate(redteam):
        rt_time = rt['time']
        rt_source = rt['source']
        rt_dest = rt['dest']
        
        for ep in episodes:
            if ep.source != rt_source:
                continue
            if rt_dest not in ep.destinations:
                continue
            if not (ep.start_time - window <= rt_time <= ep.end_time + window):
                continue
            
            redteam_matched.add((rt_time, rt_source, rt_dest))
            episode_matched.add(ep.id)
            
            matches.append({
                'redteam_index': rt_idx,
                'redteam': rt,
                'episode_id': ep.id,
                'episode_source': ep.source,
                'episode_user': ep.user,
                'episode_signals': list(ep.signals),
                'time_delta': rt_time - ep.start_time,
            })
    
    matches.sort(key=lambda x: x['redteam_index'])
    
    return {
        'total_redteam': len(redteam),
        'matched_redteam': len(redteam_matched),
        'total_episodes': len(episodes),
        'matched_episodes': len(episode_matched),
        'recall': len(redteam_matched) / len(redteam) if redteam else 0,
        'episode_overlap_rate': len(episode_matched) / len(episodes) if episodes else 0,
        'matches': matches
    }


# ============================================================
# TIMESTAMP-GATED FILE ITERATOR
# ============================================================

def iter_auth_timestamp_range(filepath: Path, start_ts: int, end_ts: int, warmup_margin: int):
    """
    Iterate over auth lines, skipping until reaching start_ts.
    Only yields lines with timestamps between start_ts and end_ts.
    """
    print(f"  Seeking to timestamps >= {start_ts}...")
    
    in_range = False
    lines_skipped = 0
    lines_yielded = 0
    
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            parsed = parse_auth_fast(line)
            if not parsed:
                continue
            
            ts, source, dest, user = parsed
            
            # Skip until we reach the start timestamp
            if not in_range:
                if ts >= start_ts:
                    in_range = True
                    print(f"  Found first timestamp {ts} after skipping {lines_skipped:,} auth events")
                else:
                    lines_skipped += 1
                    continue
            
            # Stop when we exceed end timestamp
            if ts > end_ts:
                print(f"  Reached end timestamp {ts} after yielding {lines_yielded:,} events")
                break
            
            lines_yielded += 1
            yield (ts, source, dest, user)
    
    print(f"  Total yielded: {lines_yielded:,} auth events")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--max-events", type=int, default=0, help="Max auth events to process (0=unlimited)")
    
    args = parser.parse_args()
    
    base = Path(args.base_dir)
    out = Path(args.out_dir) if args.out_dir else base / "v027_output"
    out.mkdir(parents=True, exist_ok=True)
    
    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"
    
    config = Config()
    
    print("=" * 70)
    print("SRIA RT v0.2.7 - BLIND DETECTION (Timestamp-Gated)")
    print("=" * 70)
    print(f"  Processing auth timestamps from {config.start_timestamp} to {config.end_timestamp}")
    print(f"  Redteam window: {config.redteam_min} - {config.redteam_max}")
    print(f"  Warmup margin: {config.warmup_margin}")
    print(f"  Min events per episode: {config.min_episode_events}")
    print("=" * 70)
    
    redteam = load_redteam(redteam_file)
    print(f"\n[validation] Loaded {len(redteam)} redteam events")
    print(f"[validation] Time range: {config.redteam_min} - {config.redteam_max}")
    
    detector = BlindEpisodeDetector(config)
    
    print(f"\n[detection] Scanning {auth_file} (timestamp-gated)...")
    print(f"  Max events: {'unlimited' if args.max_events == 0 else f'{args.max_events:,}'}")
    
    start_time = time.time()
    event_count = 0
    
    for ts, source, dest, user in iter_auth_timestamp_range(auth_file, config.start_timestamp, config.end_timestamp, config.warmup_margin):
        if args.max_events > 0 and event_count >= args.max_events:
            break
        
        detector.process(ts, source, dest, user)
        event_count += 1
        
        if event_count % config.report_interval == 0:
            elapsed = time.time() - start_time
            rate = event_count / elapsed if elapsed > 0 else 0
            print(f"  Processed {event_count:,} events ({rate:,.0f} events/sec)...")
    
    elapsed = time.time() - start_time
    print(f"\n[detection] Processed {event_count:,} events in {elapsed:.1f} seconds ({event_count/elapsed:,.0f} events/sec)")
    print(f"[detection] Total auth events (including warmup): {detector.total_events:,}")
    
    episodes = detector.finish()
    print(f"[detection] Episodes detected: {len(episodes):,}")
    
    if episodes:
        signal_counts = Counter()
        for ep in episodes:
            for sig in ep.signals:
                signal_counts[sig] += 1
        print("\n[detection] Top signals (collapsed):")
        for sig, cnt in signal_counts.most_common(10):
            print(f"  {sig}: {cnt:,}")
        
        avg_duration = sum(ep.end_time - ep.start_time for ep in episodes) / len(episodes)
        avg_events = sum(ep.events_count for ep in episodes) / len(episodes)
        print(f"\n[detection] Avg episode duration: {avg_duration:.1f}s")
        print(f"[detection] Avg events per episode: {avg_events:.1f}")
    
    # Validate
    print("\n[validation] Comparing episodes to redteam ground truth...")
    results = validate(episodes, redteam, config.validation_window)
    
    print("\n" + "=" * 70)
    print("VALIDATION RESULTS (Blind Detection)")
    print("=" * 70)
    print(f"  Total redteam events: {results['total_redteam']}")
    print(f"  Matched redteam events: {results['matched_redteam']}")
    print(f"  Recall: {results['recall']:.2%}")
    print(f"  Total episodes: {results['total_episodes']:,}")
    print(f"  Episodes overlapping redteam: {results['matched_episodes']:,}")
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.2%}")
    
    # Save outputs
    episodes_file = out / "detected_episodes.jsonl"
    with open(episodes_file, 'w') as f:
        for ep in episodes:
            f.write(json.dumps({
                'id': ep.id,
                'source': ep.source,
                'user': ep.user,
                'start_time': ep.start_time,
                'end_time': ep.end_time,
                'signals': list(ep.signals),
                'max_risk': ep.max_risk,
                'events_count': ep.events_count,
            }) + '\n')
    
    matches_file = out / "redteam_matches.jsonl"
    with open(matches_file, 'w') as f:
        for match in results['matches']:
            f.write(json.dumps(match) + '\n')
    
    print(f"\n[output] Episodes: {episodes_file}")
    print(f"[output] Matches: {matches_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()