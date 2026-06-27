#!/usr/bin/env python3
"""
sria_rt_v024.py - BLIND DETECTION (Fixed)
- Bounded episode eviction (no memory leak)
- Correct scoring order (fanout after update is intentional but documented)
- Proper time window validation
- Detailed match output for analysis
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
import time

# ============================================================
# CONFIGURATION
# ============================================================

@dataclass
class Config:
    episode_window: int = 300
    min_episode_signals: int = 2
    warmup_events: int = 100000
    min_source_fanout: int = 5
    min_user_fanout: int = 5
    first_time_bonus: float = 0.35
    fanout_bonus: float = 0.25
    validation_window: int = 60
    report_interval: int = 5_000_000


# ============================================================
# FAST PARSER
# ============================================================

def parse_auth_fast(line: str) -> Optional[Tuple]:
    """Parse auth line, return (timestamp, source, dest, user) or None"""
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
# EPISODE DETECTOR (Blind - No redteam knowledge)
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
        self.counter = 0
        self.total_events = 0
        self.warmup_complete = False
        
        # Knowledge bases
        self.seen_user_dest: Dict[Tuple[str, str], int] = {}
        self.seen_source_dest: Dict[Tuple[str, str], int] = {}
        self.source_fanout: Dict[str, Set[str]] = {}
        self.user_fanout: Dict[str, Set[str]] = {}
        
        # For periodic cleanup
        self.last_cleanup_ts = 0
    
    def _key(self, source: str, user: str) -> str:
        return f"{source}|{user}" if user else source
    
    def _update_fanout(self, fanout: Dict[str, Set[str]], key: str, dest: str) -> int:
        if key not in fanout:
            fanout[key] = {dest}
            return 1
        s = fanout[key]
        if dest not in s:
            s.add(dest)
        return len(s)
    
    def _expire_episodes(self, current_ts: int):
        """Expire episodes that have exceeded the window"""
        expired = []
        for key, ep in self.current.items():
            if current_ts - ep.start_time > self.config.episode_window:
                expired.append(key)
        
        for key in expired:
            ep = self.current.pop(key)
            if len(ep.signals) >= self.config.min_episode_signals:
                self.episodes.append(ep)
    
    def process(self, ts: int, source: str, dest: str, user: Optional[str]):
        self.total_events += 1
        
        # Warmup check
        if not self.warmup_complete and self.total_events >= self.config.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_events:,} events")
        
        # Periodic episode expiration
        if ts - self.last_cleanup_ts > self.config.episode_window:
            self._expire_episodes(ts)
            self.last_cleanup_ts = ts
        
        episode_key = self._key(source, user or '')
        
        # ============================================================
        # STEP 1: Calculate risk and signals (using current state)
        # ============================================================
        risk = 0.0
        signals = set()
        
        if self.warmup_complete:
            user_dest_key = (user, dest) if user else None
            source_dest_key = (source, dest)
            
            # First-time user to destination
            if user_dest_key and user_dest_key not in self.seen_user_dest:
                risk += self.config.first_time_bonus
                signals.add('first_time_user_to_dest')
            
            # First-time source to destination
            if source_dest_key not in self.seen_source_dest:
                risk += self.config.first_time_bonus * 0.8
                signals.add('first_time_source_to_dest')
            
            # Source fanout (NOTE: uses state from previous events, not including this one)
            fanout_size = len(self.source_fanout.get(source, set()))
            if fanout_size >= self.config.min_source_fanout:
                risk += self.config.fanout_bonus
                signals.add(f'source_fanout_{fanout_size}')
            
            # User fanout
            if user:
                fanout_size = len(self.user_fanout.get(user, set()))
                if fanout_size >= self.config.min_user_fanout:
                    risk += self.config.fanout_bonus
                    signals.add(f'user_fanout_{fanout_size}')
        
        # ============================================================
        # STEP 2: Update knowledge bases (for future events)
        # ============================================================
        if user:
            key = (user, dest)
            self.seen_user_dest[key] = self.seen_user_dest.get(key, 0) + 1
            self._update_fanout(self.user_fanout, user, dest)
        
        key = (source, dest)
        self.seen_source_dest[key] = self.seen_source_dest.get(key, 0) + 1
        self._update_fanout(self.source_fanout, source, dest)
        
        # Skip if no signals
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
        
        ep = self.current[episode_key]
        ep.end_time = ts
        ep.signals.update(signals)
        ep.max_risk = max(ep.max_risk, risk)
        ep.destinations.add(dest)
        if user:
            ep.users.add(user)
        ep.events_count += 1
    
    def finish(self) -> List[Episode]:
        # Expire all remaining episodes
        for key, ep in self.current.items():
            if len(ep.signals) >= self.config.min_episode_signals:
                self.episodes.append(ep)
        self.current.clear()
        return self.episodes


# ============================================================
# REDTEAM VALIDATOR (Post-hoc only)
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
    """Validate episodes against redteam ground truth (post-hoc only)"""
    matches = []  # Store detailed matches
    redteam_matched = set()
    episode_matched = set()
    
    for rt_idx, rt in enumerate(redteam):
        rt_time = rt['time']
        rt_source = rt['source']
        rt_dest = rt['dest']
        rt_user = rt['user']
        
        for ep in episodes:
            # Source must match
            if ep.source != rt_source:
                continue
            
            # Destination must be in episode's destinations
            if rt_dest not in ep.destinations:
                continue
            
            # Time overlap: redteam time falls within episode window +/- validation window
            # Corrected: ep.start - window <= rt_time <= ep.end + window
            if not (ep.start_time - window <= rt_time <= ep.end_time + window):
                continue
            
            # Match found
            redteam_matched.add((rt_time, rt_source, rt_dest))
            episode_matched.add(ep.id)
            
            matches.append({
                'redteam_index': rt_idx,
                'redteam': rt,
                'episode_id': ep.id,
                'episode_source': ep.source,
                'episode_user': ep.user,
                'episode_start': ep.start_time,
                'episode_end': ep.end_time,
                'episode_signals': list(ep.signals),
                'episode_destinations': list(ep.destinations)[:20],
                'time_delta_rt_to_ep_start': rt_time - ep.start_time,
                'time_delta_rt_to_ep_end': rt_time - ep.end_time,
            })
    
    # Sort matches by redteam index for readability
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
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="SRIA RT v0.2.4 - Blind Detection (Fixed)")
    parser.add_argument("--base-dir", default=".")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--max-lines", type=int, default=0, help="0 = unlimited")
    parser.add_argument("--warmup", type=int, default=100000)
    parser.add_argument("--episode-window", type=int, default=300)
    parser.add_argument("--validation-window", type=int, default=60)
    
    args = parser.parse_args()
    
    base = Path(args.base_dir)
    out = Path(args.out_dir) if args.out_dir else base / "v024_output"
    out.mkdir(parents=True, exist_ok=True)
    
    auth_file = base / "auth.txt"
    redteam_file = base / "redteam.txt"
    
    print("=" * 70)
    print("SRIA RT v0.2.4 - BLIND DETECTION VALIDATION (Fixed)")
    print("=" * 70)
    print(f"Base dir: {base}")
    print(f"Auth: {auth_file}")
    print(f"Redteam: {redteam_file}")
    print(f"Episode window: {args.episode_window}s")
    print(f"Validation window: {args.validation_window}s")
    print(f"Warmup events: {args.warmup:,}")
    print("=" * 70)
    print("NOTE: redteam.txt used ONLY for post-hoc validation")
    print("      Detection uses ONLY auth.txt")
    print("=" * 70)
    
    # Load redteam for validation only
    redteam = load_redteam(redteam_file)
    print(f"\n[validation] Loaded {len(redteam)} redteam events")
    
    # Blind detection
    config = Config(
        warmup_events=args.warmup,
        episode_window=args.episode_window,
        validation_window=args.validation_window
    )
    detector = BlindEpisodeDetector(config)
    
    print(f"\n[detection] Scanning {auth_file}...")
    print(f"  Max lines: {'unlimited' if args.max_lines == 0 else f'{args.max_lines:,}'}")
    print(f"  Report interval: {config.report_interval:,} lines")
    
    line_count = 0
    start_time = time.time()
    
    with open(auth_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if args.max_lines > 0 and line_count >= args.max_lines:
                break
            
            parsed = parse_auth_fast(line)
            if parsed:
                ts, source, dest, user = parsed
                detector.process(ts, source, dest, user)
            
            line_count += 1
            if line_count % config.report_interval == 0:
                elapsed = time.time() - start_time
                rate = line_count / elapsed if elapsed > 0 else 0
                print(f"  Scanned {line_count:,} lines ({rate:,.0f} lines/sec)...")
    
    elapsed = time.time() - start_time
    print(f"\n[detection] Scanned {line_count:,} lines in {elapsed:.1f} seconds ({line_count/elapsed:,.0f} lines/sec)")
    print(f"[detection] Total auth events processed: {detector.total_events:,}")
    print(f"[detection] Warmup complete: {detector.warmup_complete}")
    
    episodes = detector.finish()
    print(f"[detection] Episodes detected: {len(episodes)}")
    
    # Episode signals summary
    if episodes:
        signal_counts = Counter()
        for ep in episodes:
            for sig in ep.signals:
                signal_counts[sig] += 1
        print("\n[detection] Top signals:")
        for sig, cnt in signal_counts.most_common(10):
            print(f"  {sig}: {cnt:,}")
        
        # Episode stats
        avg_duration = sum(ep.end_time - ep.start_time for ep in episodes) / len(episodes)
        avg_events = sum(ep.events_count for ep in episodes) / len(episodes)
        print(f"\n[detection] Avg episode duration: {avg_duration:.1f}s")
        print(f"[detection] Avg events per episode: {avg_events:.1f}")
    
    # Validate against redteam
    print("\n[validation] Comparing episodes to redteam ground truth...")
    results = validate(episodes, redteam, args.validation_window)
    
    print("\n" + "=" * 70)
    print("VALIDATION RESULTS (Blind Detection)")
    print("=" * 70)
    print(f"  Total redteam events: {results['total_redteam']}")
    print(f"  Matched redteam events: {results['matched_redteam']}")
    print(f"  Recall: {results['recall']:.2%}")
    print(f"  Total episodes: {results['total_episodes']}")
    print(f"  Episodes overlapping redteam: {results['matched_episodes']}")
    print(f"  Episode overlap rate: {results['episode_overlap_rate']:.2%}")
    
    # Save results
    # Save episodes
    episodes_file = out / "detected_episodes.jsonl"
    with open(episodes_file, 'w') as f:
        for ep in episodes:
            f.write(json.dumps({
                'id': ep.id,
                'source': ep.source,
                'user': ep.user,
                'start_time': ep.start_time,
                'end_time': ep.end_time,
                'duration': ep.end_time - ep.start_time,
                'events_count': ep.events_count,
                'signals': list(ep.signals),
                'max_risk': ep.max_risk,
                'destinations': list(ep.destinations)[:50],
                'users': list(ep.users)[:20],
            }) + '\n')
    
    # Save matches
    matches_file = out / "redteam_matches.jsonl"
    with open(matches_file, 'w') as f:
        for match in results['matches']:
            f.write(json.dumps(match) + '\n')
    
    # Save summary report
    report = out / "validation_report.txt"
    report_lines = [
        "=" * 70,
        "SRIA RT v0.2.4 Blind Detection Validation Report",
        "=" * 70,
        "",
        f"Total redteam events: {results['total_redteam']}",
        f"Matched redteam events: {results['matched_redteam']}",
        f"Recall: {results['recall']:.2%}",
        f"Total episodes: {results['total_episodes']}",
        f"Episodes overlapping redteam: {results['matched_episodes']}",
        f"Episode overlap rate: {results['episode_overlap_rate']:.2%}",
        "",
        "=" * 70,
        "First 20 Matches (by redteam index):",
        "=" * 70,
    ]
    
    for match in results['matches'][:20]:
        rt = match['redteam']
        report_lines.append(f"\nRT#{match['redteam_index']}: {rt['time']} {rt['user']} {rt['source']}->{rt['dest']}")
        report_lines.append(f"  Episode {match['episode_id']}: source={match['episode_source']}, user={match['episode_user']}")
        report_lines.append(f"  Episode time: {match['episode_start']} - {match['episode_end']}")
        report_lines.append(f"  Signals: {match['episode_signals'][:5]}")
        report_lines.append(f"  Destinations in episode: {len(match['episode_destinations'])}")
    
    report_file = out / "validation_report.txt"
    report_file.write_text("\n".join(report_lines))
    
    print(f"\n[output] Episodes saved to: {episodes_file}")
    print(f"[output] Matches saved to: {matches_file}")
    print(f"[output] Report saved to: {report_file}")
    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()