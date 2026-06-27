#!/usr/bin/env python3
"""
SRIA Red Team Validation v0.2.1 (FINAL)
Authentication-focused episode detection for lateral movement.
NO GROUND TRUTH LEAKAGE - redteam.txt used ONLY for validation.

Key features:
- Score first, then learn (correct baseline ordering)
- Warmup period (no first-time detection until baseline established)
- Episode key: (source_computer, source_user)
- Strict matching: source + destination + time
- Honest metrics: episode_overlap_rate (not "precision")
- Harmonic overlap score (not misleading "F1")
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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


# ============================================================
# PARSERS
# ============================================================

def parse_auth_line(line: str) -> Optional[Dict]:
    parts = line.strip().split(',')
    if len(parts) < 9:
        return None
    try:
        return {
            "type": "auth",
            "timestamp": int(parts[0]),
            "source_user": parts[1] if parts[1] != '?' else None,
            "dest_user": parts[2] if parts[2] != '?' else None,
            "source_computer": parts[3] if parts[3] != '?' else None,
            "dest_computer": parts[4] if parts[4] != '?' else None,
            "auth_type": parts[5] if parts[5] != '?' else None,
            "logon_type": parts[6] if parts[6] != '?' else None,
            "orientation": parts[7] if parts[7] != '?' else None,
            "success": parts[8] == "Success",
        }
    except (ValueError, IndexError):
        return None


def parse_redteam_line(line: str) -> Optional[Dict]:
    parts = line.strip().split(',')
    if len(parts) < 4:
        return None
    try:
        return {
            "timestamp": int(parts[0]),
            "user": parts[1],
            "source_computer": parts[2],
            "dest_computer": parts[3],
        }
    except (ValueError, IndexError):
        return None


# ============================================================
# EPISODE DETECTOR
# ============================================================

@dataclass
class Episode:
    id: int
    episode_key: str
    source_computer: str
    source_user: str
    start_time: int
    end_time: int
    events: List[Dict] = field(default_factory=list)
    signals: Set[str] = field(default_factory=set)
    max_risk: float = 0.0
    destinations: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)


class AuthEpisodeDetector:
    def __init__(self, config: Config):
        self.config = config
        self.episodes: List[Episode] = []
        self.current_episodes: Dict[str, Episode] = {}
        self.episode_counter = 0
        self.total_auth_events = 0
        self.warmup_complete = False
        
        # Knowledge bases (updated AFTER scoring)
        self.seen_user_to_dest: Dict[Tuple[str, str], int] = defaultdict(int)
        self.seen_source_to_dest: Dict[Tuple[str, str], int] = defaultdict(int)
        self.source_fanout: Dict[str, Set[str]] = defaultdict(set)
        self.user_fanout: Dict[str, Set[str]] = defaultdict(set)
    
    def _get_episode_key(self, event: Dict) -> str:
        source = event.get('source_computer', 'unknown')
        user = event.get('source_user', 'unknown')
        return f"{source}|{user}"
    
    def _calculate_risk_and_signals(self, event: Dict) -> Tuple[float, Set[str]]:
        """Calculate risk and signals using CURRENT baseline (before learning this event)"""
        risk = 0.0
        signals = set()
        
        source = event.get('source_computer')
        dest = event.get('dest_computer')
        user = event.get('source_user') or event.get('dest_user')
        success = event.get('success', False)
        
        if not source or not dest or not success:
            return risk, signals
        
        # NO LEAKAGE: No hardcoded references to C17693
        
        # First-time detection (using current baseline)
        if self.warmup_complete:
            if user and dest and (user, dest) not in self.seen_user_to_dest:
                risk += self.config.first_time_bonus
                signals.add('first_time_user_to_dest')
            
            if (source, dest) not in self.seen_source_to_dest:
                risk += self.config.first_time_bonus * 0.8
                signals.add('first_time_source_to_dest')
        
        # Fanout detection (using current counts)
        fanout_size = len(self.source_fanout.get(source, set()))
        if fanout_size >= self.config.min_source_fanout:
            risk += self.config.fanout_bonus
            signals.add(f'source_fanout_{fanout_size}')
        
        if user:
            fanout_size = len(self.user_fanout.get(user, set()))
            if fanout_size >= self.config.min_user_fanout:
                risk += self.config.fanout_bonus
                signals.add(f'user_fanout_{fanout_size}')
        
        return min(risk, 1.0), signals
    
    def process_event(self, event: Dict):
        """Process an authentication event - SCORE FIRST, THEN LEARN"""
        self.total_auth_events += 1
        
        if not self.warmup_complete and self.total_auth_events >= self.config.warmup_events:
            self.warmup_complete = True
            print(f"  Warmup complete after {self.total_auth_events:,} events")
        
        source = event.get('source_computer')
        dest = event.get('dest_computer')
        user = event.get('source_user') or event.get('dest_user')
        timestamp = event.get('timestamp', 0)
        
        episode_key = self._get_episode_key(event)
        
        # STEP 1: Calculate risk and signals using CURRENT baseline
        risk, signals = self._calculate_risk_and_signals(event)
        
        # STEP 2: Update baseline for future events
        if source and dest:
            self.seen_source_to_dest[(source, dest)] += 1
            self.source_fanout[source].add(dest)
        if user and dest:
            self.seen_user_to_dest[(user, dest)] += 1
            self.user_fanout[user].add(dest)
        
        # STEP 3: Update episode
        if episode_key not in self.current_episodes:
            self.episode_counter += 1
            self.current_episodes[episode_key] = Episode(
                id=self.episode_counter,
                episode_key=episode_key,
                source_computer=source or 'unknown',
                source_user=user or 'unknown',
                start_time=timestamp,
                end_time=timestamp
            )
        
        ep = self.current_episodes[episode_key]
        ep.end_time = timestamp
        ep.events.append(event)
        ep.signals.update(signals)
        ep.max_risk = max(ep.max_risk, risk)
        
        if dest:
            ep.destinations.add(dest)
        if user:
            ep.users.add(user)
        
        # Close episodes that exceed window
        to_close = [k for k, e in self.current_episodes.items() 
                   if timestamp - e.start_time > self.config.episode_window]
        
        for k in to_close:
            ep = self.current_episodes.pop(k)
            if len(ep.signals) >= self.config.min_episode_signals:
                self.episodes.append(ep)
    
    def get_episodes(self) -> List[Episode]:
        for ep in self.current_episodes.values():
            if len(ep.signals) >= self.config.min_episode_signals:
                self.episodes.append(ep)
        self.current_episodes.clear()
        return self.episodes


# ============================================================
# RED TEAM VALIDATOR
# ============================================================

class RedTeamValidator:
    def __init__(self, redteam_file: Path):
        self.redteam_events = []
        with open(redteam_file, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                event = parse_redteam_line(line)
                if event:
                    self.redteam_events.append(event)
        print(f"Loaded {len(self.redteam_events)} redteam events")
    
    def match_episodes(self, episodes: List[Episode], window_sec: int = 60) -> Dict:
        matches = []
        redteam_matched = set()  # Use tuple to avoid timestamp collisions
        episode_matched = set()
        
        for rt in self.redteam_events:
            rt_time = rt['timestamp']
            rt_source = rt['source_computer']
            rt_dest = rt['dest_computer']
            
            for ep in episodes:
                if ep.source_computer != rt_source:
                    continue
                if rt_dest not in ep.destinations:
                    continue
                time_overlap = (abs(ep.start_time - rt_time) <= window_sec or 
                               abs(ep.end_time - rt_time) <= window_sec)
                if not time_overlap:
                    continue
                
                matches.append({
                    'redteam': rt,
                    'episode': ep,
                    'time_delta': min(abs(ep.start_time - rt_time), abs(ep.end_time - rt_time))
                })
                # Use tuple to uniquely identify redteam events
                redteam_matched.add((rt_time, rt_source, rt_dest))
                episode_matched.add(ep.id)
        
        true_positive_episodes = len(episode_matched)
        unmatched_episodes = len(episodes) - true_positive_episodes
        episode_overlap_rate = true_positive_episodes / len(episodes) if episodes else 0
        recall = len(redteam_matched) / len(self.redteam_events) if self.redteam_events else 0
        
        # Harmonic overlap score (not canonical F1 because episode_overlap_rate != precision)
        harmonic_overlap_score = 2 * (episode_overlap_rate * recall) / (episode_overlap_rate + recall) if (episode_overlap_rate + recall) > 0 else 0
        
        return {
            'total_redteam': len(self.redteam_events),
            'matched_redteam': len(redteam_matched),
            'total_episodes': len(episodes),
            'matched_episodes': true_positive_episodes,
            'unmatched_episodes': unmatched_episodes,
            'episode_overlap_rate': episode_overlap_rate,
            'recall': recall,
            'harmonic_overlap_score': harmonic_overlap_score,
            'matches': matches
        }


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="SRIA Red Team Validation v0.2.1 (FINAL)")
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument("--out-dir", type=Path, default=Path("./sria_rt_output"))
    parser.add_argument("--max-lines", type=int, default=0)
    parser.add_argument("--episode-window", type=int, default=300)
    parser.add_argument("--warmup-events", type=int, default=100000)
    
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    
    config = Config(episode_window=args.episode_window, warmup_events=args.warmup_events)
    detector = AuthEpisodeDetector(config)
    
    print("=" * 70)
    print("SRIA Red Team Validation v0.2.1 (FINAL)")
    print("=" * 70)
    print(f"Base dir: {args.base_dir}")
    print(f"Episode window: {args.episode_window}s")
    print(f"Warmup events: {args.warmup_events:,}")
    print("NOTE: redteam.txt used ONLY for validation - NO LEAKAGE")
    print("=" * 70)
    
    auth_file = args.base_dir / "auth.txt"
    if not auth_file.exists():
        print(f"ERROR: {auth_file} not found!")
        return
    
    print(f"\nProcessing {auth_file}...")
    line_count = 0
    with open(auth_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            if args.max_lines > 0 and line_count >= args.max_lines:
                break
            event = parse_auth_line(line)
            if event:
                detector.process_event(event)
            line_count += 1
            if line_count % 500000 == 0:
                print(f"  Processed {line_count:,} lines...")
    
    print(f"  Processed {line_count:,} lines")
    print(f"  Total auth events: {detector.total_auth_events:,}")
    print(f"  Warmup complete: {detector.warmup_complete}")
    
    episodes = detector.get_episodes()
    print(f"\nDetected episodes: {len(episodes)}")
    
    if episodes:
        signal_counts = Counter()
        for ep in episodes:
            for signal in ep.signals:
                signal_counts[signal] += 1
        print("\nEpisode signals (top 15):")
        for signal, count in signal_counts.most_common(15):
            print(f"  {signal}: {count}")
    
    # Save episodes
    episodes_file = args.out_dir / "sria_rt_episodes_v021.jsonl"
    with open(episodes_file, 'w') as f:
        for ep in episodes:
            f.write(json.dumps({
                'id': ep.id,
                'episode_key': ep.episode_key,
                'source_computer': ep.source_computer,
                'source_user': ep.source_user,
                'start_time': ep.start_time,
                'end_time': ep.end_time,
                'duration': ep.end_time - ep.start_time,
                'event_count': len(ep.events),
                'signals': list(ep.signals),
                'max_risk': ep.max_risk,
                'destinations': list(ep.destinations),
                'users': list(ep.users),
            }) + '\n')
    print(f"\nEpisodes saved to: {episodes_file}")
    
    # Validate against redteam
    redteam_file = args.base_dir / "redteam.txt"
    if redteam_file.exists():
        print("\n" + "=" * 70)
        print("RED TEAM VALIDATION (Source + Destination + Time)")
        print("=" * 70)
        
        validator = RedTeamValidator(redteam_file)
        results = validator.match_episodes(episodes, window_sec=60)
        
        print(f"\nResults:")
        print(f"  Total redteam events: {results['total_redteam']}")
        print(f"  Matched redteam events: {results['matched_redteam']}")
        print(f"  Total episodes: {results['total_episodes']}")
        print(f"  Episodes overlapping redteam: {results['matched_episodes']}")
        print(f"  Episodes NOT overlapping redteam: {results['unmatched_episodes']}")
        print(f"\n  Episode overlap rate: {results['episode_overlap_rate']:.2%}")
        print(f"  Recall: {results['recall']:.2%}")
        print(f"  Harmonic overlap score: {results['harmonic_overlap_score']:.2%}")
        
        matches_file = args.out_dir / "sria_rt_redteam_matches_v021.jsonl"
        with open(matches_file, 'w') as f:
            for match in results['matches']:
                f.write(json.dumps({
                    'redteam': match['redteam'],
                    'episode_id': match['episode'].id,
                    'episode_source': match['episode'].source_computer,
                    'episode_signals': list(match['episode'].signals),
                    'time_delta': match['time_delta']
                }) + '\n')
        print(f"Matches saved to: {matches_file}")
        
        if results['matches']:
            print("\nSample matches (first 10):")
            for match in results['matches'][:10]:
                rt = match['redteam']
                ep = match['episode']
                print(f"\n  Time {rt['timestamp']}: {rt['source_computer']} -> {rt['dest_computer']}")
                print(f"    Episode: {ep.episode_key}")
                print(f"    Signals: {list(ep.signals)[:5]}")
                print(f"    Destinations in episode: {len(ep.destinations)}")
                print(f"    Delta: {match['time_delta']}s")
    else:
        print(f"WARNING: {redteam_file} not found - skipping validation")
    
    # Save report
    report_file = args.out_dir / "sria_rt_report_v021.txt"
    with open(report_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("SRIA Red Team Validation v0.2.1 Report\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Total episodes: {len(episodes)}\n")
        if redteam_file.exists():
            f.write(f"Total redteam events: {results['total_redteam']}\n")
            f.write(f"Matched redteam events: {results['matched_redteam']}\n")
            f.write(f"Episodes overlapping redteam: {results['matched_episodes']}\n")
            f.write(f"Episodes NOT overlapping redteam: {results['unmatched_episodes']}\n")
            f.write(f"\nEpisode overlap rate: {results['episode_overlap_rate']:.2%}\n")
            f.write(f"Recall: {results['recall']:.2%}\n")
            f.write(f"Harmonic overlap score: {results['harmonic_overlap_score']:.2%}\n")
    
    print(f"\nReport saved to: {report_file}")
    print("\n" + "=" * 70)
    print("Done!")
    print("=" * 70)


if __name__ == "__main__":
    main()
