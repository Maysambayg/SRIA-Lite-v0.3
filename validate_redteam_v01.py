# validate_redteam_v01.py
"""
Red Team validation for SRIA RT v0.1.
Computes overlap between SRIA episodes and known redteam events.
"""

import json
from pathlib import Path
from collections import Counter

def validate(episodes_file, redteam_file, window_sec=60):
    # Load episodes
    episodes = []
    with open(episodes_file, 'r') as f:
        for line in f:
            episodes.append(json.loads(line))
    
    # Load redteam
    redteam_events = []
    with open(redteam_file, 'r') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 4:
                redteam_events.append({
                    'timestamp': int(parts[0]),
                    'user': parts[1],
                    'source': parts[2],
                    'dest': parts[3]
                })
    
    # Match
    matches = []
    for rt in redteam_events:
        for ep in episodes:
            time_overlap = abs(ep['start_time'] - rt['timestamp']) <= window_sec
            host_match = ep['host'] == rt['source'] or ep['host'] == rt['dest']
            if time_overlap and host_match:
                matches.append({
                    'redteam': rt,
                    'episode': ep,
                    'window': window_sec
                })
    
    # Results
    print(f"Total redteam events: {len(redteam_events)}")
    print(f"Matched redteam events: {len(set(m['redteam']['timestamp'] for m in matches))}")
    print(f"Matched episodes: {len(set(m['episode']['host'] for m in matches))}")
    
    return matches
