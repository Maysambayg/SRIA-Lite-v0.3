#!/usr/bin/env python3
r"""
analyze_episodes_v06.py

Ranks high-signal episodes from v0.6 into tiers:
- Tier 1: suspicious_port + suspicious_process
- Tier 2: explicit_credential + suspicious_process (+ DNS optional)
- Tier 3: DNS flood + suspicious_process
- Tier 4: infrastructure/service-account clusters

Input: F:\SRIA\high_signal_episodes_v06.jsonl
Output: episode_ranking_v06.txt + tiered JSONL files
"""

import json
from pathlib import Path
from collections import Counter

# Configuration
EPISODE_FILE = Path(r"F:\SRIA\high_signal_episodes_v06.jsonl")
OUTPUT_REPORT = Path(r"F:\SRIA\episode_ranking_v06.txt")
OUTPUT_TIER1 = Path(r"F:\SRIA\tier1_episodes_v06.jsonl")
OUTPUT_TIER2 = Path(r"F:\SRIA\tier2_episodes_v06.jsonl")
OUTPUT_TIER3 = Path(r"F:\SRIA\tier3_episodes_v06.jsonl")
OUTPUT_TIER4 = Path(r"F:\SRIA\tier4_episodes_v06.jsonl")


def classify_episode(episode):
    """
    Classify episode into tiers 1-4 based on signals derived from:
    - top_reasons
    - top_processes
    - top_event_ids
    - account_types
    - top_actors
    """
    # Get signals from available fields
    top_reasons = [r for r, _ in episode.get("top_reasons", [])]
    top_processes = [p for p, _ in episode.get("top_processes", [])]
    top_event_ids = [eid for eid, _ in episode.get("top_event_ids", [])]
    account_types = [at for at, _ in episode.get("account_types", [])]
    top_actors = [a for a, _ in episode.get("top_actors", [])]
    
    # Build signal set
    signals = set()
    
    # Check for suspicious_port in reasons
    for reason in top_reasons:
        if "suspicious_port" in reason:
            signals.add("suspicious_port")
        if "dns_flood" in reason:
            signals.add("dns_flood")
        if "explicit_credential" in reason:
            signals.add("explicit_credential")
        if "failed_logon" in reason:
            signals.add("failed_logon")
        if "special_privileges" in reason:
            signals.add("special_privileges")
    
    # Check for suspicious_process in reasons or processes
    for reason in top_reasons:
        if "suspicious_process" in reason:
            signals.add("suspicious_process")
    for proc in top_processes:
        if proc.lower() in ["cscript.exe", "cmd.exe", "powershell.exe", "rundll32.exe", "net.exe"]:
            signals.add("suspicious_process")
    
    # Check for human_user in account_types or actors
    is_human = "human_user" in account_types
    for actor in top_actors:
        if actor.startswith("User") or actor.startswith("Administrator"):
            is_human = True
    
    # Check for infrastructure/service-account
    is_infra = any(a in ["EnterpriseAppServer", "AppService"] for a in top_actors)
    
    # Tier 1: suspicious_port + suspicious_process (strongest)
    if "suspicious_port" in signals and "suspicious_process" in signals:
        return 1, "suspicious_port + suspicious_process", signals, is_human, is_infra
    
    # Tier 2: explicit_credential + suspicious_process (with or without DNS)
    if "explicit_credential" in signals and "suspicious_process" in signals:
        return 2, "explicit_credential + suspicious_process", signals, is_human, is_infra
    
    # Tier 3: DNS flood + suspicious_process
    if "dns_flood" in signals and "suspicious_process" in signals:
        return 3, "DNS flood + suspicious_process", signals, is_human, is_infra
    
    # Tier 4: infrastructure/service-account clusters
    if is_infra:
        return 4, "infrastructure/service-account cluster", signals, is_human, is_infra
    
    # Default: other correlation
    return 3, "other correlation", signals, is_human, is_infra


def main():
    if not EPISODE_FILE.exists():
        print(f"File not found: {EPISODE_FILE}")
        return
    
    # Load episodes
    episodes = []
    with open(EPISODE_FILE, 'r') as f:
        for line in f:
            if line.strip():
                episodes.append(json.loads(line))
    
    print(f"Loaded {len(episodes)} episodes")
    
    # Classify episodes
    tiered = {1: [], 2: [], 3: [], 4: []}
    tier_reasons = {}
    
    for ep in episodes:
        tier, reason, signals, is_human, is_infra = classify_episode(ep)
        tiered[tier].append(ep)
        tier_reasons[id(ep)] = (reason, signals, is_human, is_infra)
    
    # Sort each tier by max_risk descending
    for tier in tiered:
        tiered[tier].sort(key=lambda x: x.get("max_risk", 0), reverse=True)
    
    # Write tier files
    with open(OUTPUT_TIER1, 'w') as f:
        for ep in tiered[1]:
            f.write(json.dumps(ep) + "\n")
    with open(OUTPUT_TIER2, 'w') as f:
        for ep in tiered[2]:
            f.write(json.dumps(ep) + "\n")
    with open(OUTPUT_TIER3, 'w') as f:
        for ep in tiered[3]:
            f.write(json.dumps(ep) + "\n")
    with open(OUTPUT_TIER4, 'w') as f:
        for ep in tiered[4]:
            f.write(json.dumps(ep) + "\n")
    
    # Generate report
    lines = []
    lines.append("=" * 80)
    lines.append("SRIA v0.6 EPISODE RANKING REPORT")
    lines.append("=" * 80)
    lines.append(f"Total episodes: {len(episodes)}")
    lines.append("")
    
    for tier in [1, 2, 3, 4]:
        tier_names = {
            1: "TIER 1 - HIGHEST PRIORITY (suspicious_port + suspicious_process)",
            2: "TIER 2 - HIGH PRIORITY (explicit_credential + suspicious_process)",
            3: "TIER 3 - MEDIUM PRIORITY (DNS flood + suspicious_process)",
            4: "TIER 4 - LOW PRIORITY (infrastructure/service-account clusters)"
        }
        lines.append("-" * 80)
        lines.append(f"{tier_names[tier]} ({len(tiered[tier])} episodes)")
        lines.append("-" * 80)
        
        for ep in tiered[tier]:
            host = ep.get("host", "unknown")
            risk = ep.get("max_risk", 0)
            action = ep.get("recommended_action", "UNKNOWN")
            duration = ep.get("duration", 0)
            event_count = ep.get("event_count", 0)
            signals_str = ", ".join(sorted(tier_reasons[id(ep)][1]))
            reason_str = tier_reasons[id(ep)][0]
            top_actors = ", ".join([a for a, _ in ep.get("top_actors", [])[:3]])
            top_processes = ", ".join([p for p, _ in ep.get("top_processes", [])[:3]])
            
            lines.append(f"\n{host}")
            lines.append(f"  Risk: {risk} | Action: {action} | Events: {event_count} | Duration: {duration}s")
            lines.append(f"  Classification: {reason_str}")
            lines.append(f"  Signals: {signals_str}")
            lines.append(f"  Top actors: {top_actors}")
            lines.append(f"  Top processes: {top_processes}")
    
    # Summary table
    lines.append("")
    lines.append("=" * 80)
    lines.append("SUMMARY TABLE")
    lines.append("=" * 80)
    lines.append(f"{'Tier':<6} {'Count':<8} {'Description':<50}")
    lines.append("-" * 80)
    tier_desc = {
        1: "suspicious_port + suspicious_process",
        2: "explicit_credential + suspicious_process",
        3: "DNS flood + suspicious_process",
        4: "infrastructure/service-account clusters"
    }
    for tier in [1, 2, 3, 4]:
        lines.append(f"Tier {tier:<4} {len(tiered[tier]):<8} {tier_desc[tier]}")
    
    # Write report
    with open(OUTPUT_REPORT, 'w') as f:
        f.write("\n".join(lines))
    
    # Print to console
    print("\n".join(lines[:150]))  # First 150 lines
    print(f"\nFull report saved to: {OUTPUT_REPORT}")
    print(f"Tier files saved to: tier[1-4]_episodes_v06.jsonl")


if __name__ == "__main__":
    main()