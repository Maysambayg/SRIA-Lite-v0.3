#!/usr/bin/env python3
"""
sria_rt_v01.py

SRIA Red Team Validation v0.1

Purpose:
- Process the full LANL unified dataset format:
    auth.txt
    proc.txt
    flows.txt
    dns.txt
    redteam.txt

- Generate SRIA-style compressed episodes from host/network/auth/process/DNS signals.
- Validate detected episodes against known redteam events.
- Keep this conservative: recurrence/overlap does not prove compromise.

Default expected files in current directory:
    auth.txt
    proc.txt
    flows.txt
    dns.txt
    redteam.txt

Outputs:
    sria_rt_v01_output/
        sria_rt_episodes_v01.jsonl
        sria_rt_redteam_matches_v01.jsonl
        sria_rt_report_v01.txt

Run:
    py sria_rt_v01.py --self-test
    py sria_rt_v01.py --max-lines 1000000
    py sria_rt_v01.py
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import json
import tempfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple


# ============================================================
# CONFIG
# ============================================================

@dataclass
class Config:
    base_dir: Path = Path(".")
    out_dir: Path = Path("sria_rt_v01_output")

    auth_file: Path = Path("auth.txt")
    proc_file: Path = Path("proc.txt")
    flows_file: Path = Path("flows.txt")
    dns_file: Path = Path("dns.txt")
    redteam_file: Path = Path("redteam.txt")

    episode_window_sec: int = 300
    redteam_match_window_sec: int = 300
    progress_every: int = 1_000_000
    max_lines: int = 0

    suspicious_ports: Set[int] = field(
        default_factory=lambda: {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337}
    )

    large_flow_bytes: int = 10_000_000
    dns_window_sec: int = 60
    dns_threshold: int = 100
    proc_window_sec: int = 300
    proc_burst_threshold: int = 25

    min_episode_signals: int = 2
    min_episode_risk: float = 0.45


# ============================================================
# FILE HELPERS
# ============================================================

def open_text(path: Path):
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.suffix == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def resolve_path(base_dir: Path, p: Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else base_dir / p


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def clean(value: str) -> Optional[str]:
    value = value.strip()
    if value == "?" or value == "":
        return None
    return value


# ============================================================
# PARSERS
# ============================================================

def parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    """
    auth.txt:
    time,source user@domain,destination user@domain,source computer,
    destination computer,authentication type,logon type,
    authentication orientation,success/failure
    """
    parts = line.rstrip("\n").split(",")
    if len(parts) < 9:
        return None
    return {
        "type": "auth",
        "timestamp": safe_int(parts[0], -1),
        "source_user": clean(parts[1]),
        "dest_user": clean(parts[2]),
        "source_computer": clean(parts[3]),
        "dest_computer": clean(parts[4]),
        "auth_type": clean(parts[5]),
        "logon_type": clean(parts[6]),
        "orientation": clean(parts[7]),
        "success": parts[8].strip().lower() == "success",
    }


def parse_proc_line(line: str) -> Optional[Dict[str, Any]]:
    """
    proc.txt:
    time,user@domain,computer,process name,start/end
    """
    parts = line.rstrip("\n").split(",")
    if len(parts) < 5:
        return None
    return {
        "type": "proc",
        "timestamp": safe_int(parts[0], -1),
        "user": clean(parts[1]),
        "computer": clean(parts[2]),
        "process": clean(parts[3]),
        "action": clean(parts[4]) or "",
    }


def parse_flow_line(line: str) -> Optional[Dict[str, Any]]:
    """
    flows.txt:
    time,duration,source computer,source port,destination computer,
    destination port,protocol,packet count,byte count
    """
    parts = line.rstrip("\n").split(",")
    if len(parts) < 9:
        return None
    return {
        "type": "flow",
        "timestamp": safe_int(parts[0], -1),
        "duration": safe_int(parts[1], 0),
        "source_computer": clean(parts[2]),
        "source_port": safe_int(parts[3], 0),
        "dest_computer": clean(parts[4]),
        "dest_port": safe_int(parts[5], 0),
        "protocol": clean(parts[6]),
        "packets": safe_int(parts[7], 0),
        "bytes": safe_int(parts[8], 0),
    }


def parse_dns_line(line: str) -> Optional[Dict[str, Any]]:
    """
    dns.txt:
    time,source computer,computer resolved
    """
    parts = line.rstrip("\n").split(",")
    if len(parts) < 3:
        return None
    return {
        "type": "dns",
        "timestamp": safe_int(parts[0], -1),
        "source_computer": clean(parts[1]),
        "resolved_computer": clean(parts[2]),
    }


def parse_redteam_line(line: str) -> Optional[Dict[str, Any]]:
    """
    redteam.txt:
    time,user@domain,source computer,destination computer
    """
    parts = line.rstrip("\n").split(",")
    if len(parts) < 4:
        return None
    return {
        "timestamp": safe_int(parts[0], -1),
        "user": clean(parts[1]),
        "source_computer": clean(parts[2]),
        "dest_computer": clean(parts[3]),
    }


# ============================================================
# EPISODE MODEL
# ============================================================

@dataclass
class Episode:
    host: str
    bucket: int
    start_time: int
    end_time: int
    event_count: int = 0
    max_risk: float = 0.0
    signals: Counter = field(default_factory=Counter)
    users: Counter = field(default_factory=Counter)
    source_hosts: Counter = field(default_factory=Counter)
    dest_hosts: Counter = field(default_factory=Counter)
    processes: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    auth_types: Counter = field(default_factory=Counter)
    logon_types: Counter = field(default_factory=Counter)
    event_types: Counter = field(default_factory=Counter)
    examples: List[Dict[str, Any]] = field(default_factory=list)

    def add(
        self,
        timestamp: int,
        event_type: str,
        risk: float,
        signals: Iterable[str],
        user: Optional[str] = None,
        source_host: Optional[str] = None,
        dest_host: Optional[str] = None,
        process: Optional[str] = None,
        port: Optional[int] = None,
        auth_type: Optional[str] = None,
        logon_type: Optional[str] = None,
        example: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.start_time = min(self.start_time, timestamp)
        self.end_time = max(self.end_time, timestamp)
        self.event_count += 1
        self.max_risk = max(self.max_risk, risk)
        self.event_types[event_type] += 1

        for sig in signals:
            self.signals[sig] += 1

        if user:
            self.users[user] += 1
        if source_host:
            self.source_hosts[source_host] += 1
        if dest_host:
            self.dest_hosts[dest_host] += 1
        if process:
            self.processes[process] += 1
        if port:
            self.ports[str(port)] += 1
        if auth_type:
            self.auth_types[auth_type] += 1
        if logon_type:
            self.logon_types[logon_type] += 1

        if example and len(self.examples) < 5:
            self.examples.append(example)

    def score(self) -> float:
        weights = {
            "suspicious_port": 80,
            "process_burst": 45,
            "failed_auth": 45,
            "auth_lateral": 25,
            "dns_flood": 30,
            "large_flow": 15,
            "redteam_overlap": 100,
        }
        signal_score = sum(weights.get(sig, 5) for sig in self.signals)
        density_bonus = min(30, self.event_count // 10)
        return round(self.max_risk * 100 + signal_score + density_bonus, 3)

    def recommended_action(self) -> str:
        sigs = set(self.signals)
        if "redteam_overlap" in sigs:
            return "GROUND_TRUTH_MATCH"
        if "suspicious_port" in sigs and ("process_burst" in sigs or "failed_auth" in sigs or "auth_lateral" in sigs):
            return "HUMAN_REVIEW"
        if self.max_risk >= 0.75 or self.score() >= 140:
            return "HUMAN_REVIEW"
        if self.max_risk >= 0.45 or self.score() >= 90:
            return "COLLECT_EVIDENCE"
        return "WATCH"

    def tier(self) -> int:
        sigs = set(self.signals)
        if "suspicious_port" in sigs and ("process_burst" in sigs or "failed_auth" in sigs or "auth_lateral" in sigs):
            return 1
        if "failed_auth" in sigs and ("process_burst" in sigs or "dns_flood" in sigs):
            return 2
        if "dns_flood" in sigs and ("process_burst" in sigs or "auth_lateral" in sigs):
            return 3
        return 4

    def to_json(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "bucket": self.bucket,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": max(0, self.end_time - self.start_time),
            "event_count": self.event_count,
            "max_risk": round(self.max_risk, 3),
            "score": self.score(),
            "tier": self.tier(),
            "recommended_action": self.recommended_action(),
            "signals": sorted(self.signals.keys()),
            "top_signals": self.signals.most_common(10),
            "top_users": self.users.most_common(10),
            "top_source_hosts": self.source_hosts.most_common(10),
            "top_dest_hosts": self.dest_hosts.most_common(10),
            "top_processes": self.processes.most_common(10),
            "top_ports": self.ports.most_common(10),
            "top_auth_types": self.auth_types.most_common(10),
            "top_logon_types": self.logon_types.most_common(10),
            "event_types": self.event_types.most_common(),
            "examples": self.examples,
        }


class EpisodeStore:
    def __init__(self, window_sec: int):
        self.window_sec = window_sec
        self.episodes: Dict[Tuple[str, int], Episode] = {}

    def _bucket(self, timestamp: int) -> int:
        return timestamp // self.window_sec

    def add(
        self,
        host: Optional[str],
        timestamp: int,
        event_type: str,
        risk: float,
        signals: Iterable[str],
        **kwargs: Any,
    ) -> None:
        if not host or timestamp < 0:
            return
        bucket = self._bucket(timestamp)
        key = (host, bucket)

        if key not in self.episodes:
            self.episodes[key] = Episode(
                host=host,
                bucket=bucket,
                start_time=timestamp,
                end_time=timestamp,
            )

        self.episodes[key].add(
            timestamp=timestamp,
            event_type=event_type,
            risk=risk,
            signals=signals,
            **kwargs,
        )

    def filtered(self, config: Config) -> List[Episode]:
        out = []
        for ep in self.episodes.values():
            if len(ep.signals) >= config.min_episode_signals or ep.max_risk >= config.min_episode_risk:
                out.append(ep)
        out.sort(key=lambda e: (e.tier(), -e.score(), e.start_time, e.host))
        return out


# ============================================================
# TRACKERS
# ============================================================

class DNSBurstTracker:
    def __init__(self, window_sec: int, threshold: int):
        self.window_sec = window_sec
        self.threshold = threshold
        self.by_host: Dict[str, Deque[int]] = defaultdict(deque)

    def add(self, host: Optional[str], timestamp: int) -> Tuple[bool, int]:
        if not host:
            return False, 0
        q = self.by_host[host]
        cutoff = timestamp - self.window_sec
        while q and q[0] < cutoff:
            q.popleft()
        q.append(timestamp)
        return len(q) >= self.threshold, len(q)


class ProcessBurstTracker:
    def __init__(self, window_sec: int, threshold: int):
        self.window_sec = window_sec
        self.threshold = threshold
        self.by_host: Dict[str, Deque[Tuple[int, str, Optional[str]]]] = defaultdict(deque)

    def add(self, host: Optional[str], timestamp: int, process: Optional[str], user: Optional[str]) -> Tuple[bool, int]:
        if not host:
            return False, 0
        q = self.by_host[host]
        cutoff = timestamp - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()
        q.append((timestamp, process or "", user))
        return len(q) >= self.threshold, len(q)


# ============================================================
# REDTEAM LOADING + VALIDATION
# ============================================================

def load_redteam(path: Path) -> List[Dict[str, Any]]:
    events = []
    if not path.exists():
        return events

    with open_text(path) as f:
        for line in f:
            if not line.strip():
                continue
            ev = parse_redteam_line(line)
            if ev and ev["timestamp"] >= 0:
                events.append(ev)

    events.sort(key=lambda x: x["timestamp"])
    return events


def validate_against_redteam(
    episodes: List[Episode],
    redteam_events: List[Dict[str, Any]],
    window_sec: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    matches = []
    matched_rt_indices = set()
    matched_episode_keys = set()

    for i, rt in enumerate(redteam_events):
        rt_time = rt["timestamp"]
        rt_hosts = {rt.get("source_computer"), rt.get("dest_computer")}
        rt_hosts.discard(None)

        for ep in episodes:
            if ep.host not in rt_hosts:
                continue
            if ep.start_time <= rt_time + window_sec and ep.end_time >= rt_time - window_sec:
                matched_rt_indices.add(i)
                matched_episode_keys.add((ep.host, ep.bucket))
                matches.append({
                    "redteam": rt,
                    "episode": ep.to_json(),
                    "match_window_sec": window_sec,
                    "time_delta_to_episode_start": rt_time - ep.start_time,
                    "time_delta_to_episode_end": rt_time - ep.end_time,
                })

    summary = {
        "redteam_events": len(redteam_events),
        "matched_redteam_events": len(matched_rt_indices),
        "redteam_recall": round(len(matched_rt_indices) / max(1, len(redteam_events)), 6),
        "episodes": len(episodes),
        "matched_episodes": len(matched_episode_keys),
        "episode_match_rate": round(len(matched_episode_keys) / max(1, len(episodes)), 6),
        "total_matches": len(matches),
    }

    return matches, summary


# ============================================================
# PROCESSORS
# ============================================================

def process_flows(path: Path, store: EpisodeStore, config: Config, stats: Counter) -> None:
    if not path.exists():
        print(f"[skip] flows file not found: {path}")
        return

    print(f"[flows] reading {path}")
    with open_text(path) as f:
        for n, line in enumerate(f, 1):
            if config.max_lines and n > config.max_lines:
                break

            ev = parse_flow_line(line)
            if not ev or ev["timestamp"] < 0:
                stats["flow_parse_fail"] += 1
                continue

            stats["flow_events"] += 1
            ts = ev["timestamp"]
            src = ev["source_computer"]
            dst = ev["dest_computer"]
            dport = ev["dest_port"]
            bytes_ = ev["bytes"]

            signals = []
            risk = 0.0

            if dport in config.suspicious_ports:
                signals.append("suspicious_port")
                risk = max(risk, 0.75)

            if bytes_ >= config.large_flow_bytes:
                signals.append("large_flow")
                risk = max(risk, 0.30)

            if signals:
                example = {
                    "type": "flow",
                    "timestamp": ts,
                    "source_computer": src,
                    "dest_computer": dst,
                    "dest_port": dport,
                    "bytes": bytes_,
                }
                store.add(
                    host=src,
                    timestamp=ts,
                    event_type="flow",
                    risk=risk,
                    signals=signals,
                    source_host=src,
                    dest_host=dst,
                    port=dport,
                    example=example,
                )
                store.add(
                    host=dst,
                    timestamp=ts,
                    event_type="flow",
                    risk=risk,
                    signals=signals,
                    source_host=src,
                    dest_host=dst,
                    port=dport,
                    example=example,
                )
                stats["flow_signal_events"] += 1

            if n % config.progress_every == 0:
                print(f"  flows: {n:,} lines processed; signal_events={stats['flow_signal_events']:,}")


def process_auth(path: Path, store: EpisodeStore, config: Config, stats: Counter) -> None:
    if not path.exists():
        print(f"[skip] auth file not found: {path}")
        return

    print(f"[auth] reading {path}")
    with open_text(path) as f:
        for n, line in enumerate(f, 1):
            if config.max_lines and n > config.max_lines:
                break

            ev = parse_auth_line(line)
            if not ev or ev["timestamp"] < 0:
                stats["auth_parse_fail"] += 1
                continue

            stats["auth_events"] += 1
            ts = ev["timestamp"]
            src = ev["source_computer"]
            dst = ev["dest_computer"]
            user = ev["source_user"] or ev["dest_user"]
            success = ev["success"]

            signals = []
            risk = 0.0

            if not success:
                signals.append("failed_auth")
                risk = max(risk, 0.55)

            if success and src and dst and src != dst:
                signals.append("auth_lateral")
                risk = max(risk, 0.22)

            if signals:
                example = {
                    "type": "auth",
                    "timestamp": ts,
                    "source_user": ev["source_user"],
                    "dest_user": ev["dest_user"],
                    "source_computer": src,
                    "dest_computer": dst,
                    "auth_type": ev["auth_type"],
                    "logon_type": ev["logon_type"],
                    "orientation": ev["orientation"],
                    "success": success,
                }
                store.add(
                    host=src,
                    timestamp=ts,
                    event_type="auth",
                    risk=risk,
                    signals=signals,
                    user=user,
                    source_host=src,
                    dest_host=dst,
                    auth_type=ev["auth_type"],
                    logon_type=ev["logon_type"],
                    example=example,
                )
                store.add(
                    host=dst,
                    timestamp=ts,
                    event_type="auth",
                    risk=risk,
                    signals=signals,
                    user=user,
                    source_host=src,
                    dest_host=dst,
                    auth_type=ev["auth_type"],
                    logon_type=ev["logon_type"],
                    example=example,
                )
                stats["auth_signal_events"] += 1

            if n % config.progress_every == 0:
                print(f"  auth: {n:,} lines processed; signal_events={stats['auth_signal_events']:,}")


def process_proc(path: Path, store: EpisodeStore, config: Config, stats: Counter) -> None:
    if not path.exists():
        print(f"[skip] proc file not found: {path}")
        return

    print(f"[proc] reading {path}")
    tracker = ProcessBurstTracker(config.proc_window_sec, config.proc_burst_threshold)

    with open_text(path) as f:
        for n, line in enumerate(f, 1):
            if config.max_lines and n > config.max_lines:
                break

            ev = parse_proc_line(line)
            if not ev or ev["timestamp"] < 0:
                stats["proc_parse_fail"] += 1
                continue

            stats["proc_events"] += 1

            action = (ev["action"] or "").lower()
            if action != "start":
                continue

            host = ev["computer"]
            ts = ev["timestamp"]
            proc = ev["process"]
            user = ev["user"]

            is_burst, count = tracker.add(host, ts, proc, user)

            if is_burst:
                example = {
                    "type": "proc",
                    "timestamp": ts,
                    "user": user,
                    "computer": host,
                    "process": proc,
                    "window_count": count,
                }
                store.add(
                    host=host,
                    timestamp=ts,
                    event_type="proc",
                    risk=0.45,
                    signals=["process_burst"],
                    user=user,
                    process=proc,
                    example=example,
                )
                stats["proc_burst_events"] += 1

            if n % config.progress_every == 0:
                print(f"  proc: {n:,} lines processed; burst_events={stats['proc_burst_events']:,}")


def process_dns(path: Path, store: EpisodeStore, config: Config, stats: Counter) -> None:
    if not path.exists():
        print(f"[skip] dns file not found: {path}")
        return

    print(f"[dns] reading {path}")
    tracker = DNSBurstTracker(config.dns_window_sec, config.dns_threshold)

    with open_text(path) as f:
        for n, line in enumerate(f, 1):
            if config.max_lines and n > config.max_lines:
                break

            ev = parse_dns_line(line)
            if not ev or ev["timestamp"] < 0:
                stats["dns_parse_fail"] += 1
                continue

            stats["dns_events"] += 1
            host = ev["source_computer"]
            ts = ev["timestamp"]
            is_flood, count = tracker.add(host, ts)

            if is_flood:
                example = {
                    "type": "dns",
                    "timestamp": ts,
                    "source_computer": host,
                    "resolved_computer": ev["resolved_computer"],
                    "window_count": count,
                }
                store.add(
                    host=host,
                    timestamp=ts,
                    event_type="dns",
                    risk=0.45,
                    signals=["dns_flood"],
                    source_host=host,
                    dest_host=ev["resolved_computer"],
                    example=example,
                )
                stats["dns_flood_events"] += 1

            if n % config.progress_every == 0:
                print(f"  dns: {n:,} lines processed; flood_events={stats['dns_flood_events']:,}")


# ============================================================
# OUTPUT
# ============================================================

def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    count = 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
            count += 1
    return count


def write_report(
    path: Path,
    episodes: List[Episode],
    matches: List[Dict[str, Any]],
    validation_summary: Dict[str, Any],
    stats: Counter,
    config: Config,
) -> None:
    tier_counts = Counter(ep.tier() for ep in episodes)
    action_counts = Counter(ep.recommended_action() for ep in episodes)
    signal_counts = Counter()
    host_counts = Counter()

    for ep in episodes:
        host_counts[ep.host] += 1
        signal_counts.update(ep.signals.keys())

    lines = []
    lines.append("=" * 100)
    lines.append("SRIA RED TEAM VALIDATION REPORT v0.1")
    lines.append("=" * 100)
    lines.append("")
    lines.append("Configuration:")
    lines.append(f"  base_dir: {config.base_dir}")
    lines.append(f"  out_dir: {config.out_dir}")
    lines.append(f"  episode_window_sec: {config.episode_window_sec}")
    lines.append(f"  redteam_match_window_sec: {config.redteam_match_window_sec}")
    lines.append(f"  max_lines: {'unlimited' if config.max_lines == 0 else config.max_lines}")
    lines.append("")
    lines.append("Input event statistics:")
    for k, v in stats.most_common():
        lines.append(f"  {k}: {v:,}")

    lines.append("")
    lines.append("Episode summary:")
    lines.append(f"  episodes_written: {len(episodes):,}")
    lines.append("  tiers:")
    for tier in sorted(tier_counts):
        lines.append(f"    Tier {tier}: {tier_counts[tier]:,}")
    lines.append("  actions:")
    for action, count in action_counts.most_common():
        lines.append(f"    {action}: {count:,}")

    lines.append("")
    lines.append("Redteam validation:")
    for k, v in validation_summary.items():
        lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("Top episode signals:")
    for sig, count in signal_counts.most_common(20):
        lines.append(f"  {sig}: {count:,}")

    lines.append("")
    lines.append("Top hosts by episode count:")
    for host, count in host_counts.most_common(30):
        lines.append(f"  {host}: {count:,}")

    lines.append("")
    lines.append("=" * 100)
    lines.append("TOP 50 EPISODES")
    lines.append("=" * 100)
    for idx, ep in enumerate(episodes[:50], 1):
        row = ep.to_json()
        lines.append("")
        lines.append(
            f"#{idx:03d} | Tier {row['tier']} | score={row['score']} | "
            f"{row['host']} | {row['recommended_action']} | "
            f"risk={row['max_risk']} | events={row['event_count']} | "
            f"duration={row['duration']}s"
        )
        lines.append(f"  Signals: {', '.join(row['signals'])}")
        lines.append(f"  Users: {row['top_users'][:5]}")
        lines.append(f"  Processes: {row['top_processes'][:5]}")
        lines.append(f"  Ports: {row['top_ports'][:5]}")
        lines.append(f"  Event types: {row['event_types']}")

    lines.append("")
    lines.append("=" * 100)
    lines.append("INTERPRETATION")
    lines.append("=" * 100)
    lines.append(
        "This report measures overlap between SRIA-generated episodes and LANL redteam ground truth. "
        "A match indicates temporal/host overlap, not automatic proof that the episode explains the redteam event."
    )
    lines.append(
        "High recall suggests the episode logic is capturing relevant redteam-adjacent activity. "
        "Low recall means the current SRIA signals are missing redteam behavior and need adjustment."
    )
    lines.append(
        "High episode volume or low match rate suggests false-positive pressure and requires stricter gating."
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline(config: Config) -> Dict[str, Any]:
    config.base_dir = Path(config.base_dir)
    config.out_dir = resolve_path(config.base_dir, config.out_dir)

    auth_path = resolve_path(config.base_dir, config.auth_file)
    proc_path = resolve_path(config.base_dir, config.proc_file)
    flows_path = resolve_path(config.base_dir, config.flows_file)
    dns_path = resolve_path(config.base_dir, config.dns_file)
    redteam_path = resolve_path(config.base_dir, config.redteam_file)

    config.out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 100)
    print("SRIA Red Team Validation v0.1")
    print("=" * 100)
    print(f"Base dir: {config.base_dir}")
    print(f"Output dir: {config.out_dir}")
    print(f"Auth: {auth_path}")
    print(f"Proc: {proc_path}")
    print(f"Flows: {flows_path}")
    print(f"DNS: {dns_path}")
    print(f"Redteam: {redteam_path}")
    print(f"Max lines per file: {'unlimited' if config.max_lines == 0 else config.max_lines}")
    print("=" * 100)

    store = EpisodeStore(config.episode_window_sec)
    stats = Counter()

    redteam_events = load_redteam(redteam_path)
    stats["redteam_events"] = len(redteam_events)
    print(f"[redteam] loaded {len(redteam_events):,} events")

    process_flows(flows_path, store, config, stats)
    process_auth(auth_path, store, config, stats)
    process_proc(proc_path, store, config, stats)
    process_dns(dns_path, store, config, stats)

    episodes = store.filtered(config)
    print(f"[episodes] filtered episodes: {len(episodes):,}")

    matches, validation_summary = validate_against_redteam(
        episodes=episodes,
        redteam_events=redteam_events,
        window_sec=config.redteam_match_window_sec,
    )

    episodes_path = config.out_dir / "sria_rt_episodes_v01.jsonl"
    matches_path = config.out_dir / "sria_rt_redteam_matches_v01.jsonl"
    report_path = config.out_dir / "sria_rt_report_v01.txt"

    write_jsonl(episodes_path, (ep.to_json() for ep in episodes))
    write_jsonl(matches_path, matches)
    write_report(report_path, episodes, matches, validation_summary, stats, config)

    print("")
    print("=" * 100)
    print("DONE")
    print("=" * 100)
    print(f"Episodes: {episodes_path}")
    print(f"Matches:  {matches_path}")
    print(f"Report:   {report_path}")
    print("")
    print("Validation summary:")
    for k, v in validation_summary.items():
        print(f"  {k}: {v}")

    return {
        "episodes": episodes,
        "matches": matches,
        "validation_summary": validation_summary,
        "stats": stats,
        "episodes_path": episodes_path,
        "matches_path": matches_path,
        "report_path": report_path,
    }


# ============================================================
# SELF TEST
# ============================================================

def write_lines(path: Path, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line.rstrip("\n") + "\n")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)

        write_lines(base / "redteam.txt", [
            "1000,U1@DOM,C1,C2",
            "2000,U2@DOM,C3,C4",
        ])

        write_lines(base / "flows.txt", [
            "995,1,C1,12345,C2,4444,6,10,2000",
            "1990,1,C3,12345,C4,80,6,10,2000",
        ])

        write_lines(base / "auth.txt", [
            "1001,U1@DOM,U1@DOM,C1,C2,Kerberos,Network,LogOn,Success",
            "2001,U2@DOM,U2@DOM,C3,C4,Kerberos,Network,LogOn,Fail",
        ])

        proc_lines = []
        for i in range(30):
            proc_lines.append(f"{1000+i},U1@DOM,C2,P{i},Start")
        write_lines(base / "proc.txt", proc_lines)

        dns_lines = []
        for i in range(105):
            dns_lines.append(f"{3000+i//3},C9,CX{i}")
        write_lines(base / "dns.txt", dns_lines)

        cfg = Config(
            base_dir=base,
            out_dir=Path("out"),
            progress_every=10_000,
            proc_burst_threshold=10,
            dns_threshold=50,
        )

        result = run_pipeline(cfg)
        summary = result["validation_summary"]

        assert summary["redteam_events"] == 2
        assert summary["matched_redteam_events"] >= 1
        assert len(result["episodes"]) > 0
        assert result["episodes_path"].exists()
        assert result["matches_path"].exists()
        assert result["report_path"].exists()

        print("")
        print("[self-test] PASS")


# ============================================================
# CLI
# ============================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SRIA Red Team Validation v0.1")

    parser.add_argument("--base-dir", default=".", help="Directory containing LANL files")
    parser.add_argument("--out-dir", default="sria_rt_v01_output", help="Output directory")

    parser.add_argument("--auth", default="auth.txt", help="auth.txt path")
    parser.add_argument("--proc", default="proc.txt", help="proc.txt path")
    parser.add_argument("--flows", default="flows.txt", help="flows.txt path")
    parser.add_argument("--dns", default="dns.txt", help="dns.txt path")
    parser.add_argument("--redteam", default="redteam.txt", help="redteam.txt path")

    parser.add_argument("--episode-window", type=int, default=300)
    parser.add_argument("--redteam-window", type=int, default=300)
    parser.add_argument("--progress-every", type=int, default=1_000_000)
    parser.add_argument("--max-lines", type=int, default=0)

    parser.add_argument("--large-flow-bytes", type=int, default=10_000_000)
    parser.add_argument("--dns-threshold", type=int, default=100)
    parser.add_argument("--proc-burst-threshold", type=int, default=25)

    parser.add_argument("--self-test", action="store_true")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.self_test:
        self_test()
        return

    cfg = Config(
        base_dir=Path(args.base_dir),
        out_dir=Path(args.out_dir),
        auth_file=Path(args.auth),
        proc_file=Path(args.proc),
        flows_file=Path(args.flows),
        dns_file=Path(args.dns),
        redteam_file=Path(args.redteam),
        episode_window_sec=args.episode_window,
        redteam_match_window_sec=args.redteam_window,
        progress_every=args.progress_every,
        max_lines=args.max_lines,
        large_flow_bytes=args.large_flow_bytes,
        dns_threshold=args.dns_threshold,
        proc_burst_threshold=args.proc_burst_threshold,
    )

    run_pipeline(cfg)


if __name__ == "__main__":
    main()
