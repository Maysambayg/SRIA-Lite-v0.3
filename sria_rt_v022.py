#!/usr/bin/env python3
"""
sria_rt_v022.py

Fast SRIA red-team alignment validator.

Purpose:
- Do NOT scan forever blindly.
- Load redteam.txt.
- Scan auth.txt once.
- Only inspect rows near redteam timestamp windows.
- Confirm whether redteam source/destination/user patterns exist in auth.txt.
- Produce a small evidence report.

Run:
  py F:\SRIA\SRIA_RT_v01\sria_rt_v022.py --base-dir F:\SRIA\SRIA_RT_v01

Optional:
  py F:\SRIA\SRIA_RT_v01\sria_rt_v022.py --base-dir F:\SRIA\SRIA_RT_v01 --window 300
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from collections import defaultdict, Counter


def norm(x: str) -> str:
    return (x or "").strip().lower()


def parse_redteam(path: Path):
    events = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            try:
                ts = int(parts[0])
            except ValueError:
                continue

            events.append({
                "time": ts,
                "user": parts[1],
                "source": parts[2],
                "dest": parts[3],
                "line_no": line_no,
            })
    return events


def safe_int(x):
    try:
        return int(x)
    except Exception:
        return None


def parse_auth_line(line: str):
    """
    LANL auth.txt commonly uses:
    time,source_user,dest_user,source_computer,dest_computer,auth_type,logon_type,auth_orientation,success

    We keep it tolerant.
    """
    parts = [p.strip() for p in line.rstrip("\n").split(",")]
    if len(parts) < 5:
        return None

    ts = safe_int(parts[0])
    if ts is None:
        return None

    return {
        "time": ts,
        "source_user": parts[1] if len(parts) > 1 else "",
        "dest_user": parts[2] if len(parts) > 2 else "",
        "source": parts[3] if len(parts) > 3 else "",
        "dest": parts[4] if len(parts) > 4 else "",
        "raw": line.rstrip("\n"),
    }


def build_time_index(redteam_events, window: int):
    """
    Maps every timestamp in redteam_time +/- window to candidate redteam indices.
    Redteam file is small, so this is acceptable.
    """
    by_time = defaultdict(list)
    for i, rt in enumerate(redteam_events):
        start = rt["time"] - window
        end = rt["time"] + window
        for t in range(start, end + 1):
            by_time[t].append(i)
    return by_time


def match_score(rt, auth):
    score = 0
    reasons = []

    if norm(rt["source"]) == norm(auth["source"]):
        score += 3
        reasons.append("source_match")

    if norm(rt["dest"]) == norm(auth["dest"]):
        score += 3
        reasons.append("dest_match")

    user = norm(rt["user"])
    if user and (user == norm(auth["source_user"]) or user == norm(auth["dest_user"])):
        score += 2
        reasons.append("user_match")

    dt = abs(rt["time"] - auth["time"])
    if dt == 0:
        score += 3
        reasons.append("exact_time")
    elif dt <= 10:
        score += 2
        reasons.append("time_within_10s")
    elif dt <= 300:
        score += 1
        reasons.append("time_within_window")

    return score, reasons


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-dir", default=".", help="Folder containing auth.txt and redteam.txt")
    ap.add_argument("--out-dir", default=None, help="Output folder")
    ap.add_argument("--window", type=int, default=300, help="Seconds around each redteam timestamp")
    ap.add_argument("--progress-every", type=int, default=1_000_000)
    args = ap.parse_args()

    base_dir = Path(args.base_dir)
    out_dir = Path(args.out_dir) if args.out_dir else base_dir / "sria_rt_v022_output"
    out_dir.mkdir(parents=True, exist_ok=True)

    auth_file = base_dir / "auth.txt"
    redteam_file = base_dir / "redteam.txt"

    matches_file = out_dir / "redteam_auth_matches_v022.jsonl"
    report_file = out_dir / "redteam_alignment_report_v022.txt"

    print("=" * 80)
    print("SRIA Red Team Auth Alignment v0.2.2")
    print("=" * 80)
    print(f"Base dir: {base_dir}")
    print(f"Auth: {auth_file}")
    print(f"Redteam: {redteam_file}")
    print(f"Window: +/- {args.window}s")
    print(f"Output: {out_dir}")
    print("=" * 80)

    if not auth_file.exists():
        raise FileNotFoundError(f"auth.txt not found: {auth_file}")
    if not redteam_file.exists():
        raise FileNotFoundError(f"redteam.txt not found: {redteam_file}")

    redteam = parse_redteam(redteam_file)
    if not redteam:
        raise RuntimeError("No redteam events loaded. Check redteam.txt format.")

    rt_min = min(r["time"] for r in redteam)
    rt_max = max(r["time"] for r in redteam)

    print(f"[redteam] loaded {len(redteam)} events")
    print(f"[redteam] time range: {rt_min} - {rt_max}")

    time_index = build_time_index(redteam, args.window)

    best_by_rt = {}
    total_candidate_auth = 0
    total_lines = 0
    auth_min = None
    auth_max = None

    source_counter = Counter()
    dest_counter = Counter()

    print("\n[auth] scanning once...")

    with auth_file.open("r", encoding="utf-8", errors="replace") as f, matches_file.open("w", encoding="utf-8") as out:
        for line in f:
            total_lines += 1

            auth = parse_auth_line(line)
            if auth is None:
                continue

            ts = auth["time"]
            auth_min = ts if auth_min is None else min(auth_min, ts)
            auth_max = ts if auth_max is None else max(auth_max, ts)

            # Skip most of the file cheaply
            candidates = time_index.get(ts)
            if not candidates:
                if total_lines % args.progress_every == 0:
                    print(f"  scanned {total_lines:,} auth lines... candidates={total_candidate_auth:,}")
                continue

            total_candidate_auth += 1
            source_counter[auth["source"]] += 1
            dest_counter[auth["dest"]] += 1

            for rt_idx in candidates:
                rt = redteam[rt_idx]
                score, reasons = match_score(rt, auth)

                if score <= 0:
                    continue

                existing = best_by_rt.get(rt_idx)
                if existing is None or score > existing["score"]:
                    best_by_rt[rt_idx] = {
                        "redteam_index": rt_idx,
                        "score": score,
                        "reasons": reasons,
                        "delta_seconds": auth["time"] - rt["time"],
                        "redteam": rt,
                        "auth": auth,
                    }

            if total_lines % args.progress_every == 0:
                print(f"  scanned {total_lines:,} auth lines... candidates={total_candidate_auth:,}")

        for rt_idx, item in sorted(best_by_rt.items()):
            out.write(json.dumps(item) + "\n")

    matched = len(best_by_rt)
    recall = matched / max(1, len(redteam))

    strong = sum(1 for x in best_by_rt.values() if x["score"] >= 7)
    medium = sum(1 for x in best_by_rt.values() if 4 <= x["score"] < 7)
    weak = sum(1 for x in best_by_rt.values() if x["score"] < 4)

    lines = []
    lines.append("=" * 80)
    lines.append("SRIA REDTEAM AUTH ALIGNMENT REPORT v0.2.2")
    lines.append("=" * 80)
    lines.append(f"Auth lines scanned: {total_lines:,}")
    lines.append(f"Auth time range observed: {auth_min} - {auth_max}")
    lines.append(f"Redteam events: {len(redteam):,}")
    lines.append(f"Redteam time range: {rt_min} - {rt_max}")
    lines.append(f"Candidate auth rows inside redteam windows: {total_candidate_auth:,}")
    lines.append(f"Matched redteam events: {matched:,}")
    lines.append(f"Recall estimate: {recall:.4f}")
    lines.append("")
    lines.append("Match strength:")
    lines.append(f"  strong score >= 7: {strong:,}")
    lines.append(f"  medium score 4-6: {medium:,}")
    lines.append(f"  weak score < 4: {weak:,}")
    lines.append("")
    lines.append("Top auth sources inside redteam windows:")
    for k, v in source_counter.most_common(20):
        lines.append(f"  {k}: {v:,}")
    lines.append("")
    lines.append("Top auth destinations inside redteam windows:")
    for k, v in dest_counter.most_common(20):
        lines.append(f"  {k}: {v:,}")
    lines.append("")
    lines.append("Best first 20 matches:")
    for rt_idx, item in list(sorted(best_by_rt.items()))[:20]:
        rt = item["redteam"]
        auth = item["auth"]
        lines.append(
            f"  RT#{rt_idx} score={item['score']} dt={item['delta_seconds']} "
            f"rt=({rt['time']},{rt['user']},{rt['source']}->{rt['dest']}) "
            f"auth=({auth['time']},{auth['source_user']}/{auth['dest_user']},{auth['source']}->{auth['dest']}) "
            f"reasons={item['reasons']}"
        )
    lines.append("")
    lines.append(f"Matches JSONL: {matches_file}")
    lines.append(f"Report: {report_file}")

    report_file.write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "\n".join(lines))
    print("\nDONE")


if __name__ == "__main__":
    main()
