#!/usr/bin/env python3
"""
SRIA RT v0.6.1a - Disk-Friendly Auth Time Profiler

Purpose:
  Build a compact time-density profile from LANL auth.txt without storing raw events.
  This is a safer precursor to auditable background-window selection.

Typical CMD use from F:\\SRIA\\SRIA_RT_v01:
  py sria_rt_v061a_auth_time_profile.py --auth-file auth.txt --out-dir v061a_auth_time_profile --bucket-size 3600 --progress-every-lines 1000000

Smoke test:
  py sria_rt_v061a_auth_time_profile.py --auth-file auth.txt --out-dir v061a_auth_time_profile_smoke --bucket-size 3600 --sample-limit-lines 5000000 --progress-every-lines 500000

Notes:
  - Reads auth.txt sequentially.
  - Stores only bucket counts and lightweight metadata.
  - Supports sample-limit smoke tests.
  - Supports max-runtime stop with checkpoint.
  - Supports resume from checkpoint, but resume skips already processed lines sequentially.
    This is still safe, but not instant on a 73 GB file. Prefer long single runs when possible.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


VERSION = "0.6.1a"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_int(value: object, default: int = 0) -> int:
    try:
        if value is None:
            return default
        s = str(value).strip()
        if not s:
            return default
        return int(float(s))
    except Exception:
        return default


def parse_auth_timestamp(line: str) -> Optional[int]:
    """LANL auth lines start with integer time in seconds."""
    if not line:
        return None
    # Fast split on first comma only.
    try:
        first = line.split(",", 1)[0]
        return int(first)
    except Exception:
        return None


def bucket_start_for_ts(ts: int, bucket_size: int) -> int:
    return (ts // bucket_size) * bucket_size


def load_checkpoint(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_checkpoint(path: Path, state: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def write_profile_csv(path: Path, buckets: Dict[int, int], bucket_size: int) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "bucket_start",
                "bucket_end",
                "bucket_size",
                "auth_line_count",
            ],
        )
        w.writeheader()
        for start in sorted(buckets):
            w.writerow(
                {
                    "bucket_start": start,
                    "bucket_end": start + bucket_size,
                    "bucket_size": bucket_size,
                    "auth_line_count": buckets[start],
                }
            )


def write_report(path: Path, lines: List[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarize_buckets(buckets: Dict[int, int]) -> dict:
    counts = list(buckets.values())
    if not counts:
        return {
            "bucket_count": 0,
            "min_bucket_count": 0,
            "max_bucket_count": 0,
            "mean_bucket_count": 0,
            "median_bucket_count": 0,
            "nonempty_bucket_count": 0,
        }
    counts_sorted = sorted(counts)
    n = len(counts_sorted)
    if n % 2:
        med = counts_sorted[n // 2]
    else:
        med = (counts_sorted[n // 2 - 1] + counts_sorted[n // 2]) / 2.0
    return {
        "bucket_count": len(counts),
        "min_bucket_count": min(counts),
        "max_bucket_count": max(counts),
        "mean_bucket_count": sum(counts) / len(counts),
        "median_bucket_count": med,
        "nonempty_bucket_count": len([c for c in counts if c > 0]),
    }


def progress_line(processed: int, bad_lines: int, min_ts: Optional[int], max_ts: Optional[int], start_wall: float) -> str:
    elapsed = max(time.time() - start_wall, 1e-9)
    rate = processed / elapsed
    return (
        f"[progress] lines={processed:,} bad={bad_lines:,} "
        f"range={min_ts if min_ts is not None else 'NA'}-"
        f"{max_ts if max_ts is not None else 'NA'} rate={rate:,.0f} lines/sec elapsed={elapsed:,.1f}s"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="SRIA RT v0.6.1a disk-friendly auth time profiler")
    ap.add_argument("--auth-file", required=True, help="Path to LANL auth.txt")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    ap.add_argument("--bucket-size", type=int, default=3600, help="Time bucket size in seconds")
    ap.add_argument("--sample-limit-lines", type=int, default=0, help="Stop after N lines for smoke testing; 0 means no limit")
    ap.add_argument("--max-runtime-seconds", type=int, default=0, help="Stop after N seconds and write checkpoint; 0 means no runtime limit")
    ap.add_argument("--progress-every-lines", type=int, default=1000000, help="Print/write progress every N lines")
    ap.add_argument("--checkpoint-every-lines", type=int, default=1000000, help="Write checkpoint every N lines")
    ap.add_argument("--resume", action="store_true", help="Resume from checkpoint if available")
    ap.add_argument("--quiet", action="store_true", help="Reduce console progress output")
    args = ap.parse_args()

    auth_path = Path(args.auth_file)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    bucket_size = int(args.bucket_size)
    if bucket_size <= 0:
        raise SystemExit("--bucket-size must be positive")

    profile_csv = out_dir / "v061a_auth_time_profile.csv"
    report_txt = out_dir / "v061a_auth_time_profile_report.txt"
    manifest_json = out_dir / "v061a_auth_time_profile_manifest.json"
    checkpoint_json = out_dir / "v061a_auth_time_profile_checkpoint.json"
    progress_log = out_dir / "v061a_auth_time_profile_progress.log"

    print("=" * 80)
    print("SRIA RT v0.6.1a - Disk-Friendly Auth Time Profiler")
    print("=" * 80)
    print(f"Auth file: {auth_path}")
    print(f"Output dir: {out_dir}")
    print(f"Bucket size: {bucket_size}")
    print(f"Sample limit lines: {args.sample_limit_lines if args.sample_limit_lines else 'none'}")
    print(f"Max runtime seconds: {args.max_runtime_seconds if args.max_runtime_seconds else 'none'}")
    print(f"Resume: {bool(args.resume)}")
    print("NOTE: This script builds a compact timestamp histogram only.")
    print("NOTE: It does not run SRIA detection, load models, or score episodes.")
    print("=" * 80)

    if not auth_path.exists():
        raise SystemExit(f"Auth file not found: {auth_path}")

    buckets: Dict[int, int] = defaultdict(int)
    processed = 0
    bad_lines = 0
    min_ts: Optional[int] = None
    max_ts: Optional[int] = None
    resume_skip_lines = 0
    started_at = utc_now()

    cp = load_checkpoint(checkpoint_json) if args.resume else None
    if cp:
        if cp.get("auth_file") == str(auth_path) and int(cp.get("bucket_size", -1)) == bucket_size:
            processed = int(cp.get("processed_lines", 0))
            bad_lines = int(cp.get("bad_lines", 0))
            min_ts = cp.get("min_ts")
            max_ts = cp.get("max_ts")
            buckets = defaultdict(int, {int(k): int(v) for k, v in cp.get("buckets", {}).items()})
            resume_skip_lines = processed
            print(f"[resume] checkpoint loaded; skipping {resume_skip_lines:,} already processed lines")
        else:
            print("[resume] checkpoint ignored because auth file or bucket size differs")

    start_wall = time.time()
    last_checkpoint_processed = processed
    stop_reason = "completed"

    progress_log.write_text(
        f"started_at={started_at}\nversion={VERSION}\nauth_file={auth_path}\nbucket_size={bucket_size}\n",
        encoding="utf-8",
    )

    with auth_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        # Resume by skipping lines. This is safer than byte offsets across encodings/newlines.
        if resume_skip_lines:
            for _ in range(resume_skip_lines):
                if not f.readline():
                    break

        while True:
            line = f.readline()
            if not line:
                stop_reason = "eof"
                break

            processed += 1
            ts = parse_auth_timestamp(line)
            if ts is None:
                bad_lines += 1
            else:
                if min_ts is None or ts < min_ts:
                    min_ts = ts
                if max_ts is None or ts > max_ts:
                    max_ts = ts
                buckets[bucket_start_for_ts(ts, bucket_size)] += 1

            if args.sample_limit_lines and processed >= args.sample_limit_lines:
                stop_reason = "sample_limit_lines"
                break

            if args.max_runtime_seconds and (time.time() - start_wall) >= args.max_runtime_seconds:
                stop_reason = "max_runtime_seconds"
                break

            if args.progress_every_lines > 0 and processed % args.progress_every_lines == 0:
                msg = progress_line(processed, bad_lines, min_ts, max_ts, start_wall)
                with progress_log.open("a", encoding="utf-8") as pf:
                    pf.write(msg + "\n")
                if not args.quiet:
                    print(msg, flush=True)

            if args.checkpoint_every_lines > 0 and processed - last_checkpoint_processed >= args.checkpoint_every_lines:
                state = {
                    "version": VERSION,
                    "auth_file": str(auth_path),
                    "out_dir": str(out_dir),
                    "bucket_size": bucket_size,
                    "processed_lines": processed,
                    "bad_lines": bad_lines,
                    "min_ts": min_ts,
                    "max_ts": max_ts,
                    "buckets": {str(k): v for k, v in buckets.items()},
                    "updated_at": utc_now(),
                    "stop_reason": "checkpoint",
                }
                write_checkpoint(checkpoint_json, state)
                last_checkpoint_processed = processed

    completed_at = utc_now()
    elapsed = time.time() - start_wall

    # Final artifacts
    write_profile_csv(profile_csv, buckets, bucket_size)

    summary = summarize_buckets(buckets)
    manifest = {
        "version": VERSION,
        "auth_file": str(auth_path),
        "out_dir": str(out_dir),
        "bucket_size": bucket_size,
        "sample_limit_lines": args.sample_limit_lines,
        "max_runtime_seconds": args.max_runtime_seconds,
        "processed_lines": processed,
        "bad_lines": bad_lines,
        "min_ts": min_ts,
        "max_ts": max_ts,
        "stop_reason": stop_reason,
        "started_at": started_at,
        "completed_at": completed_at,
        "elapsed_seconds": elapsed,
        "lines_per_second": processed / elapsed if elapsed > 0 else None,
        "profile_csv": str(profile_csv),
        "report_txt": str(report_txt),
        "checkpoint_json": str(checkpoint_json),
        "progress_log": str(progress_log),
        "summary": summary,
    }
    manifest_json.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    state = {
        "version": VERSION,
        "auth_file": str(auth_path),
        "out_dir": str(out_dir),
        "bucket_size": bucket_size,
        "processed_lines": processed,
        "bad_lines": bad_lines,
        "min_ts": min_ts,
        "max_ts": max_ts,
        "buckets": {str(k): v for k, v in buckets.items()},
        "updated_at": completed_at,
        "stop_reason": stop_reason,
    }
    write_checkpoint(checkpoint_json, state)

    report_lines = [
        f"SRIA RT v{VERSION} Auth Time Profile",
        "=" * 80,
        f"auth_file: {auth_path}",
        f"out_dir: {out_dir}",
        f"bucket_size: {bucket_size}",
        f"processed_lines: {processed:,}",
        f"bad_lines: {bad_lines:,}",
        f"auth_time_range: {min_ts} to {max_ts}",
        f"stop_reason: {stop_reason}",
        f"elapsed_seconds: {elapsed:,.2f}",
        f"lines_per_second: {processed / elapsed:,.0f}" if elapsed > 0 else "lines_per_second: NA",
        "",
        "Bucket summary:",
        f"  bucket_count: {summary['bucket_count']:,}",
        f"  nonempty_bucket_count: {summary['nonempty_bucket_count']:,}",
        f"  min_bucket_count: {summary['min_bucket_count']:,}",
        f"  median_bucket_count: {summary['median_bucket_count']:,.2f}",
        f"  mean_bucket_count: {summary['mean_bucket_count']:,.2f}",
        f"  max_bucket_count: {summary['max_bucket_count']:,}",
        "",
        "Outputs:",
        f"  {profile_csv.name}",
        f"  {manifest_json.name}",
        f"  {checkpoint_json.name}",
        f"  {progress_log.name}",
        "",
        "Interpretation:",
        "  This is a compact density profile only. It does not select final background windows.",
        "  Use v0.6.1b to select auditable windows from this profile without rescanning auth.txt.",
    ]
    write_report(report_txt, report_lines)

    print("=" * 80)
    print("SRIA RT v0.6.1a Auth Time Profile")
    print("=" * 80)
    print(f"processed_lines: {processed:,}")
    print(f"bad_lines: {bad_lines:,}")
    print(f"auth_time_range: {min_ts} to {max_ts}")
    print(f"stop_reason: {stop_reason}")
    print(f"bucket_count: {summary['bucket_count']:,}")
    print(f"elapsed_seconds: {elapsed:,.2f}")
    if elapsed > 0:
        print(f"lines_per_second: {processed / elapsed:,.0f}")
    print(f"Wrote profile: {profile_csv}")
    print(f"Wrote report: {report_txt}")
    print(f"Wrote manifest: {manifest_json}")
    print(f"Wrote checkpoint: {checkpoint_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
