"""Adapter: feed the Rust aya-tracer's JSON straight into the Python ML detector.

The Rust probe (`aya-tracer/`) emits one JSON line per window with the SAME contract as
`tracer.py` -- {pid: {syscall: count}}. This script reads those lines from stdin, turns each
process into a syscall fingerprint via `features.histogram_to_vector`, learns a clean
baseline over the first `--baseline-windows`, then flags anomalous processes live.

    sudo ./aya-tracer/target/release/aya-tracer | python3 monitor_from_stdin.py

So the kernel-side probe can be Rust (no bcc) while the ML stays in Python -- the JSON line is
the language-agnostic seam between them.
"""
from __future__ import annotations

import argparse
import json
import sys

from features import histogram_to_vector
from detector import AnomalyDetector, DistanceAnomalyDetector


def main() -> None:
    ap = argparse.ArgumentParser(description="ML detector reading aya-tracer JSON from stdin")
    ap.add_argument("--baseline-windows", type=int, default=15)
    ap.add_argument("--contamination", type=float, default=0.02)
    ap.add_argument("--detector", choices=["iforest", "distance"], default="distance")
    args = ap.parse_args()

    detector = (DistanceAnomalyDetector(contamination=args.contamination)
                if args.detector == "distance"
                else AnomalyDetector(contamination=args.contamination))

    baseline: list[list[float]] = []
    windows_seen = 0
    fitted = False
    print(f"[*] detector={args.detector}; learning baseline over "
          f"{args.baseline_windows} windows from aya-tracer stdin...", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            per_pid = json.loads(line)
        except json.JSONDecodeError:
            continue
        # JSON keys are strings; rebuild {syscall_int: count} per process.
        fingerprints = {
            pid: histogram_to_vector({int(s): c for s, c in hist.items()})
            for pid, hist in per_pid.items()
        }

        if not fitted:
            baseline.extend(fingerprints.values())
            windows_seen += 1
            if windows_seen >= args.baseline_windows:
                detector.fit(baseline)
                fitted = True
                print(f"[*] baseline learned from {len(baseline)} process-samples. "
                      f"Monitoring...", file=sys.stderr)
            continue

        pids = list(fingerprints)
        vectors = [fingerprints[p] for p in pids]
        if not vectors:
            continue
        preds = detector.predict(vectors)
        scores = detector.score(vectors)
        for pid, pred, score in zip(pids, preds, scores):
            if pred == -1:
                print(f"ANOMALY  pid={pid}  score={score:+.4f}")


if __name__ == "__main__":
    main()
