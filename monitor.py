"""Live host anomaly monitor: learn a baseline, then flag anomalous processes.

Run as root (eBPF needs privileges):
    sudo python3 monitor.py --baseline-windows 30 --window 1.0

Flow:
    1. For `baseline-windows` samples, record every process's syscall fingerprint
       while the machine does NORMAL things. This trains the detector.
    2. Then monitor forever: each window, score live processes and print anomalies.

This wires together the three pieces (tracer -> features -> detector). Each piece
is independently testable; only this entrypoint needs root + bcc.
"""
from __future__ import annotations

import argparse

from features import histogram_to_vector
from detector import AnomalyDetector, DistanceAnomalyDetector
from tracer import SyscallTracer


def main() -> None:
    ap = argparse.ArgumentParser(description="eBPF + ML host anomaly monitor")
    ap.add_argument("--window", type=float, default=1.0, help="seconds per sample window")
    ap.add_argument("--baseline-windows", type=int, default=30, help="windows to learn 'normal'")
    ap.add_argument("--contamination", type=float, default=0.02, help="expected anomaly fraction")
    ap.add_argument("--detector", choices=["iforest", "distance"], default="distance",
                    help="iforest = IsolationForest; distance = cosine-NN novelty "
                         "(better recall on a real host -- see README)")
    args = ap.parse_args()

    tracer = SyscallTracer()
    detector = (DistanceAnomalyDetector(contamination=args.contamination)
                if args.detector == "distance"
                else AnomalyDetector(contamination=args.contamination))
    print(f"[*] detector = {args.detector}")

    print(f"[*] Learning baseline over {args.baseline_windows} windows "
          f"({args.window}s each). Keep the box doing NORMAL things...")
    baseline = []
    for i in range(args.baseline_windows):
        per_pid = tracer.collect(args.window)
        baseline.extend(histogram_to_vector(h) for h in per_pid.values())
        print(f"    window {i + 1}/{args.baseline_windows}  ({len(baseline)} samples)", end="\r")
    detector.fit(baseline)
    print(f"\n[*] Baseline learned from {len(baseline)} process-samples. Monitoring...\n")

    while True:
        per_pid = tracer.collect(args.window)
        pids = list(per_pid.keys())
        vectors = [histogram_to_vector(per_pid[p]) for p in pids]
        if not vectors:
            continue
        preds = detector.predict(vectors)
        scores = detector.score(vectors)
        for pid, pred, score in zip(pids, preds, scores):
            if pred == -1:  # -1 = anomaly
                print(f"[!] ANOMALY  pid={pid:<7} score={score:+.3f}")


if __name__ == "__main__":
    main()
