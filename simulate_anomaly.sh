#!/usr/bin/env bash
# Generate a CONTROLLED, NON-destructive anomalous workload so you can watch the
# detector fire. It mimics recon/port-scan behavior: a burst of socket()/connect()
# syscalls to localhost ports -- a syscall mix a normal desktop process never makes.
#
# It is intentionally safe: localhost only, time-bounded, no fork bomb, no real
# network traffic leaving the machine.
#
# Usage:  ./simulate_anomaly.sh [seconds]   (default 10)
set -euo pipefail

DURATION="${1:-10}"
echo "[sim] generating scan-like syscall bursts for ${DURATION}s (localhost only, safe)..."

end=$((SECONDS + DURATION))
while [ "$SECONDS" -lt "$end" ]; do
  for port in 81 82 83 84 85 86 87 88 89 90; do
    # Each attempt = socket()+connect()+close(): bursty, unusual for a desktop app.
    timeout 0.05 bash -c "exec 3<>/dev/tcp/127.0.0.1/${port}" 2>/dev/null || true
  done
done

echo "[sim] done. Check monitor.py output for ANOMALY lines on this script's PID."
