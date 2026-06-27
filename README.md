# ebpf-ml-anomaly

Real-time host anomaly detection: an **eBPF** probe collects per-process syscall
activity in-kernel, and an **unsupervised ML** model flags processes whose syscall
fingerprint drifts from a learned baseline — a minimal host-IDS in the spirit of
Falco/Tracee.

![ci](https://github.com/MGE-GOAT/Ebpf-Syscall-Anomaly-Detector/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.11-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## What it does

- Attaches an eBPF program to the `raw_syscalls:sys_enter` tracepoint and counts
  syscalls per `(pid, syscall)` in-kernel.
- Drains those counts once per time window into a normalized 400-dimensional
  syscall-frequency "fingerprint" for each process.
- Learns what "normal" looks like from a baseline, then flags processes whose
  fingerprint is off-distribution — no labeled attack data required.
- Two interchangeable detectors are provided (`iforest` and `distance`).

## How it works

```
raw_syscalls:sys_enter (kernel)
        |  eBPF program counts per-(pid,syscall) into a BPF hash map
        v
   tracer.py   -- drains the map once per window  -> {pid: {syscall: count}}
        |
   features.py -- normalized 400-d syscall-frequency "fingerprint" per process
        |
   detector.py -- IsolationForest: learn 'normal', flag outliers (no labels needed)
        |
   monitor.py  -- live loop: baseline, then print ANOMALY lines
```

Detectors (pick with `monitor.py --detector`):

- **`iforest`** — IsolationForest over the 400-d syscall-frequency vectors.
- **`distance`** (default) — cosine nearest-neighbour novelty: flag a process whose
  syscall mix has no similar neighbour in the learned baseline, with the threshold
  learned unsupervised from the baseline's own NN-similarity distribution.

## Install

Requires root and bcc (Debian/Kali):

```bash
sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)   # Debian/Kali
pip install -r requirements.txt
```

## Usage

```bash
sudo python3 monitor.py --baseline-windows 30 --window 1.0   # learn normal, then watch
# in another terminal, generate a safe anomaly:
./simulate_anomaly.sh 10                                     # should trigger ANOMALY lines
```

### Tests (no root/kernel needed)

```bash
pip install pytest && pytest -q tests/
```

The pure logic (features, detector) is unit-tested in CI; the eBPF tracer is exercised
manually since it needs a real kernel — a normal split for kernel-adjacent code.

## Rust (aya) probe

The probe is also implemented in Rust with [aya](https://aya-rs.dev) under
[`aya-tracer/`](aya-tracer/) — a no-bcc, portable binary. It attaches the same
`raw_syscalls:sys_enter` tracepoint, counts per-`(pid, syscall)` in a BPF map, and
prints the **same `{pid: {syscall: count}}` JSON** `tracer.py` emits, so it drops
straight into this ML pipeline:

```bash
cd aya-tracer && cargo build --release
sudo ./target/release/aya-tracer | python3 ../monitor_from_stdin.py   # Rust probe -> Python ML
```

Verified end-to-end on `6.18.12+kali-amd64`: the Rust tracer builds clean, attaches,
streams real per-process syscall mixes, and the Python `distance` detector flags an
injected scanner from that stream. The JSON line is the language-agnostic seam (Rust
kernel side, Python ML side). See [`aya-tracer/README.md`](aya-tracer/README.md).

## Results

Unit tests: **7/7 pass**.

### Live comparison (eBPF on the real kernel, `6.18.12+kali-amd64`)

Same live baseline (~630 process-samples, 15×1s windows; tracer ~120k syscall-events/s):

| | IsolationForest | **Distance (cosine-NN)** |
|---|---|---|
| False positives (clean) | **0 / 213** | **1 / 213** (0.5%) |
| Detect a single-process **port-scan** | **0 / 8** ❌ | **8 / 8** ✅ |
| Detect a `sched_yield` flood | 0 / 8 | 0 / 8 |

The distance detector catches the recon/port-scan that IsolationForest completely
misses, at ~0.5% false positives — a recall win from a better-suited model, with no
labels needed. Both miss the `sched_yield` flood, which is correct: on a busy host
`sched_yield` is common, so that process genuinely isn't novel. This is the honest
shape of unsupervised host-IDS — it catches what is *actually* off-distribution, not
everything labeled "bad."

### Offline ML control (clean synthetic baseline)

| Metric | Value |
|---|---|
| Setup | 300 baseline + 200 held-out normal + 50 reverse-shell-like fingerprints (dim=400) |
| IsolationForest detection / FP | **50/50 = 100%** / **3/200 = 1.5%** |

On a *clean* baseline IsolationForest already separates anomalies perfectly; the live
gap above is about **baseline realism**, which the distance detector handles far
better.

## Roadmap

- Add network/`execve` features.
- Try an autoencoder detector.
- Per-process baselines.
- Ship a Grafana panel off the scores.
