"""eBPF syscall tracer (requires root + bcc).

This is the kernel-touching part. It attaches a tiny eBPF program to the
`raw_syscalls:sys_enter` tracepoint -- a SINGLE hook that fires on EVERY syscall
from EVERY process. In-kernel we just bump a per-(pid, syscall) counter in a BPF
hash map; userspace drains it once per window. This is the same core technique
production tools (Falco, Tracee) use.

Install bcc (NOT via pip) first:
    Debian/Kali/Ubuntu:  sudo apt install bpfcc-tools python3-bpfcc linux-headers-$(uname -r)

Study targets (be ready to explain these in an interview):
    - What a tracepoint is, and why raw_syscalls:sys_enter is one hook for all syscalls.
    - BPF maps (here BPF_HASH) = the kernel<->userspace shared data structure.
    - Why the in-kernel program must be tiny and bounded (the BPF verifier rejects
      unbounded loops / unsafe memory access before load).
    - bpf_get_current_pid_tgid(): upper 32 bits = PID (tgid), lower = thread id.
"""
from __future__ import annotations

import time
from collections import defaultdict

from bcc import BPF  # provided by the python3-bpfcc system package

# The eBPF program, written in restricted C. bcc compiles this against your running
# kernel at load time (that's why bcc is so portable for learning vs. raw libbpf).
BPF_PROGRAM = r"""
struct key_t { u32 pid; u32 syscall; };
BPF_HASH(counts, struct key_t, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct key_t key = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;  // PID (thread-group id)
    key.syscall = args->id;                      // syscall number
    counts.increment(key);                       // atomic ++ in the kernel map
    return 0;
}
"""


class SyscallTracer:
    def __init__(self):
        # Loading the program triggers the BPF verifier + JIT in the kernel.
        self._bpf = BPF(text=BPF_PROGRAM)

    def collect(self, window_seconds: float) -> dict[int, dict[int, int]]:
        """Sample for `window_seconds`, then drain+clear the map.

        Returns {pid: {syscall_id: count}} for that window.
        """
        time.sleep(window_seconds)
        table = self._bpf["counts"]
        per_pid: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        for k, v in table.items():
            per_pid[k.pid][k.syscall] += v.value
        table.clear()  # reset counters so the next window is independent
        return {pid: dict(h) for pid, h in per_pid.items()}
