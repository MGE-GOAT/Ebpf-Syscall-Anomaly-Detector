"""Feature extraction: turn per-process syscall counts into fixed-length vectors.

Pure Python -- NO kernel/bcc dependency on purpose, so this logic is unit-testable
and runs in CI without root. (Keeping the kernel-touching code separate from the
plain logic is itself a good systems-engineering habit -- it's what lets you test.)

The core idea:
    A process is described by *how often it makes each syscall* in a time window.
    A web server, a text editor, and a reverse shell each make a very different
    MIX of syscalls. That mix -- a syscall-frequency "fingerprint" -- is what the
    anomaly detector keys on. We never need to know what an attack looks like; we
    only need to know what NORMAL looks like, and flag anything far from it.
"""
from __future__ import annotations

# Linux x86-64 has ~350 syscalls. We pad every fingerprint to a fixed length so
# each process becomes a vector of identical size -- which is what scikit-learn
# (and any ML model) requires as input.
MAX_SYSCALL = 400


def histogram_to_vector(counts: dict[int, int], max_syscall: int = MAX_SYSCALL) -> list[float]:
    """Convert {syscall_id: count} -> a normalized fixed-length frequency vector.

    We normalize by the total count so the fingerprint is about the *mix* of
    syscalls, not the raw volume. (A busy process and an idle one doing the same
    KIND of work should look similar; volume is handled separately if you want it.)
    """
    vec = [0.0] * max_syscall
    total = sum(counts.values())
    if total == 0:
        return vec
    for syscall_id, c in counts.items():
        if 0 <= syscall_id < max_syscall:
            vec[syscall_id] = c / total
    return vec
