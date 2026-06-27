"""Unit tests for feature extraction (pure logic, no kernel needed -> runs in CI)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from features import histogram_to_vector, MAX_SYSCALL


def test_empty_histogram_is_zero_vector():
    v = histogram_to_vector({})
    assert len(v) == MAX_SYSCALL
    assert sum(v) == 0.0


def test_normalization_sums_to_one():
    v = histogram_to_vector({0: 3, 1: 1})  # 4 syscalls total
    assert abs(sum(v) - 1.0) < 1e-9
    assert abs(v[0] - 0.75) < 1e-9
    assert abs(v[1] - 0.25) < 1e-9


def test_out_of_range_syscall_is_ignored():
    v = histogram_to_vector({999_999: 5})
    assert sum(v) == 0.0
