"""Unit test for the detector (synthetic data -> runs in CI, no kernel needed)."""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detector import AnomalyDetector, DistanceAnomalyDetector


def test_flags_obvious_outlier():
    rng = np.random.default_rng(0)
    # 200 "normal" points clustered tightly around the origin...
    normal = rng.normal(0.0, 0.01, size=(200, 10)).tolist()
    det = AnomalyDetector(contamination=0.05).fit(normal)
    # ...and one point far away -> must be flagged as anomalous (-1).
    outlier = [[5.0] * 10]
    assert det.predict(outlier)[0] == -1


def test_scoring_before_fit_raises():
    det = AnomalyDetector()
    try:
        det.predict([[0.0] * 10])
    except RuntimeError:
        return
    raise AssertionError("predict() before fit() should raise")


def test_distance_detector_flags_novel_fingerprint():
    rng = np.random.default_rng(0)
    # Baseline: processes whose syscall mass sits on the first few syscalls.
    base = np.zeros((200, 20))
    base[:, :4] = rng.random((200, 4)) + 0.5
    det = DistanceAnomalyDetector(contamination=0.05).fit(base)
    # A novel process: all of its syscall mass on a syscall never seen in baseline.
    novel = np.zeros((1, 20)); novel[0, 17] = 1.0
    assert det.predict(novel)[0] == -1
    # A process resembling the baseline must NOT be flagged.
    similar = np.zeros((1, 20)); similar[0, :4] = 0.7
    assert det.predict(similar)[0] == 1


def test_distance_detector_before_fit_raises():
    try:
        DistanceAnomalyDetector().predict([[0.0] * 10])
    except RuntimeError:
        return
    raise AssertionError("predict() before fit() should raise")
