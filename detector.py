"""Unsupervised anomaly detection over syscall fingerprints.

We use IsolationForest. Intuition: it builds random trees that "isolate" points;
anomalies are easy to isolate (they sit alone in feature space) so they end up with
short average path lengths -> high anomaly score. Crucially it's UNSUPERVISED: you
train it on a clean baseline of normal behavior and need ZERO labeled attacks.

Why IsolationForest and not, say, a neural autoencoder?
    - It's cheap, fast, and works well in high-dim sparse spaces (our 400-d syscall
      vectors are mostly zeros).
    - No GPU, no training loop -- fits the "runs on the box it's monitoring" goal.
    (An autoencoder is a great v2; mention that tradeoff in an interview.)
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self, contamination: float = 0.02, random_state: int = 0):
        # `contamination` = expected fraction of anomalies in the data. It sets the
        # decision threshold. Keep it small for a baseline you believe is clean.
        self._model = IsolationForest(contamination=contamination, random_state=random_state)
        self._fitted = False

    def fit(self, baseline_vectors):
        """Learn 'normal' from a clean baseline (list of fixed-length vectors)."""
        self._model.fit(baseline_vectors)
        self._fitted = True
        return self

    def score(self, vectors):
        """Anomaly score; LOWER = more anomalous (sklearn convention)."""
        self._require_fitted()
        return self._model.decision_function(vectors)

    def predict(self, vectors):
        """+1 = normal, -1 = anomaly."""
        self._require_fitted()
        return self._model.predict(vectors)

    def _require_fitted(self):
        if not self._fitted:
            raise RuntimeError("Call fit() on a clean baseline before scoring.")


class DistanceAnomalyDetector:
    """Nearest-neighbour (cosine) novelty detector over syscall fingerprints.

    Why add this alongside IsolationForest? On a real, heterogeneous host the IForest
    over 400-d sparse vectors is too permissive -- it rarely splits on the one syscall
    dimension that makes a process novel, so genuinely off-distribution fingerprints
    (e.g. a process that is ~100% one rare syscall) still score as normal.

    This detector instead asks a directly meaningful question: *is this process's
    syscall mix similar to ANYTHING we saw in the clean baseline?* It scores each
    process by its maximum cosine similarity to a baseline fingerprint; a process with
    no similar neighbour is flagged. The threshold is learned unsupervised from the
    baseline's own nearest-neighbour similarity distribution (the `contamination`
    quantile), so no labelled attacks are needed -- same contract as AnomalyDetector.

    Note this will (correctly) NOT flag e.g. a localhost port-scan on a networked host:
    socket/connect-heavy mixes ARE similar to normal network apps. It flags the truly
    novel, which is what an unsupervised host-IDS can honestly catch.
    """

    def __init__(self, contamination: float = 0.02):
        self._contamination = contamination
        self._baseline = None
        self._threshold = None
        self._fitted = False

    @staticmethod
    def _l2_normalize(mat):
        mat = np.asarray(mat, dtype=np.float64)
        norms = np.linalg.norm(mat, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return mat / norms

    def _max_sim_to_baseline(self, vectors, exclude_self=False):
        v = self._l2_normalize(vectors)
        sims = v @ self._baseline.T          # cosine sim (both L2-normalized) [N, B]
        if exclude_self:                     # drop each point's own match (self-sim=1)
            np.fill_diagonal(sims, -np.inf)
        return sims.max(axis=1)

    def fit(self, baseline_vectors):
        """Learn 'normal' and a novelty threshold from a clean baseline."""
        self._baseline = self._l2_normalize(baseline_vectors)
        # Each baseline point's similarity to its nearest OTHER baseline point.
        self_sims = self._max_sim_to_baseline(baseline_vectors, exclude_self=True)
        # Flag things less similar than the bottom `contamination` of the baseline itself.
        self._threshold = float(np.quantile(self_sims, self._contamination))
        self._fitted = True
        return self

    def score(self, vectors):
        """Anomaly score; LOWER = more anomalous (max cosine sim to baseline)."""
        self._require_fitted()
        return self._max_sim_to_baseline(vectors)

    def predict(self, vectors):
        """+1 = normal, -1 = anomaly (max baseline similarity below learned threshold)."""
        self._require_fitted()
        sims = self._max_sim_to_baseline(vectors)
        return np.where(sims < self._threshold, -1, 1)

    def _require_fitted(self):
        if not self._fitted:
            raise RuntimeError("Call fit() on a clean baseline before scoring.")
