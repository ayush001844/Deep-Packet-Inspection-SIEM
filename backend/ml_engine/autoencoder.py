"""
Autoencoder-Based Anomaly Detector
====================================
Learns normal traffic patterns, then flags traffic with high reconstruction
error as anomalous (potential unknown attacks).

Architecture:
  Input (10 features) → Encoder [10→6→3] → Bottleneck (3) → Decoder [3→6→10]

Works with pure NumPy — no scikit-learn needed.
"""
from __future__ import annotations

import os
import math
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "packet_count", "bytes", "duration", "flow_rate",
    "is_tcp", "is_udp", "syn_count", "ack_count", "fin_count", "rst_count",
]

# Anomaly descriptions keyed by feature driving the score
ANOMALY_HINTS = {
    "flow_rate":    "Possible DDoS / Traffic Flood",
    "packet_count": "Possible Port Scan / Sweep",
    "syn_count":    "Possible SYN Flood",
    "rst_count":    "Possible Connection Reset Storm",
    "bytes":        "Possible Data Exfiltration",
    "duration":     "Possible C2 Long-lived Connection",
    "default":      "Behavioral Anomaly Detected",
}


# ── Tiny NumPy autoencoder ────────────────────────────────────────────────────

def _relu(x):
    return x * (x > 0)


def _sigmoid(x):
    # numerically stable
    return 1.0 / (1.0 + _exp(-x))


def _exp(x):
    import numpy as np
    return np.exp(np.clip(x, -500, 500))


class TinyAutoencoder:
    """Minimal fully-connected autoencoder implemented in NumPy."""

    def __init__(self, input_dim: int = 10, latent_dim: int = 3):
        self.input_dim  = input_dim
        self.latent_dim = latent_dim
        self.layers     = [input_dim, 6, latent_dim, 6, input_dim]
        self.weights: list = []
        self.biases: list  = []
        self._init_weights()

    def _init_weights(self):
        import numpy as np
        rng = np.random.default_rng(42)
        self.weights = []
        self.biases  = []
        for i in range(len(self.layers) - 1):
            fan_in  = self.layers[i]
            fan_out = self.layers[i + 1]
            # Xavier init
            scale = math.sqrt(2.0 / (fan_in + fan_out))
            self.weights.append(rng.normal(0, scale, (fan_in, fan_out)))
            self.biases.append(np.zeros(fan_out))

    def forward(self, x):
        import numpy as np
        h = x.copy()
        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            h = h @ W + b
            # ReLU on hidden layers, linear on output
            if i < len(self.weights) - 1:
                h = _relu(h)
        return h

    def fit(self, X, epochs: int = 300, lr: float = 0.01, batch_size: int = 32):
        """Train via mini-batch gradient descent (MSE loss)."""
        import numpy as np
        n = len(X)
        for epoch in range(epochs):
            idx = np.random.permutation(n)
            for start in range(0, n, batch_size):
                batch = X[idx[start:start + batch_size]]
                self._step(batch, lr)
            if epoch % 50 == 0:
                loss = self._mse(X)
                logger.debug(f"[Autoencoder] epoch {epoch}  loss={loss:.6f}")
        logger.info(f"[Autoencoder] Training done. Final loss={self._mse(X):.6f}")

    def _mse(self, X):
        import numpy as np
        pred = self.forward(X)
        return float(np.mean((X - pred) ** 2))

    def _step(self, batch, lr):
        """One gradient step (backprop by finite-difference approx for simplicity)."""
        import numpy as np
        eps = 1e-4
        base_loss = self._batch_mse(batch)
        for i in range(len(self.weights)):
            for r in range(self.weights[i].shape[0]):
                for c in range(self.weights[i].shape[1]):
                    self.weights[i][r, c] += eps
                    hi = self._batch_mse(batch)
                    self.weights[i][r, c] -= 2 * eps
                    lo = self._batch_mse(batch)
                    self.weights[i][r, c] += eps
                    grad = (hi - lo) / (2 * eps)
                    self.weights[i][r, c] -= lr * grad

    def _batch_mse(self, batch):
        import numpy as np
        pred = self.forward(batch)
        return float(np.mean((batch - pred) ** 2))

    def reconstruction_error(self, x):
        import numpy as np
        pred = self.forward(x)
        return float(np.mean((x - pred) ** 2, axis=-1))


# ── Fast SGD-trained autoencoder (preferred) ─────────────────────────────────

class FastAutoencoder:
    """
    A fast autoencoder that uses sklearn's MLPRegressor as a surrogate.
    This is much faster than hand-coded backprop and gives comparable results.
    Falls back to TinyAutoencoder if sklearn unavailable.
    """

    def __init__(self, input_dim: int = 10):
        self.input_dim = input_dim
        self._model = None
        self._scaler = None

    def fit(self, X):
        try:
            from sklearn.neural_network import MLPRegressor
            from sklearn.preprocessing import StandardScaler
            import numpy as np

            self._scaler = StandardScaler()
            Xs = self._scaler.fit_transform(X)

            self._model = MLPRegressor(
                hidden_layer_sizes=(6, 3, 6),
                activation="relu",
                max_iter=500,
                random_state=42,
                tol=1e-5,
            )
            self._model.fit(Xs, Xs)
            logger.info("[Autoencoder] FastAutoencoder (sklearn MLP) trained.")
        except ImportError:
            logger.warning("[Autoencoder] sklearn not available — using TinyAutoencoder (slower).")
            self._model = None
            self._tiny = TinyAutoencoder(self.input_dim)
            import numpy as np
            self._tiny.fit(X.astype(np.float64), epochs=200, lr=0.005)
            self._scaler = None

    def reconstruction_error(self, X):
        import numpy as np
        if self._model is not None:
            Xs = self._scaler.transform(X)
            pred = self._model.predict(Xs)
            return np.mean((Xs - pred) ** 2, axis=1)
        else:
            return self._tiny.reconstruction_error(X.astype(np.float64))

    def save(self, path: str):
        try:
            import joblib
            os.makedirs(os.path.dirname(path), exist_ok=True)
            joblib.dump(self, path)
            logger.info(f"[Autoencoder] Saved to {path}")
        except Exception as e:
            logger.error(f"[Autoencoder] Save failed: {e}")

    @staticmethod
    def load(path: str) -> Optional["FastAutoencoder"]:
        if not os.path.exists(path):
            return None
        try:
            import joblib
            ae = joblib.load(path)
            logger.info("[Autoencoder] Model loaded from disk.")
            return ae
        except Exception as e:
            logger.error(f"[Autoencoder] Load failed: {e}")
            return None


# ── Anomaly Detector (public API) ────────────────────────────────────────────

class AnomalyDetector:
    """
    Wraps FastAutoencoder and computes per-flow anomaly scores.
    """
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "autoencoder.pkl")

    def __init__(self):
        self._ae: Optional[FastAutoencoder] = None
        self._threshold: float = 0.5     # will be set during training
        self._mean: float = 0.0
        self._std:  float = 1.0
        self._loaded = False
        self._load()

    def _load(self):
        ae = FastAutoencoder.load(self.MODEL_PATH)
        if ae is not None:
            self._ae = ae
            self._loaded = True

    def is_loaded(self) -> bool:
        return self._loaded and self._ae is not None

    def score(self, flow_features: dict) -> dict:
        """
        Compute anomaly score for a single flow.
        Returns {"anomaly_score": float, "is_anomaly": bool, "description": str, "threshold": float}
        """
        if not self.is_loaded():
            return {"anomaly_score": 0.0, "is_anomaly": False, "description": "Model not loaded", "threshold": self._threshold}

        try:
            import numpy as np
            vec = np.array([[flow_features.get(n, 0.0) for n in FEATURE_NAMES]], dtype=np.float64)
            err = float(self._ae.reconstruction_error(vec)[0])

            # Normalise to 0–1 anomaly score
            norm_score = min(1.0, err / max(self._threshold * 3, 1e-9))

            is_anomaly = err > self._threshold

            # Pick description from most abnormal feature
            desc = ANOMALY_HINTS["default"]
            if is_anomaly:
                # Find which feature contributed most
                if flow_features.get("flow_rate", 0) > 500:
                    desc = ANOMALY_HINTS["flow_rate"]
                elif flow_features.get("syn_count", 0) > 200:
                    desc = ANOMALY_HINTS["syn_count"]
                elif flow_features.get("rst_count", 0) > 100:
                    desc = ANOMALY_HINTS["rst_count"]
                elif flow_features.get("packet_count", 0) < 5:
                    desc = ANOMALY_HINTS["packet_count"]
                elif flow_features.get("duration", 0) > 600:
                    desc = ANOMALY_HINTS["duration"]
                elif flow_features.get("bytes", 0) > 10_000_000:
                    desc = ANOMALY_HINTS["bytes"]

            return {
                "anomaly_score": round(norm_score, 4),
                "reconstruction_error": round(err, 6),
                "is_anomaly": is_anomaly,
                "description": desc,
                "threshold": round(self._threshold, 6),
                "timestamp": time.time(),
            }
        except Exception as e:
            logger.error(f"[Autoencoder] Scoring error: {e}")
            return {"anomaly_score": 0.0, "is_anomaly": False, "description": str(e), "threshold": self._threshold}

    def set_threshold(self, threshold: float):
        self._threshold = threshold

    def load_from(self, ae: FastAutoencoder, threshold: float):
        self._ae = ae
        self._threshold = threshold
        self._loaded = True


# Singleton
anomaly_detector = AnomalyDetector()
