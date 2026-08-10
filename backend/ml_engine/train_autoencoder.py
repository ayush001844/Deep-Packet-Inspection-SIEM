"""
Autoencoder Training Script
=============================
Generates synthetic normal traffic baseline and trains the autoencoder.
Run:  python backend/ml_engine/train_autoencoder.py
"""
import os
import logging
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_normal_traffic(n: int = 2000):
    """Generate synthetic normal flow feature vectors."""
    data = []
    for _ in range(n):
        is_tcp = random.random() > 0.35
        dur = random.uniform(0.5, 120.0)
        pkts = random.randint(10, 300)
        byt = pkts * random.randint(100, 1500)
        rate = pkts / max(dur, 0.01)
        syn = random.randint(1, 10) if is_tcp else 0
        ack = random.randint(5, 80) if is_tcp else 0
        fin = random.randint(1, 8) if is_tcp else 0
        rst = random.randint(0, 3)
        data.append([pkts, byt, dur, rate, float(is_tcp), float(not is_tcp), syn, ack, fin, rst])
    return data


def train():
    try:
        import numpy as np
    except ImportError:
        logger.error("[Autoencoder] NumPy not available — cannot train.")
        return False

    from backend.ml_engine.autoencoder import FastAutoencoder, AnomalyDetector

    logger.info("[Autoencoder] Generating normal traffic baseline…")
    raw = generate_normal_traffic(2000)
    X = np.array(raw, dtype=np.float64)

    logger.info("[Autoencoder] Training autoencoder on normal traffic…")
    ae = FastAutoencoder(input_dim=10)
    ae.fit(X)

    # Compute per-sample errors on training set to set threshold
    errors = ae.reconstruction_error(X)
    mean_err = float(np.mean(errors))
    std_err  = float(np.std(errors))
    # Threshold = mean + 3×std  (catches ~99.7% of normal as non-anomalous)
    threshold = mean_err + 3.0 * std_err

    logger.info(f"[Autoencoder] Error stats: mean={mean_err:.6f}  std={std_err:.6f}  threshold={threshold:.6f}")

    # Inject threshold into the model object before saving
    ae._threshold = threshold

    model_path = os.path.join(os.path.dirname(__file__), "models", "autoencoder.pkl")
    ae.save(model_path)
    logger.info(f"[Autoencoder] Model saved → {model_path}")
    return True


if __name__ == "__main__":
    train()
