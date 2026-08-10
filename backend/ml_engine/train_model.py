"""
ML Engine — Multi-Class Intrusion Detection Model Trainer
==========================================================
Trains a Random Forest on 5 traffic classes:
  0 = Normal
  1 = SSH Brute Force
  2 = DDoS (UDP/ICMP flood)
  3 = Port Scan
  4 = C2 Beaconing

Features (10):
  packet_count, bytes, duration, flow_rate,
  is_tcp, is_udp, syn_count, ack_count, fin_count, rst_count
"""
import os
import random
import logging

logger = logging.getLogger(__name__)

# --- Class Labels (keep in sync with predict.py) ---
ATTACK_CLASSES = {
    0: "Normal",
    1: "SSH Brute Force",
    2: "DDoS",
    3: "Port Scan",
    4: "C2 Beaconing",
}


def _r(lo, hi):
    return random.uniform(lo, hi)


def _ri(lo, hi):
    return random.randint(lo, hi)


def generate_training_data():
    X, y = [], []

    # ── Class 0: Normal traffic ──────────────────────────────────────────
    # Mix of TCP and UDP, moderate rates, varied durations
    for _ in range(600):
        is_tcp = random.random() > 0.4
        dur = _r(1.0, 120.0)
        pkts = _ri(10, 200)
        byt = pkts * _ri(200, 1500)
        rate = pkts / dur
        syn = _ri(1, 5) if is_tcp else 0
        ack = _ri(5, 50) if is_tcp else 0
        fin = _ri(1, 5) if is_tcp else 0
        rst = 0
        X.append([pkts, byt, dur, rate, float(is_tcp), float(not is_tcp), syn, ack, fin, rst])
        y.append(0)

    # ── Class 1: SSH Brute Force ─────────────────────────────────────────
    # TCP port 22, very high SYN/RST rate, short flows, many small packets
    for _ in range(250):
        dur = _r(0.5, 8.0)
        pkts = _ri(1000, 8000)
        byt = pkts * _ri(40, 80)       # Small SSH auth packets
        rate = pkts / dur               # Extremely high flow rate
        syn = _ri(400, 2000)
        ack = _ri(200, 1000)
        fin = _ri(0, 5)
        rst = _ri(100, 800)
        X.append([pkts, byt, dur, rate, 1.0, 0.0, syn, ack, fin, rst])
        y.append(1)

    # ── Class 2: DDoS ────────────────────────────────────────────────────
    # Massive UDP flood — astronomical packet counts, very short duration
    for _ in range(250):
        dur = _r(0.1, 5.0)
        pkts = _ri(10000, 100000)
        byt = pkts * _ri(60, 150)       # Typically small UDP payloads
        rate = pkts / dur               # Colossal rate
        X.append([pkts, byt, dur, rate, 0.0, 1.0, 0, 0, 0, 0])
        y.append(2)

    # ── Class 3: Port Scan ────────────────────────────────────────────────
    # Many short TCP flows, one SYN each (SYN scan), high rst, tiny bytes
    for _ in range(250):
        dur = _r(0.01, 2.0)
        pkts = _ri(1, 4)                # Exactly 1-4 packets per flow
        byt = pkts * _ri(40, 80)
        rate = pkts / max(dur, 0.01)
        syn = 1
        ack = 0
        fin = 0
        rst = random.choice([0, 1])     # Some return RST
        X.append([pkts, byt, dur, rate, 1.0, 0.0, syn, ack, fin, rst])
        y.append(3)

    # ── Class 4: C2 Beaconing ─────────────────────────────────────────────
    # Regular heartbeat: small HTTPS/TCP packets every N seconds
    # Very consistent: low variance in bytes/pkt, long duration, low pps
    for _ in range(250):
        dur = _r(300.0, 3600.0)         # Long-lived connections
        pkts = _ri(20, 200)             # Few packets over long time
        byt = pkts * _ri(50, 300)       # Tiny consistent payloads
        rate = pkts / dur               # Very low rate — the fingerprint
        syn = _ri(1, 3)
        ack = _ri(10, 80)
        fin = _ri(1, 3)
        rst = 0
        X.append([pkts, byt, dur, rate, 1.0, 0.0, syn, ack, fin, rst])
        y.append(4)

    return X, y


def train_model():
    """Train a 5-class RandomForest and save to models/intrusion_model.pkl"""
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
        import joblib
        import numpy as np
    except ImportError:
        logger.error("[ML Engine] scikit-learn or joblib not installed. Cannot train.")
        return False

    logger.info("[ML Engine] Generating training data for 5 attack classes…")
    X_raw, y_raw = generate_training_data()

    X = np.array(X_raw, dtype=np.float64)
    y = np.array(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    logger.info("[ML Engine] Training RandomForestClassifier (5 classes)…")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train_s, y_train)

    # Quick evaluation
    y_pred = clf.predict(X_test_s)
    report = classification_report(y_test, y_pred,
                                   target_names=list(ATTACK_CLASSES.values()),
                                   zero_division=0)
    logger.info(f"[ML Engine] Classification report:\n{report}")

    # ── Save model + scaler + metadata ───────────────────────────────────
    model_dir = os.path.join(os.path.dirname(__file__), "models")
    os.makedirs(model_dir, exist_ok=True)

    joblib.dump(clf, os.path.join(model_dir, "intrusion_model.pkl"))
    joblib.dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    logger.info(f"[ML Engine] Model + scaler saved to {model_dir}/")
    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_model()
