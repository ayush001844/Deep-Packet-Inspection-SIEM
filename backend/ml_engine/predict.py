"""
ML Engine — Multi-Class Predictor
===================================
Loads the trained RandomForest + StandardScaler and exposes a simple
`predict(session_data) -> dict | None` interface.

Attack classes (must stay in sync with train_model.py):
  0 = Normal
  1 = SSH Brute Force
  2 = DDoS
  3 = Port Scan
  4 = C2 Beaconing
"""
import os
import time
import logging
from typing import Optional

from backend.ml_engine.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

# ── Class label metadata ─────────────────────────────────────────────────────
ATTACK_CLASSES = {
    0: "Normal",
    1: "SSH Brute Force",
    2: "DDoS",
    3: "Port Scan",
    4: "C2 Beaconing",
}

SEVERITY_MAP = {
    "Normal":          "info",
    "SSH Brute Force": "high",
    "DDoS":            "critical",
    "Port Scan":       "medium",
    "C2 Beaconing":    "high",
}

MITRE_MAP = {
    "SSH Brute Force": {"technique": "T1110", "tactic": "Credential Access"},
    "DDoS":            {"technique": "T1498", "tactic": "Impact"},
    "Port Scan":       {"technique": "T1046", "tactic": "Discovery"},
    "C2 Beaconing":    {"technique": "T1071", "tactic": "Command and Control"},
    "Normal":          {"technique": "",      "tactic": ""},
}

CONFIDENCE_THRESHOLD = 0.72   # Raise this to reduce false positives


# ── Heuristic fallback (no scikit-learn) ────────────────────────────────────
class HeuristicPredictor:
    """
    Pure-Python rule-based model that mimics the ML model's outputs when
    scikit-learn / joblib are unavailable (e.g. Python 3.14 without wheels).
    """

    def predict_proba(self, X):
        feats = X[0]
        # Indices: 0=pkt_cnt 1=bytes 2=dur 3=rate 4=is_tcp 5=is_udp 6=syn 7=ack 8=fin 9=rst
        pkt_cnt = feats[0]
        duration = feats[2]
        rate    = feats[3]
        is_tcp  = feats[4]
        is_udp  = feats[5]
        syn_cnt = feats[6]
        rst_cnt = feats[9]

        # Default to normal
        proba = [0.97, 0.01, 0.01, 0.01, 0.01]  # 5 classes

        # DDoS: massive UDP, very high rate
        if is_udp and rate > 2000:
            proba = [0.02, 0.01, 0.95, 0.01, 0.01]
        # SSH Brute Force: TCP, high rate, many SYN+RST
        elif is_tcp and rate > 150 and syn_cnt > 100 and rst_cnt > 50:
            proba = [0.02, 0.94, 0.01, 0.01, 0.02]
        # Port Scan: TCP, very few packets per flow, very high rate
        elif is_tcp and pkt_cnt <= 4 and rate > 20:
            proba = [0.02, 0.01, 0.01, 0.94, 0.02]
        # C2 Beaconing: TCP, very long duration, very low rate, few packets
        elif is_tcp and duration > 200 and rate < 0.5 and pkt_cnt < 200:
            proba = [0.02, 0.01, 0.01, 0.02, 0.94]

        return [proba]

    def predict(self, X):
        proba = self.predict_proba(X)[0]
        return [proba.index(max(proba))]

    def classes_(self):
        return [0, 1, 2, 3, 4]


# ── Main Predictor ────────────────────────────────────────────────────────────
class PredictorWrapper:

    def __init__(self):
        self.model      = None
        self.scaler     = None
        self.feature_names = FeatureExtractor.get_feature_names()
        self._load()

    def _load(self):
        model_dir  = os.path.join(os.path.dirname(__file__), "models")
        model_path = os.path.join(model_dir, "intrusion_model.pkl")
        scaler_path = os.path.join(model_dir, "scaler.pkl")

        try:
            import joblib  # noqa: F401 — just testing availability

            if os.path.exists(model_path):
                import joblib as jl
                self.model = jl.load(model_path)
                self.scaler = jl.load(scaler_path) if os.path.exists(scaler_path) else None
                classes = list(getattr(self.model, "classes_", []))
                logger.info(f"[ML Engine] Loaded model — classes: {[ATTACK_CLASSES.get(c, c) for c in classes]}")
            else:
                logger.warning("[ML Engine] Model file missing — using heuristic fallback.")
                self.model  = HeuristicPredictor()
                self.scaler = None
        except ImportError:
            logger.warning("[ML Engine] joblib not available — using heuristic fallback.")
            self.model  = HeuristicPredictor()
            self.scaler = None

    def predict(self, session_data: dict) -> Optional[dict]:
        """
        Run inference on raw session dict (from SessionTracker.to_dict()).

        Returns a detection dict if an attack is found, else None.
        """
        if self.model is None:
            return None

        feats = FeatureExtractor.extract_features(session_data)
        vec   = [feats.get(n, 0.0) for n in self.feature_names]

        try:
            X = [vec]
            if self.scaler is not None:
                import numpy as np
                X = self.scaler.transform(np.array(X))

            proba  = self.model.predict_proba(X)[0]
            pred   = int(proba.index(max(proba)) if isinstance(proba, list) else proba.argmax())
            conf   = float(max(proba))
            label  = ATTACK_CLASSES.get(pred, "Unknown")

            if label == "Normal" or conf < CONFIDENCE_THRESHOLD:
                return None

            severity = SEVERITY_MAP.get(label, "medium")
            mitre    = MITRE_MAP.get(label, {})

            return {
                "attack":     label,
                "confidence": round(conf, 4),
                "severity":   severity.upper(),
                "class_id":   pred,
                "features":   feats,
                "mitre_technique": mitre.get("technique", ""),
                "mitre_tactic":    mitre.get("tactic", ""),
                "timestamp":  time.time(),
                # Per-class probabilities for the dashboard chart
                "class_probabilities": {
                    ATTACK_CLASSES[i]: round(float(proba[i]), 4)
                    for i in range(len(proba))
                },
            }

        except Exception as e:
            logger.error(f"[ML Engine] Prediction error: {e}")
            return None


# Singleton
ml_predictor = PredictorWrapper()
