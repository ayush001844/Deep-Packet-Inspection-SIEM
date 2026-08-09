import os
import joblib
import numpy as np
from .feature_extractor import extract_features

# Base severity mapping for standard classes
SEVERITY_MAP = {
    "BENIGN": "INFO",
    "DDoS": "HIGH",
    "PortScan": "LOW",
    "BruteForce": "HIGH",
    "Web Attack": "CRITICAL",
    "Botnet": "CRITICAL"
}

class MLPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.classes = []
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        ml_dir = os.path.dirname(__file__)
        model_path = os.path.join(ml_dir, 'models', 'intrusion_model.pkl')
        scaler_path = os.path.join(ml_dir, 'scaler.pkl')
        
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            print("[ML Predictor] Models not found. Auto-training...")
            from .train import train_and_save_model
            try:
                train_and_save_model()
            except Exception as e:
                print(f"[ML Predictor] Auto-training failed: {e}")
                return
                
        try:
            data = joblib.load(model_path)
            self.model = data.get('model')
            self.classes = data.get('classes', [])
            self.accuracy = data.get('accuracy', 0.0)
            
            self.scaler = joblib.load(scaler_path)
            
            self.is_loaded = True
            print(f"[ML Predictor] Loaded ensemble model (Accuracy: {self.accuracy:.2f})")
        except Exception as e:
            print(f"[ML Predictor] Failed to load model: {e}")

    def predict_flow(self, flow) -> dict:
        """
        Takes a SessionFlow object and returns a prediction dictionary.
        Output matches requested format:
        {
            "attack": "DDoS",
            "confidence": 0.96,
            "severity": "HIGH",
            "is_attack": True/False
        }
        """
        if not self.is_loaded or self.model is None or self.scaler is None:
            return {"attack": "BENIGN", "confidence": 0.0, "severity": "INFO", "is_attack": False}

        try:
            # 1. Extract 8 features
            features = extract_features(flow)
            features = features.reshape(1, -1) # Reshape for single prediction
            
            # 2. Scale features
            features_scaled = self.scaler.transform(features)
            
            # 3. Predict probabilities
            probs = self.model.predict_proba(features_scaled)[0]
            
            pred_idx = np.argmax(probs)
            confidence = float(probs[pred_idx])
            attack = self.classes[pred_idx]
            severity = SEVERITY_MAP.get(attack, "MEDIUM")
            
            return {
                "attack": attack,
                "confidence": round(confidence, 3),
                "severity": severity,
                "is_attack": attack != "BENIGN" and confidence > 0.6
            }
        except Exception as e:
            print(f"[ML Predictor] Prediction error: {e}")
            return {"attack": "ERROR", "confidence": 0.0, "severity": "INFO", "is_attack": False}

# Singleton instance
predictor = MLPredictor()
