import os
import joblib
import numpy as np
from .feature_extractor import extract_features

class MLPredictor:
    def __init__(self):
        self.model = None
        self.classes = []
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
        if not os.path.exists(model_path):
            print("[ML Predictor] model.pkl not found. Auto-training...")
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
            self.is_loaded = True
            print(f"[ML Predictor] Loaded ensemble model (Accuracy: {self.accuracy:.2f})")
        except Exception as e:
            print(f"[ML Predictor] Failed to load model: {e}")

    def predict_flow(self, flow) -> dict:
        """
        Takes a SessionFlow object and returns a prediction dictionary.
        """
        if not self.is_loaded or self.model is None:
            return {"attack_type": "BENIGN", "confidence": 0.0, "error": "Model not loaded"}

        try:
            features = extract_features(flow)
            features = features.reshape(1, -1) # Reshape for single prediction
            
            # Predict probabilities
            probs = self.model.predict_proba(features)[0]
            
            pred_idx = np.argmax(probs)
            confidence = float(probs[pred_idx])
            attack_type = self.classes[pred_idx]
            
            # Convert probabilities to dict
            prob_dict = {self.classes[i]: float(probs[i]) for i in range(len(self.classes))}
            
            return {
                "attack_type": attack_type,
                "confidence": confidence,
                "probabilities": prob_dict,
                "is_attack": attack_type != "BENIGN" and confidence > 0.6
            }
        except Exception as e:
            print(f"[ML Predictor] Prediction error: {e}")
            return {"attack_type": "ERROR", "confidence": 0.0, "error": str(e)}

# Singleton instance
predictor = MLPredictor()
