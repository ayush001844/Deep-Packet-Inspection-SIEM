import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Attack classes from CICIDS2017
CLASSES = [
    "BENIGN", 
    "DDoS", 
    "PortScan", 
    "BruteForce", 
    "Web Attack", 
    "Botnet"
]

def generate_synthetic_data(samples_per_class=5000):
    """
    Generates synthetic training data based on CICIDS2017 feature distributions.
    This provides a realistic baseline model without requiring a 50GB dataset download.
    """
    np.random.seed(42)
    X = []
    y = []
    
    for class_idx, label in enumerate(CLASSES):
        # Base profiles for each class (means for the 20 features)
        if label == "BENIGN":
            # Normal traffic: mixed protocols, average size, low flags
            means = [5.0, 6, 2000, 5000, 15, 1400, 3, 500, 100, 40, 1500, 1, 1, 0, 1, 1, 1, 1, 0.5, 0.5]
            stds  = [10.0, 5, 5000, 10000, 30, 2000, 5, 300, 50,  20, 500,  1, 1, 0, 1, 1, 1, 1, 0.5, 0.5]
            
        elif label == "DDoS":
            # DDoS: high packet rate, small packets, lots of SYNs
            means = [0.1, 6, 1000, 0, 50, 10000, 500, 64, 5, 64, 64, 50, 0, 0, 0, 0, 1, 50, 0.002, 0.0]
            stds  = [0.05, 0, 200, 0, 20, 5000, 200, 10, 2, 0, 10,  20, 0, 0, 0, 0, 1, 20, 0.001, 0.0]
            
        elif label == "PortScan":
            # Port scan: high unique dest ports, SYNs/RSTs
            means = [2.0, 6, 100, 0, 10, 50, 5, 40, 0, 40, 40, 10, 0, 10, 0, 0, 10, 1, 0.2, 0.0]
            stds  = [1.0, 0, 50,  0, 5,  25, 2, 0,  0, 0,  0,  5,  0, 5,  0, 0, 5,  0, 0.1, 0.0]
            
        elif label == "BruteForce":
            # Brute force (SSH/FTP): longer duration, moderate packets, push/ack
            means = [30.0, 6, 5000, 8000, 40, 433, 1.3, 325, 100, 50, 900, 1, 1, 0, 20, 40, 1, 1, 0.7, 0.7]
            stds  = [10.0, 0, 2000, 3000, 15, 200, 0.5, 100, 30, 10, 200, 0, 0, 0, 5, 10, 0, 0, 0.2, 0.2]
            
        elif label == "Web Attack":
            # Web attacks: TCP 80/443, specific payload sizes
            means = [5.0, 6, 800, 3000, 12, 760, 2.4, 316, 150, 60, 1200, 1, 1, 0, 5, 12, 1, 1, 0.4, 0.4]
            stds  = [2.0, 0, 300, 1000, 5,  300, 1.0, 100, 50, 20, 300,  0, 0, 0, 2, 3, 0, 0, 0.1, 0.1]
            
        elif label == "Botnet":
            # Botnet / Beaconing: periodic small packets
            means = [60.0, 6, 200, 200, 4, 6.6, 0.06, 100, 10, 80, 120, 1, 1, 0, 2, 4, 1, 1, 15.0, 15.0]
            stds  = [10.0, 0, 50, 50, 1, 2.0, 0.02, 20, 5, 10, 20, 0, 0, 0, 1, 1, 0, 0, 2.0, 2.0]

        # Generate samples with normal distribution
        class_X = np.random.normal(loc=means, scale=stds, size=(samples_per_class, len(means)))
        
        # Clip values to realistic ranges (e.g., no negative bytes)
        class_X = np.clip(class_X, 0, None)
        
        # Round flag counts and categorical features
        class_X[:, 1] = np.round(class_X[:, 1]) # Protocol
        class_X[:, 11:18] = np.round(class_X[:, 11:18]) # Flags & Ports
        
        X.append(class_X)
        y.extend([class_idx] * samples_per_class)
        
    X = np.vstack(X)
    y = np.array(y)
    return X, y

def train_and_save_model():
    """Trains the ML ensemble and saves it to disk."""
    print("[ML Train] Generating synthetic CICIDS2017 corpus...")
    X, y = generate_synthetic_data(samples_per_class=10000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("[ML Train] Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, n_jobs=-1)
    
    print("[ML Train] Training XGBoost...")
    xgb = XGBClassifier(n_estimators=50, max_depth=6, learning_rate=0.1, random_state=42, n_jobs=-1)
    
    print("[ML Train] Building Voting Ensemble...")
    # Soft voting uses predicted probabilities for better confidence calibration
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('xgb', xgb)],
        voting='soft'
    )
    
    ensemble.fit(X_train, y_train)
    
    # Evaluate
    y_pred = ensemble.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"[ML Train] Validation Accuracy: {acc:.4f}")
    
    # Save model metadata alongside the classifier
    model_data = {
        'model': ensemble,
        'classes': CLASSES,
        'accuracy': acc,
        'timestamp': np.datetime64('now').astype(str)
    }
    
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    joblib.dump(model_data, model_path)
    print(f"[ML Train] Model saved to {model_path}")

if __name__ == "__main__":
    train_and_save_model()
