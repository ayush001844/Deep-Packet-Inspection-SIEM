import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import StandardScaler

# Attack classes
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
    Generates synthetic training data for 8 features:
    0: duration (s)
    1: packet_count
    2: byte_count
    3: src_port
    4: dst_port
    5: protocol (TCP=6, UDP=17, ICMP=1)
    6: flow_rate (bytes/s)
    7: tcp_flags (count)
    """
    np.random.seed(42)
    X = []
    y = []
    
    for class_idx, label in enumerate(CLASSES):
        # Base profiles for each class (means for the 8 features)
        if label == "BENIGN":
            # duration, packet_count, byte_count, src_port, dst_port, protocol, flow_rate, tcp_flags
            means = [5.0, 15, 2000, 50000, 443, 6, 400.0, 3]
            stds  = [2.0, 5, 500, 10000, 0, 0, 100.0, 1]
            
        elif label == "DDoS":
            # DDoS: small duration, high packets, large volume, random ports, TCP/UDP
            means = [0.1, 500, 30000, 40000, 80, 6, 300000.0, 5]
            stds  = [0.05, 100, 5000, 20000, 0, 0, 50000.0, 1]
            
        elif label == "PortScan":
            # Port scan: short duration, few packets, sequential/random dest ports
            means = [0.5, 3, 120, 50000, 22, 6, 240.0, 1]
            stds  = [0.2, 1, 20, 10000, 10000, 0, 50.0, 0]
            
        elif label == "BruteForce":
            # Brute force (SSH/FTP): longer duration, moderate packets
            means = [30.0, 40, 8000, 50000, 22, 6, 266.0, 4]
            stds  = [5.0, 10, 1000, 10000, 0, 0, 50.0, 1]
            
        elif label == "Web Attack":
            # Web attacks: TCP 80/443, specific payloads
            means = [5.0, 20, 5000, 50000, 80, 6, 1000.0, 3]
            stds  = [1.0, 5, 500, 10000, 0, 0, 100.0, 1]
            
        elif label == "Botnet":
            # Botnet / Beaconing: periodic small packets
            means = [60.0, 4, 200, 50000, 8080, 6, 3.33, 2]
            stds  = [10.0, 1, 20, 10000, 0, 0, 1.0, 0]

        # Generate samples with normal distribution
        class_X = np.random.normal(loc=means, scale=stds, size=(samples_per_class, len(means)))
        
        # Clip values to realistic ranges
        class_X = np.clip(class_X, 0, None)
        
        # Round integer features (packet_count, src_port, dst_port, protocol, tcp_flags)
        class_X[:, 1] = np.round(class_X[:, 1]) # packet_count
        class_X[:, 3] = np.round(class_X[:, 3]) # src_port
        class_X[:, 4] = np.round(class_X[:, 4]) # dst_port
        class_X[:, 5] = np.round(class_X[:, 5]) # protocol
        class_X[:, 7] = np.round(class_X[:, 7]) # tcp_flags
        
        X.append(class_X)
        y.extend([class_idx] * samples_per_class)
        
    X = np.vstack(X)
    y = np.array(y)
    return X, y

def train_and_save_model():
    """Trains the ML ensemble and saves it and the scaler to disk."""
    print("[ML Train] Generating synthetic dataset with 8 features...")
    X, y = generate_synthetic_data(samples_per_class=10000)
    
    print("[ML Train] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
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
    
    ml_dir = os.path.dirname(__file__)
    models_dir = os.path.join(ml_dir, 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, 'intrusion_model.pkl')
    scaler_path = os.path.join(ml_dir, 'scaler.pkl')
    
    joblib.dump(model_data, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"[ML Train] Model saved to {model_path}")
    print(f"[ML Train] Scaler saved to {scaler_path}")

if __name__ == "__main__":
    train_and_save_model()
