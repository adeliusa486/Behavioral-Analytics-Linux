"""
detector.py
Uses Isolation Forest (unsupervised ML) to detect anomalous behavior
in the feature set extracted from auth logs.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

def train_detector(feature_df, contamination=0.05, random_state=42):
    """
    Trains an Isolation Forest model on the provided feature DataFrame.
    Saves the trained model to disk for later use.
    
    Parameters:
        feature_df (pd.DataFrame): DataFrame from features.py
        contamination (float): Expected proportion of outliers (0.05 = 5%)
        random_state (int): Seed for reproducibility
    
    Returns:
        model: Trained IsolationForest model
        predictions: Array of predictions (1=normal, -1=anomaly)
        anomaly_scores: Array of anomaly scores (higher = more anomalous)
    """
    # Select numerical features for training
    feature_columns = [
        'failed_login_count_5min',
        'hour_of_day',
        'is_weekend',
        'event_type_code',
        'username_length',
        'is_root'
    ]
    
    # Ensure all required columns exist
    available_cols = [col for col in feature_columns if col in feature_df.columns]
    if len(available_cols) < 2:
        print("[!] Not enough feature columns for training. Exiting.")
        return None, None, None
    
    X = feature_df[available_cols].copy()
    
    # Handle any missing values (shouldn't be any, but just in case)
    X.fillna(0, inplace=True)
    
    # Standardize features: Isolation Forest is distance-based, scaling helps.
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Initialize and train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1  # Use all CPU cores
    )
    
    print("[+] Training Isolation Forest model...")
    model.fit(X_scaled)
    
    # Get predictions: 1 for normal, -1 for anomaly
    predictions = model.predict(X_scaled)
    
    # Get anomaly scores (negative values, lower = more anomalous)
    raw_scores = model.decision_function(X_scaled)
    # Normalize to 0-1 where 1 is most anomalous
    if raw_scores.max() != raw_scores.min():
        anomaly_scores = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min())
    else:
        anomaly_scores = np.zeros_like(raw_scores)
    
    # Save model and scaler for later use
    model_dir = 'models'
    os.makedirs(model_dir, exist_ok=True)
    with open(os.path.join(model_dir, 'isolation_forest.pkl'), 'wb') as f:
        pickle.dump(model, f)
    with open(os.path.join(model_dir, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    print(f"[+] Model saved to {model_dir}/")
    
    return model, predictions, anomaly_scores


def detect_anomalies(feature_df, model_path=None, scaler_path=None):
    """
    Applies a trained Isolation Forest model to detect anomalies.
    If model_path is None, trains a new model.
    
    Returns:
        feature_df with added columns: 'anomaly', 'is_anomaly', 'risk_score'
    """
    if feature_df.empty:
        print("[!] Empty feature DataFrame. Cannot detect anomalies.")
        return feature_df
    
    # Copy to avoid modifying original
    result_df = feature_df.copy()
    
    # If model provided, load it; otherwise train new
    if model_path and os.path.exists(model_path) and scaler_path and os.path.exists(scaler_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        print("[+] Loaded existing model.")
        
        # Prepare features
        feature_columns = [
            'failed_login_count_5min',
            'hour_of_day',
            'is_weekend',
            'event_type_code',
            'username_length',
            'is_root'
        ]
        available_cols = [col for col in feature_columns if col in result_df.columns]
        X = result_df[available_cols].fillna(0)
        X_scaled = scaler.transform(X)
        
        # Predict
        preds = model.predict(X_scaled)
        raw_scores = model.decision_function(X_scaled)
        # Normalize scores to 0-1
        if raw_scores.max() != raw_scores.min():
            scores = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min())
        else:
            scores = np.zeros_like(raw_scores)
        
        result_df['anomaly'] = preds
        result_df['risk_score'] = scores
        result_df['is_anomaly'] = (result_df['anomaly'] == -1)
        
        return result_df
    else:
        print("[!] No pre-trained model found. Training new model...")
        model, preds, scores = train_detector(result_df)
        if model is None:
            return result_df
        # After training, we have predictions and scores for the same data
        result_df['anomaly'] = preds
        result_df['risk_score'] = scores
        result_df['is_anomaly'] = (result_df['anomaly'] == -1)
        return result_df


# ---- Test the detector ----
if __name__ == "__main__":
    from parser import parse_auth_log
    from features import extract_features
    
    # Load and parse sample log
    df = parse_auth_log("./logs/auth.log.sample")
    feat_df = extract_features(df)
    
    # Detect anomalies
    result_df = detect_anomalies(feat_df)
    
    # Show only anomalies
    anomalies = result_df[result_df['is_anomaly'] == True]
    print(f"\n[!] Found {len(anomalies)} anomalous events:")
    print(anomalies[['timestamp', 'ip_address', 'username', 'event_type', 'failed_login_count_5min', 'risk_score']].head(10))
