"""
features.py
Extracts behavioral features from parsed log data for anomaly detection.
Key features: failed login counts per IP over time windows, hour of day, etc.
"""

import pandas as pd
import numpy as np
from datetime import timedelta

def extract_features(df):
    """
    Takes a DataFrame from parser.py and computes features for each event.
    Returns a new DataFrame with numerical features.
    Features:
        - failed_login_count_5min: Number of failed attempts from same IP in last 5 minutes
        - hour_of_day: Hour of the event (0-23)
        - is_weekend: 1 if Saturday/Sunday else 0
        - event_type_encoded: Numeric code for event type
        - username_length: Length of username (anomalous usernames might be weird)
    """
    if df.empty:
        print("[!] Cannot extract features from empty DataFrame.")
        return df

    # Make a copy to avoid modifying original
    feature_df = df.copy()

    # ---- Feature 1: Failed Login Count per IP in Last 5 Minutes ----
    # This is the most important security feature.
    # We'll use a rolling window on each IP group.

    # First, ensure timestamp is datetime and set as index for rolling operation
    feature_df.set_index('timestamp', inplace=True)
    feature_df.sort_index(inplace=True)

    # Create a boolean column indicating failed attempts
    feature_df['is_failed'] = feature_df['event_type'].str.contains('Failed|Invalid', case=False).astype(int)

    # Group by IP address and apply rolling count
    # Explanation of rolling window:
    #   - '5T' means 5 minutes.
    #   - For each timestamp, look back 5 minutes and sum the 'is_failed' values for that IP.
    #   - The window is "trailing" (looks backward in time).
    failed_counts = []
    for ip, group in feature_df.groupby('ip_address'):
        # Rolling sum over a 5-minute window
        rolled = group['is_failed'].rolling(window='5min', closed='both').sum()
        failed_counts.append(rolled)

    # Concatenate results (they are aligned with the index)
    feature_df['failed_login_count_5min'] = pd.concat(failed_counts).sort_index()

    # ---- Feature 2: Hour of Day (time-based anomaly) ----
    feature_df['hour_of_day'] = feature_df.index.hour

    # ---- Feature 3: Is Weekend? (0 or 1) ----
    feature_df['is_weekend'] = feature_df.index.dayofweek.isin([5, 6]).astype(int)

    # ---- Feature 4: Event Type Encoding (Categorical -> Numeric) ----
    # Map event types to numeric codes for ML algorithm
    event_mapping = {
        'Failed Password': 0,
        'Failed Password (repeated)': 0,
        'Invalid User': 1,
        'Accepted Password': 2,
        'Sudo Command': 3
    }
    feature_df['event_type_code'] = feature_df['event_type'].map(event_mapping).fillna(-1).astype(int)

    # ---- Feature 5: Username Length (attackers often use short or long names) ----
    feature_df['username_length'] = feature_df['username'].str.len()

    # ---- Feature 6: Is Root? (target account) ----
    feature_df['is_root'] = (feature_df['username'] == 'root').astype(int)

    # Reset index to have timestamp as column again
    feature_df.reset_index(inplace=True)

    # Remove temporary column used for rolling calculation
    feature_df.drop(columns=['is_failed'], inplace=True, errors='ignore')

    # Reorder columns for clarity (optional)
    cols_order = ['timestamp', 'hostname', 'username', 'ip_address', 'event_type',
                  'failed_login_count_5min', 'hour_of_day', 'is_weekend',
                  'event_type_code', 'username_length', 'is_root', 'raw_message']
    feature_df = feature_df[[c for c in cols_order if c in feature_df.columns]]

    print(f"[+] Features extracted: {len(feature_df)} rows.")
    return feature_df


def get_aggregated_features(feature_df, window_minutes=5):
    """
    Advanced: Aggregates features per IP over a time window for more stable detection.
    This is useful for reducing noise.
    Returns a DataFrame with one row per (IP, window).
    """
    if feature_df.empty:
        return pd.DataFrame()

    # Set timestamp as index for resampling
    df_temp = feature_df.set_index('timestamp')
    # We'll aggregate per IP and per time bin
    aggregated = df_temp.groupby('ip_address').resample(f'{window_minutes}T').agg({
        'failed_login_count_5min': 'max',   # Max failures in that window
        'event_type_code': 'mean',           # Average event severity
        'username_length': 'mean',
        'is_root': 'sum'                     # Number of root attempts
    }).reset_index()
    return aggregated


# ---- Test the feature extraction ----
if __name__ == "__main__":
    from parser import parse_auth_log
    df = parse_auth_log("./logs/auth.log.sample")
    feat_df = extract_features(df)
    print("\n--- Features Sample ---")
    print(feat_df[['timestamp', 'ip_address', 'failed_login_count_5min', 'hour_of_day']].head(15))
