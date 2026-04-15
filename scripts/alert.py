"""
alert.py
Generates alerts for detected anomalies.
Outputs: Colored terminal messages, CSV report in output/alerts.csv
"""

import pandas as pd
import os
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

def generate_alerts(result_df, output_dir='output'):
    """
    Takes the DataFrame with anomaly predictions and:
    1. Prints a summary to the terminal (with colors)
    2. Saves a detailed CSV of all anomalous events
    
    Parameters:
        result_df (pd.DataFrame): Output from detector.detect_anomalies()
        output_dir (str): Directory to save output files
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Filter only anomalies
    anomalies = result_df[result_df['is_anomaly'] == True].copy()
    
    if anomalies.empty:
        print(Fore.GREEN + "[+] No anomalies detected. System appears normal.")
        # Still save an empty file with header
        header_df = pd.DataFrame(columns=['timestamp', 'ip_address', 'username', 'event_type', 
                                          'failed_login_count_5min', 'risk_score', 'raw_message'])
        header_df.to_csv(os.path.join(output_dir, 'alerts.csv'), index=False)
        return
    
    # Sort by risk score descending (most suspicious first)
    anomalies.sort_values('risk_score', ascending=False, inplace=True)
    
    # ---- Terminal Output with Colors ----
    print("\n" + "="*80)
    print(Fore.RED + Style.BRIGHT + f"[!] ALERT: {len(anomalies)} Suspicious Events Detected!")
    print("="*80)
    
    # Group by IP address to summarize
    ip_summary = anomalies.groupby('ip_address').agg({
        'risk_score': ['max', 'count'],
        'failed_login_count_5min': 'max',
        'username': lambda x: list(set(x))[:3]  # show up to 3 usernames targeted
    }).reset_index()
    ip_summary.columns = ['IP_Address', 'Max_Risk_Score', 'Event_Count', 'Max_Failures_5min', 'Target_Usernames']
    ip_summary.sort_values('Max_Risk_Score', ascending=False, inplace=True)
    
    print(Fore.YELLOW + "\n[Summary by IP Address]")
    print(ip_summary.to_string(index=False))
    
    print(Fore.CYAN + "\n[Detailed Anomalous Events (Top 10)]")
    # Select columns to display
    display_cols = ['timestamp', 'ip_address', 'username', 'event_type', 
                    'failed_login_count_5min', 'risk_score']
    top_anomalies = anomalies[display_cols].head(10)
    print(top_anomalies.to_string(index=False))
    
    # ---- Save Full Report to CSV ----
    csv_path = os.path.join(output_dir, 'alerts.csv')
    # Save all anomaly data (including raw message for context)
    save_cols = ['timestamp', 'ip_address', 'username', 'event_type', 
                 'failed_login_count_5min', 'hour_of_day', 'is_weekend', 
                 'risk_score', 'raw_message']
    anomalies[save_cols].to_csv(csv_path, index=False)
    print(Fore.GREEN + f"\n[+] Full alert details saved to {csv_path}")
    
    # ---- Optional: Save all events with features (for further analysis) ----
    all_features_path = os.path.join(output_dir, 'all_events_features.csv')
    result_df.to_csv(all_features_path, index=False)
    print(Fore.GREEN + f"[+] Complete feature dataset saved to {all_features_path}")
    
    # ---- Generate a simple text report ----
    report_path = os.path.join(output_dir, 'incident_report.txt')
    with open(report_path, 'w') as f:
        f.write(f"Behavioral Analytics Incident Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        f.write(f"Total Anomalies: {len(anomalies)}\n\n")
        f.write("Top Suspicious IPs:\n")
        f.write(ip_summary.to_string(index=False))
        f.write("\n\nDetailed Events:\n")
        f.write(anomalies[display_cols].to_string(index=False))
    print(Fore.GREEN + f"[+] Text report saved to {report_path}")
    
    return anomalies


# ---- Test alert generation ----
if __name__ == "__main__":
    from parser import parse_auth_log
    from features import extract_features
    from detector import detect_anomalies
    
    df = parse_auth_log("./logs/auth.log.sample")
    feat_df = extract_features(df)
    result_df = detect_anomalies(feat_df)
    generate_alerts(result_df)
