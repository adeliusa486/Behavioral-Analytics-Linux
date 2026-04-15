#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import os

def create_visualizations(alerts_csv='output/alerts.csv', output_dir='output'):
    if not os.path.exists(alerts_csv):
        print(f"[!] Alerts file not found: {alerts_csv}")
        print("[!] Run main program first: python3 main.py --train")
        return

    alerts = pd.read_csv(alerts_csv)
    if alerts.empty:
        print("[!] No alerts to visualize.")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Chart 1: Top Suspicious IPs
    plt.figure(figsize=(12, 6))
    top_ips = alerts['ip_address'].value_counts().head(10)
    plt.bar(range(len(top_ips)), top_ips.values, color='crimson')
    plt.xticks(range(len(top_ips)), top_ips.index, rotation=45, ha='right')
    plt.title('Top 10 Suspicious IP Addresses by Alert Count')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Anomalous Events')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'top_suspicious_ips.png'), dpi=150)
    plt.close()
    print(f"[+] Saved: {output_dir}/top_suspicious_ips.png")

    # Chart 2: Risk Score Distribution
    plt.figure(figsize=(10, 5))
    plt.hist(alerts['risk_score'], bins=20, color='orange', edgecolor='black', alpha=0.7)
    plt.title('Distribution of Anomaly Risk Scores')
    plt.xlabel('Risk Score (0 = Normal, 1 = Highly Anomalous)')
    plt.ylabel('Number of Events')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'risk_score_distribution.png'), dpi=150)
    plt.close()
    print(f"[+] Saved: {output_dir}/risk_score_distribution.png")

    # Chart 3: Events by Hour (if timestamp exists)
    if 'timestamp' in alerts.columns:
        try:
            alerts['hour'] = pd.to_datetime(alerts['timestamp']).dt.hour
            plt.figure(figsize=(10, 5))
            alerts['hour'].value_counts().sort_index().plot(kind='bar', color='navy')
            plt.title('Anomalous Events by Hour of Day')
            plt.xlabel('Hour (0-23)')
            plt.ylabel('Number of Alerts')
            plt.xticks(rotation=0)
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'events_by_hour.png'), dpi=150)
            plt.close()
            print(f"[+] Saved: {output_dir}/events_by_hour.png")
        except:
            pass

if __name__ == "__main__":
    create_visualizations()o

