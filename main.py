#!/usr/bin/env python3
"""
main.py
Behavioral Analytics System for Detecting Suspicious Linux Activity
University Cybersecurity Project

Usage:
    python3 main.py [--logfile PATH] [--train] [--model PATH]
"""

import argparse
import sys
import os

# Import our modules
from scripts.parser import parse_auth_log
from scripts.features import extract_features
from scripts.detector import detect_anomalies
from scripts.alert import generate_alerts

def main():
    parser = argparse.ArgumentParser(description='Behavioral Analytics for Linux Logs')
    parser.add_argument('--logfile', type=str, default='./logs/auth.log.sample',
                        help='Path to auth.log file (default: ./logs/auth.log.sample)')
    parser.add_argument('--train', action='store_true',
                        help='Force training a new model (ignores saved model)')
    parser.add_argument('--model', type=str, default='models/isolation_forest.pkl',
                        help='Path to saved model (default: models/isolation_forest.pkl)')
    parser.add_argument('--scaler', type=str, default='models/scaler.pkl',
                        help='Path to saved scaler (default: models/scaler.pkl)')
    parser.add_argument('--output', type=str, default='output',
                        help='Output directory for reports (default: output)')
    args = parser.parse_args()
    
    print(Fore.CYAN + Style.BRIGHT + "="*60)
    print(Fore.CYAN + Style.BRIGHT + " Behavioral Analytics System for Linux Logs")
    print(Fore.CYAN + Style.BRIGHT + "="*60)
    
    # Step 1: Parse Logs
    print(Fore.WHITE + f"\n[1/4] Parsing log file: {args.logfile}")
    df = parse_auth_log(args.logfile)
    if df.empty:
        print(Fore.RED + "[!] No events parsed. Exiting.")
        sys.exit(1)
    
    # Step 2: Extract Features
    print(Fore.WHITE + "\n[2/4] Extracting behavioral features...")
    feature_df = extract_features(df)
    if feature_df.empty:
        print(Fore.RED + "[!] Feature extraction failed. Exiting.")
        sys.exit(1)
    
    # Step 3: Detect Anomalies
    print(Fore.WHITE + "\n[3/4] Running anomaly detection...")
    if args.train:
        # Force training by not passing model paths
        result_df = detect_anomalies(feature_df, model_path=None, scaler_path=None)
    else:
        # Use saved model if exists, otherwise train new
        model_path = args.model if os.path.exists(args.model) else None
        scaler_path = args.scaler if os.path.exists(args.scaler) else None
        result_df = detect_anomalies(feature_df, model_path=model_path, scaler_path=scaler_path)
    
    # Step 4: Generate Alerts
    print(Fore.WHITE + "\n[4/4] Generating alerts and reports...")
    generate_alerts(result_df, output_dir=args.output)
    
    print(Fore.GREEN + Style.BRIGHT + "\n[+] Analysis complete!")
    print(Fore.GREEN + "    Check the 'output/' folder for CSV reports and incident summary.")

if __name__ == "__main__":
    # Import colorama here for main's print statements
    from colorama import init, Fore, Style
    init(autoreset=True)
    main()
