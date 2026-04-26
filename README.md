# Behavioral Analytics System for Linux Authentication Logs

A modular behavioral analytics pipeline for detecting suspicious activity in Linux authentication logs through log parsing, feature engineering, anomaly detection, and automated alert generation.

This project was developed as part of a university cybersecurity course to demonstrate the practical implementation of SIEM-inspired behavioral analytics techniques in a Linux environment.

## Project Overview

Modern security teams process thousands of log entries every day, making manual detection of suspicious behavior inefficient and error-prone. This project addresses that challenge by automating the analysis of Linux authentication logs to identify potentially malicious or abnormal activity.

The system ingests Linux log data, extracts structured behavioral information, engineers security-relevant features, and applies anomaly detection techniques to flag unusual patterns such as repeated failed logins, abnormal access times, and suspicious privilege escalation attempts.

The project demonstrates the core workflow used in modern Security Information and Event Management (SIEM) systems, including log collection and parsing, behavioral feature engineering, anomaly detection using machine learning, and alert generation with incident reporting.

## Data Sources

The sample dataset used in this project consists of Linux authentication log entries derived from real-world authentication log data for cybersecurity research and educational purposes.

- `logs/auth.log.medium` contains approximately 5,000 log entries for demonstration and testing.
- A larger dataset containing more than 86,000 log entries can be used for extended analysis, benchmarking, and performance evaluation.

These logs simulate realistic authentication activity including normal user access, failed login attempts, privilege escalation, and suspicious authentication patterns.

## Key Feature

- Parses Linux authentication logs including failed logins, successful logins, invalid user attempts, sudo usage, and repeated message entries
- Extracts behavioral indicators such as failed login counts, access timing, source IP activity, and privilege escalation attempts
- Detects anomalies using Isolation Forest without requiring labeled attack data
- Generates structured alerts with severity scoring
- Exports detailed CSV and text-based incident reports
- Saves trained machine learning model and scaler for future reuse
- Designed with modular architecture for easy extension and maintenance

## System Architecture

The project follows a layered pipeline structure:

Raw Authentication Logs  
→ Parsing Module  
→ Structured Event Data  
→ Feature Engineering Module  
→ Numerical Security Features  
→ Anomaly Detection Engine  
→ Risk Scoring and Alert Generation  
→ Reports and Exported Findings  

Each stage of the pipeline is implemented as an independent Python module to improve readability, maintainability, and scalability.

## Project Structure

Behavioral_Analytics_Project/
│
├── main.py
├── requirements.txt
├── README.md
│
├── scripts/
│   ├── __init__.py
│   ├── parser.py
│   ├── features.py
│   ├── detector.py
│   └── alert.py
│
├── logs/
│   └── auth.log.medium
│
├── output/
│
├── models/
│
└── docs/

## Module Descriptions

main.py  
Controls the execution of the full pipeline and orchestrates all modules.

parser.py  
Parses raw Linux authentication logs into structured event records using regular expressions.

features.py  
Transforms parsed log events into behavioral features suitable for anomaly detection.

detector.py  
Applies Isolation Forest to identify anomalous events and calculate risk scores.

alert.py  
Formats suspicious events into readable alerts and exports findings to reports.

## Installation

Clone the repository:

git clone https://github.com/adeliusa486/Behavioral-Analytics-Linux.git  
cd Behavioral-Analytics-Linux

Create and activate a virtual environment (recommended):

python3 -m venv venv  
source venv/bin/activate

Install project dependencies:

pip install -r requirements.txt

## Usage

Run the full pipeline:

python3 main.py --train

This command will:

1. Parse the authentication log  
2. Extract behavioral features  
3. Train the anomaly detection model  
4. Detect suspicious events  
5. Generate alerts and reports  

## Command Line Options

| Option | Description |
|--------|-------------|
| --logfile | Specify path to input log file |
| --train | Force training of a new model |
| --model | Load an existing saved model |
| --scaler | Load an existing scaler |
| --output | Specify output directory |

## Example Commands

Analyze the included sample dataset:

python3 main.py --logfile logs/auth.log.medium --train

Analyze a real Linux authentication log:

python3 main.py --logfile /var/log/auth.log --train

Use an existing trained model:

python3 main.py --model models/isolation_forest.pkl --scaler models/scaler.pkl

## Output Files

| File | Purpose |
|------|---------|
| output/alerts.csv | Contains all detected anomalous events and associated risk scores |
| output/all_events_features.csv | Full dataset with engineered behavioral features |
| output/incident_report.txt | Human-readable incident summary for reporting |

## Detection Methodology

### Log Parsing

The parser processes raw Linux authentication log entries and extracts structured information including:

- Timestamp  
- Username  
- Source IP Address  
- Event Type  
- Raw Log Message  

### Feature Engineering

Behavioral indicators generated from parsed logs include:

- Failed login attempts per IP within a rolling time window  
- Number of unique IPs per user  
- Login frequency by hour  
- Weekend versus weekday access  
- Root account targeting indicators  
- Username-based heuristics  

### Anomaly Detection

Isolation Forest is used as the primary anomaly detection algorithm.

The model identifies suspicious events by learning patterns of normal behavior and isolating observations that deviate significantly from the baseline.

This approach is suitable for security environments where labeled attack data is unavailable.

## Example Detection Output

ALERT SUMMARY

24 suspicious events detected

High Risk Sources:
45.33.22.11  
203.0.113.5  

Potential Indicators:
- Repeated failed login attempts  
- Targeting of privileged accounts  
- Off-hours authentication attempts  
- Multiple rapid authentication failures  

## Learning Outcomes

This project demonstrates practical skills in:

- Linux log analysis  
- Regular expression parsing  
- Security-focused feature engineering  
- Machine learning for anomaly detection  
- Python project modularization  
- Security alert generation and reporting  
- SIEM workflow fundamentals  

## Future Improvements

Planned enhancements include:

- Real-time monitoring using continuous log streaming  
- Support for systemd journal logs  
- Web dashboard for visualizing alerts  
- Email or messaging-based alert notifications  
- Integration with supervised learning models when labeled datasets are available  

## Academic Relevance

This project aligns with emerging cybersecurity practices in:

- Security Operations Centre  
- Threat Detection Engineering  
- Behavioral Analytics Platforms  
- Insider Threat Monitoring  
- SIEM and SOC Automation  

## License

This project is intended for educational and research purposes.

Permission is granted to use, modify, and distribute the code with attribution.

Developed as part of a university cybersecurity practical project on emerging security challenges.
