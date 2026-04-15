"""
parser.py
Parses Linux authentication logs (auth.log format) and returns a clean Pandas DataFrame.
Handles: Failed password, Accepted password, Invalid user, sudo, and repeated messages.
"""

import re
import pandas as pd
from datetime import datetime
import sys

def parse_auth_log(filepath):
    """
    Reads a raw auth.log file and extracts structured events.
    Returns: Pandas DataFrame with columns: timestamp, hostname, username, ip_address, event_type, raw_message
    """
    parsed_events = []  # List to hold each event as a dictionary

    # Define regex patterns for different event types
    # Each pattern is a compiled regular expression with named groups.
    # Named groups: (?P<name>pattern) allow us to extract data by name later.

    # Pattern 1: Failed password attempt (most common)
    # Example: "Apr 14 10:17:42 kali sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2"
    failed_password_pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'  # timestamp
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'                         # hostname and sshd pid
        r'Failed password for (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'  # user and IP
    )

    # Pattern 2: Accepted password (successful login)
    # Example: "Apr 14 10:18:01 kali sshd[1234]: Accepted password for kali from 192.168.1.101 port 22 ssh2"
    accepted_password_pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
        r'Accepted password for (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    # Pattern 3: Invalid user (user does not exist on system)
    # Example: "Apr 14 13:22:44 kali sshd[1234]: Invalid user test from 198.51.100.77 port 22"
    invalid_user_pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
        r'Invalid user (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )

    # Pattern 4: sudo command execution (privilege escalation)
    # Example: "Apr 14 10:18:30 kali sudo:    kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/apt update"
    sudo_pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sudo:\s+(?P<username>\S+)\s+:.*COMMAND=(?P<command>.*)'
    )

    # Pattern 5: Message repeated (logs may be compressed)
    # Example: "Apr 14 11:05:32 kali sshd[1234]: Message repeated 2 times: [ Failed password for root from 203.0.113.5 port 22 ssh2]"
    repeated_pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+Message repeated (?P<count>\d+) times: \[ (?P<inner_message>.*) \]'
    )

    # Read the file line by line
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Error: File not found - {filepath}")
        sys.exit(1)

    # We'll need the current year for timestamp conversion (auth.log lacks year)
    current_year = datetime.now().year

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue  # skip empty lines

        event = None

        # Try each pattern in order
        # Note: We use match = pattern.match(line) instead of search() because lines should start with timestamp
        match_fail = failed_password_pattern.match(line)
        match_accept = accepted_password_pattern.match(line)
        match_invalid = invalid_user_pattern.match(line)
        match_sudo = sudo_pattern.match(line)
        match_repeat = repeated_pattern.match(line)

        if match_fail:
            event = {
                'timestamp_str': f"{match_fail.group('month')} {match_fail.group('day')} {match_fail.group('time')}",
                'hostname': match_fail.group('hostname'),
                'username': match_fail.group('username'),
                'ip_address': match_fail.group('ip'),
                'event_type': 'Failed Password',
                'raw_message': line
            }
        elif match_accept:
            event = {
                'timestamp_str': f"{match_accept.group('month')} {match_accept.group('day')} {match_accept.group('time')}",
                'hostname': match_accept.group('hostname'),
                'username': match_accept.group('username'),
                'ip_address': match_accept.group('ip'),
                'event_type': 'Accepted Password',
                'raw_message': line
            }
        elif match_invalid:
            event = {
                'timestamp_str': f"{match_invalid.group('month')} {match_invalid.group('day')} {match_invalid.group('time')}",
                'hostname': match_invalid.group('hostname'),
                'username': match_invalid.group('username'),
                'ip_address': match_invalid.group('ip'),
                'event_type': 'Invalid User',
                'raw_message': line
            }
        elif match_sudo:
            # sudo events don't have an IP address; set to 'localhost'
            event = {
                'timestamp_str': f"{match_sudo.group('month')} {match_sudo.group('day')} {match_sudo.group('time')}",
                'hostname': match_sudo.group('hostname'),
                'username': match_sudo.group('username'),
                'ip_address': '127.0.0.1',
                'event_type': 'Sudo Command',
                'raw_message': line
            }
        elif match_repeat:
            # For repeated messages, we need to parse the inner message and multiply the event count
            count = int(match_repeat.group('count'))
            inner_msg = match_repeat.group('inner_message')
            # Try to parse the inner message to get username and IP
            inner_match_fail = failed_password_pattern.match(inner_msg)
            inner_match_accept = accepted_password_pattern.match(inner_msg)
            inner_match_invalid = invalid_user_pattern.match(inner_msg)

            if inner_match_fail:
                # Create 'count' number of events (duplicate)
                for _ in range(count):
                    parsed_events.append({
                        'timestamp_str': f"{match_repeat.group('month')} {match_repeat.group('day')} {match_repeat.group('time')}",
                        'hostname': match_repeat.group('hostname'),
                        'username': inner_match_fail.group('username'),
                        'ip_address': inner_match_fail.group('ip'),
                        'event_type': 'Failed Password (repeated)',
                        'raw_message': inner_msg
                    })
            # We skip accepted/invalid repeats for brevity (can be added similarly)
            continue  # already added events, skip to next line

        if event:
            # Convert timestamp string to datetime object for proper sorting/filtering
            # Format: "Apr 14 10:17:42" -> add current year
            ts_str_with_year = f"{event['timestamp_str']} {current_year}"
            try:
                dt = datetime.strptime(ts_str_with_year, "%b %d %H:%M:%S %Y")
            except ValueError:
                # If conversion fails, skip this line
                continue
            event['timestamp'] = dt
            # Remove temporary string field
            del event['timestamp_str']
            parsed_events.append(event)

    # Create DataFrame
    if not parsed_events:
        print("[!] Warning: No events parsed. Check log file format.")
        # Return empty DataFrame with expected columns
        return pd.DataFrame(columns=['timestamp', 'hostname', 'username', 'ip_address', 'event_type', 'raw_message'])

    df = pd.DataFrame(parsed_events)
    # Sort by timestamp
    df.sort_values('timestamp', inplace=True)
    df.reset_index(drop=True, inplace=True)

    print(f"[+] Parsed {len(df)} events successfully.")
    return df


# ---- For testing the parser alone ----
if __name__ == "__main__":
    # Test the parser on our sample file
    sample_path = "./logs/auth.log.sample"
    df = parse_auth_log(sample_path)
    print("\n--- Sample of parsed data ---")
    print(df.head(10))
    print("\n--- Event type counts ---")
    print(df['event_type'].value_counts())
