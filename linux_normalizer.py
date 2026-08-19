from dateutil import parser as date_parser
from datetime import datetime
import re

def load_linux_logs(filepath):
    """Read a Linux auth.log file and return list of lines"""
    with open(filepath, "r") as file:
        lines = file.readlines()
    return [line.strip() for line in lines if line.strip()]

def parse_timestamp(line):
    """Parse timestamp from auth.log format (Sep 15 08:00:01)"""
    match = re.match(r"(\w+ \d+ \d+:\d+:\d+)", line)
    if match:
        time_str = match.group(1) + " 2025"
        return date_parser.parse(time_str)
    return None

def parse_ssh_line(line):
    """Parse an SSH login line"""
    # Failed password
    match = re.search(r"Failed password for (\S+) from (\S+) port", line)
    if match:
        return {
            "actor": match.group(1),
            "action": "SSHLoginFailed",
            "source_ip": match.group(2),
            "target": "N/A",
            "outcome": "failure"
        }
    
    # Accepted password
    match = re.search(r"Accepted password for (\S+) from (\S+) port", line)
    if match:
        return {
            "actor": match.group(1),
            "action": "SSHLoginPassword",
            "source_ip": match.group(2),
            "target": "N/A",
            "outcome": "success"
        }
    
    # Accepted publickey
    match = re.search(r"Accepted publickey for (\S+) from (\S+) port", line)
    if match:
        return {
            "actor": match.group(1),
            "action": "SSHLoginKey",
            "source_ip": match.group(2),
            "target": "N/A",
            "outcome": "success"
        }
    
    return None

def parse_sudo_line(line):
    """Parse a sudo command line"""
    match = re.search(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)$", line)
    if match:
        user = match.group(1)
        command = match.group(2).strip()
        return {
            "actor": user,
            "action": "SudoCommand",
            "source_ip": "local",
            "target": command,
            "outcome": "success"
        }
    return None

def get_hostname(line):
    """Extract hostname from log line"""
    match = re.match(r"\w+ \d+ \d+:\d+:\d+ (\S+)", line)
    if match:
        return match.group(1)
    return "unknown"

def normalize_linux_event(line):
    """Parse one auth.log line into the standard schema"""
    timestamp = parse_timestamp(line)
    if not timestamp:
        return None
    
    hostname = get_hostname(line)
    
    # Try SSH parsing
    if "sshd[" in line:
        parsed = parse_ssh_line(line)
        if parsed:
            return {
                "timestamp": timestamp,
                "actor": parsed["actor"],
                "action": parsed["action"],
                "service": "sshd",
                "source_ip": parsed["source_ip"],
                "region": hostname,
                "target": parsed["target"],
                "mfa_used": "Key" if parsed["action"] == "SSHLoginKey" else "No",
                "raw": line
            }
    
    # Try sudo parsing
    if "sudo:" in line:
        parsed = parse_sudo_line(line)
        if parsed:
            return {
                "timestamp": timestamp,
                "actor": parsed["actor"],
                "action": parsed["action"],
                "service": "sudo",
                "source_ip": parsed["source_ip"],
                "region": hostname,
                "target": parsed["target"],
                "mfa_used": "N/A",
                "source_file": "LinuxAuth",
                "raw": line
            }
    
    # Skip session opened/closed lines
    return None

def normalize_all_linux(lines):
    """Normalize all Linux auth.log lines"""
    normalized = []
    skipped = 0
    for line in lines:
        result = normalize_linux_event(line)
        if result:
            normalized.append(result)
        else:
            skipped += 1
    if skipped > 0:
        print(f"  Skipped {skipped} non-parseable lines")
    return normalized