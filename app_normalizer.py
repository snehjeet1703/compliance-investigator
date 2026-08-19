from datetime import timezone
from dateutil import parser as date_parser
import re

def load_app_logs(filepath):
    """Read application log file and return list of lines"""
    with open(filepath, "r") as file:
        lines = file.readlines()
    return [line.strip() for line in lines if line.strip()]

def parse_app_line(line):
    """Parse one application log line"""
    # Format: [2025-07-10 08:15:22] LEVEL  category: message
    match = re.match(r"\[(.+?)\]\s+(\w+)\s+(\w+):\s+(.+)", line)
    if not match:
        return None
    
    timestamp_str = match.group(1)
    level = match.group(2)
    category = match.group(3)
    message = match.group(4)
    
    timestamp = date_parser.parse(timestamp_str).replace(tzinfo=timezone.utc)
    
    # Extract actor and action from message
    actor, action, target, source_ip = parse_message(message, category)
    
    return {
        "timestamp": timestamp,
        "actor": actor,
        "action": action,
        "service": f"app:{category}",
        "source_ip": source_ip,
        "region": "admin-portal",
        "target": target,
        "mfa_used": "N/A",
        "log_level": level,
        "source_file": "AdminPortal",
        "raw": line
    }

def parse_message(message, category):
    """Extract actor, action, target, and IP from the log message"""
    actor = "unknown"
    action = "Unknown"
    target = "N/A"
    source_ip = "unknown"
    
    # Login success: "priya.sharma logged in from 10.0.5.22 (session: sess_pr_001)"
    match = re.match(r"(\S+) logged in from (\S+)", message)
    if match:
        return match.group(1), "AppLogin", "N/A", match.group(2)
    
    # Login failed: "rahul.kapoor failed login from 203.0.113.55 (invalid password)"
    match = re.match(r"(\S+) failed login from (\S+)", message)
    if match:
        return match.group(1), "AppLoginFailed", "N/A", match.group(2)
    
    # Unknown user login attempt
    match = re.match(r"unknown user attempted login as '(\S+)' from (\S+)", message)
    if match:
        return match.group(1), "AppLoginFailed", "N/A", match.group(2)
    
    # Session ended
    match = re.match(r"(\S+) session", message)
    if match:
        return match.group(1), "SessionEnd", "N/A", "local"
    
    # Bulk export initiated
    match = re.match(r"(\S+) initiated bulk export: (\S+) table \((.+?) records\)", message)
    if match:
        return match.group(1), "BulkExport", f"table:{match.group(2)} ({match.group(3)} records)", "local"
    
    # Downloaded export
    match = re.match(r"(\S+) downloaded export: (.+?) \((.+?)\)", message)
    if match:
        return match.group(1), "DataDownload", f"file:{match.group(2)} ({match.group(3)})", "local"
    
    # Created service account
    match = re.match(r"(\S+) created service account '(\S+)' with (\S+) role", message)
    if match:
        return match.group(1), "CreateServiceAccount", f"account:{match.group(2)} role:{match.group(3)}", "local"
    
    # Deleted service account
    match = re.match(r"(\S+) deleted service account '(\S+)'", message)
    if match:
        return match.group(1), "DeleteServiceAccount", f"account:{match.group(2)}", "local"
    
    # Exported data
    match = re.match(r"(\S+) exported (.+)", message)
    if match:
        return match.group(1), "DataExport", match.group(2), "local"
    
    # Viewed/accessed something
    match = re.match(r"(\S+) (?:viewed|accessed) (.+)", message)
    if match:
        return match.group(1), "ViewedResource", match.group(2), "local"
    
    # Modified/updated/disabled something
    match = re.match(r"(\S+) (?:modified|updated|disabled|changed) (.+)", message)
    if match:
        return match.group(1), "ConfigChange", match.group(2), "local"
    
    # Generated report
    match = re.match(r"(\S+) generated (.+)", message)
    if match:
        return match.group(1), "GenerateReport", match.group(2), "local"
    
    # Fallback: try to get at least the actor
    match = re.match(r"(\S+)\s", message)
    if match:
        actor = match.group(1)
    
    return actor, f"Other:{category}", message, "local"

def normalize_all_app(lines):
    """Normalize all application log lines"""
    normalized = []
    skipped = 0
    for line in lines:
        result = parse_app_line(line)
        if result:
            normalized.append(result)
        else:
            skipped += 1
    if skipped > 0:
        print(f"  Skipped {skipped} non-parseable lines")
    return normalized