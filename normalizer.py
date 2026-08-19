from dateutil import parser as date_parser 
import json

def load_logs(filepath):
    """Read a CloudTrail JSON file and return the list of events"""
    with open(filepath, "r") as file:
        data = json.load(file)
    return data["Records"]

def get_target(event):
    """Figure out what the action was performed on"""
    params = event.get("requestParameters")
    if not params:
        return "N/A"

    if "policyArn" in params:
        policy = params["policyArn"].split("/")[-1]
        return f"policy:{policy} -> user:{params.get('userName', 'unknown')}"
    if "bucketName" in params:
        key = params.get("key", "")
        if key:
            return f"s3:{params['bucketName']}/{key}"
        return f"s3:{params['bucketName']}"
    if "userName" in params:
        return f"user:{params['userName']}"
    if "stackName" in params:
        return f"stack:{params['stackName']}"
    if "name" in params:
        return f"trail:{params['name']}"
    if "groupName" in params:
        return f"sg:{params['groupName']}"

    return "N/A"

def normalize_event(raw_event):
    """Take one raw CloudTrail event and return a clean, consistent dictionary"""
    try:
        # Actor — not all events have userName
        identity = raw_event.get("userIdentity", {})
        if "userName" in identity:
            actor = identity["userName"]
        elif "invokedBy" in identity:
            actor = f"service:{identity['invokedBy'].replace('.amazonaws.com', '')}"
        else:
            actor = f"unknown:{identity.get('type', 'unknown')}"

        # Timestamp — might be missing or empty
        raw_time = raw_event.get("eventTime", "")
        if raw_time:
            timestamp = date_parser.parse(raw_time)
        else:
            timestamp = None

        return {
            "timestamp": timestamp,
            "actor": actor,
            "action": raw_event.get("eventName", "unknown"),
            "service": raw_event.get("eventSource", "unknown").replace(".amazonaws.com", ""),
            "source_ip": raw_event.get("sourceIPAddress", "unknown"),
            "region": raw_event.get("awsRegion", "unknown"),
            "target": get_target(raw_event),
            "mfa_used": raw_event.get("additionalEventData", {}).get("MFAUsed", "N/A"),
            "source_file": "CloudTrail",
            "raw": raw_event
        }
    except Exception as e:
        return {
            "timestamp": None,
            "actor": "parse_error",
            "action": raw_event.get("eventName", "unknown"),
            "service": "error",
            "source_ip": "unknown",
            "region": "unknown",
            "target": "N/A",
            "mfa_used": "N/A",
            "source_file": "CloudTrail",
            "raw": raw_event,
            "error": str(e)
        }

def normalize_all(raw_events):
    """Normalize a list of raw events"""
    normalized = []
    skipped = 0
    for event in raw_events:
        result = normalize_event(event)
        if result["timestamp"] is None:
            skipped += 1
            print(f"  WARNING: Skipped event — {result['action']} by {result['actor']} (missing/empty timestamp)")
        else:
            normalized.append(result)
    if skipped > 0:
        print(f"  Total skipped: {skipped} events\n")
    return normalized