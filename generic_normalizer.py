import json
import re
import os
from dateutil import parser as date_parser
from datetime import timezone

def load_config(config_path):
    """Load a log format configuration"""
    with open(config_path, "r") as f:
        return json.load(f)

def find_config(filename, config_dir="log_configs"):
    """Find the right config for a file based on extension and content"""
    configs = []
    for f in os.listdir(config_dir):
        if f.endswith(".json"):
            config = load_config(os.path.join(config_dir, f))
            configs.append(config)
    return configs

def get_nested_value(data, field_path, default=None):
    """Get a value from a nested dictionary using dot notation"""
    if not data or not field_path:
        return default
    
    keys = field_path.split(".")
    current = data
    
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    
    if current is None:
        return default
    return current

def resolve_field(data, field_config):
    """Resolve a field value using config rules"""
    if isinstance(field_config, str):
        return get_nested_value(data, field_config)
    
    # Direct field lookup
    value = None
    if "field" in field_config:
        value = get_nested_value(data, field_config["field"])
    
    # If no value, try fallbacks
    if value is None and "fallbacks" in field_config:
        for fallback in field_config["fallbacks"]:
            if "field" in fallback:
                fb_value = get_nested_value(data, fallback["field"])
                if fb_value is not None:
                    prefix = fallback.get("prefix", "")
                    suffix = fallback.get("suffix", "")
                    value = f"{prefix}{fb_value}{suffix}"
                    break
            elif "value" in fallback:
                value = fallback["value"]
                break
    
    # Apply default if still None
    if value is None:
        value = field_config.get("default", "unknown")
    
    # Apply replacements
    if "replace" in field_config and isinstance(value, str):
        for old, new in field_config["replace"].items():
            value = value.replace(old, new)
    
    return value

def resolve_template(data, template):
    """Resolve a target template string like 's3:{requestParameters.bucketName}/{requestParameters.key}'"""
    def replace_placeholder(match):
        expression = match.group(1)
        
        # Handle transforms: {field|after:/} or {field|default:unknown}
        if "|" in expression:
            field_path, transform = expression.split("|", 1)
        else:
            field_path = expression
            transform = None
        
        value = get_nested_value(data, field_path, "")
        if value is None:
            value = ""
        value = str(value)
        
        # Apply transform
        if transform:
            if transform.startswith("after:"):
                separator = transform[6:]
                if separator in value:
                    value = value.split(separator)[-1]
            elif transform.startswith("default:"):
                if not value:
                    value = transform[8:]
        
        return value
    
    result = re.sub(r"\{(.+?)\}", replace_placeholder, template)
    return result

def resolve_target(data, target_rules):
    """Determine the target of an action using config rules"""
    if not target_rules:
        return "N/A"
    
    for rule in target_rules:
        check_field = rule.get("when_field_exists", "")
        value = get_nested_value(data, check_field)
        if value is not None:
            return resolve_template(data, rule["template"])
    
    return "N/A"

def normalize_json_event(raw_event, config):
    """Normalize a single JSON event using the config"""
    try:
        # Timestamp
        ts_field = config["timestamp"]["field"]
        ts_value = get_nested_value(raw_event, ts_field)
        if not ts_value:
            return None
        timestamp = date_parser.parse(str(ts_value))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        # Standard fields
        actor = resolve_field(raw_event, config["fields"]["actor"])
        action = resolve_field(raw_event, config["fields"]["action"])
        
        # Apply action mapping if configured
        action_map = config.get("action_map", {})
        if action in action_map:
            action = action_map[action]
        service = resolve_field(raw_event, config["fields"]["service"])
        source_ip = resolve_field(raw_event, config["fields"]["source_ip"])
        region = resolve_field(raw_event, config["fields"]["region"])
        mfa_used = resolve_field(raw_event, config["fields"].get("mfa_used", {"default": "N/A"}))
        
        # Target
        target = resolve_target(raw_event, config.get("target_rules", []))
        
        return {
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "service": service,
            "source_ip": source_ip,
            "region": region,
            "target": target,
            "mfa_used": mfa_used,
            "source_file": config.get("source_label", config["name"]),
            "raw": raw_event
        }
    except Exception as e:
        return {
            "timestamp": None,
            "actor": "parse_error",
            "action": "unknown",
            "service": "error",
            "source_ip": "unknown",
            "region": "unknown",
            "target": "N/A",
            "mfa_used": "N/A",
            "source_file": config.get("source_label", config["name"]),
            "raw": raw_event,
            "error": str(e)
        }

def normalize_with_config(filepath, config):
    """Load and normalize a file using the given config"""
    file_format = config.get("file_format", "json")
    
    if file_format == "json":
        with open(filepath, "r") as f:
            data = json.load(f)
        
        json_root = config.get("json_root")
        if json_root:
            records = data[json_root]
        else:
            records = data if isinstance(data, list) else [data]
        
        normalized = []
        skipped = 0
        for record in records:
            result = normalize_json_event(record, config)
            if result and result["timestamp"] is not None:
                normalized.append(result)
            else:
                skipped += 1
        
        if skipped > 0:
            print(f"  Skipped {skipped} events")
        
        return normalized
    
    else:
        print(f"  Unsupported file format: {file_format}")
        return []