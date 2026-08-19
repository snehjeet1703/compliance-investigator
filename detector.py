def detect_no_mfa_login(event):
    """Login without MFA"""
    if event["action"] == "ConsoleLogin" and event["mfa_used"] == "No":
        return {
            "rule": "LOGIN_WITHOUT_MFA",
            "severity": "HIGH",
            "description": f"{event['actor']} logged in without MFA from {event['source_ip']}",
            "event": event
        }
    return None

def detect_privilege_escalation(event):
    """User creation or admin policy attachment"""
    escalation_actions = ["CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy"]
    if event["action"] in escalation_actions:
        return {
            "rule": "PRIVILEGE_ESCALATION",
            "severity": "HIGH",
            "description": f"{event['actor']} performed {event['action']} on {event['target']}",
            "event": event
        }
    return None

def detect_cloudtrail_tampering(event):
    """Disabling or deleting audit logs"""
    tampering_actions = ["StopLogging", "DeleteTrail", "UpdateTrail"]
    if event["action"] in tampering_actions:
        return {
            "rule": "AUDIT_TRAIL_TAMPERING",
            "severity": "CRITICAL",
            "description": f"{event['actor']} performed {event['action']} on {event['target']}",
            "event": event
        }
    return None

def detect_sensitive_data_access(event):
    """Access to buckets with sensitive keywords"""
    sensitive_keywords = ["pii", "customer", "financial", "payroll", "salary", "password", "secret", "credential"]
    if event["action"] == "GetObject":
        target = event["target"].lower()
        matched = [kw for kw in sensitive_keywords if kw in target]
        if matched:
            return {
                "rule": "SENSITIVE_DATA_ACCESS",
                "severity": "HIGH",
                "description": f"{event['actor']} accessed {event['target']} (matched: {', '.join(matched)})",
                "event": event
            }
    return None

def detect_unusual_hour(event):
    """Activity outside business hours (before 8 AM or after 7 PM IST)"""
    if event["timestamp"] is None:
        return None
    # CloudTrail logs are UTC, IST is UTC+5:30
    utc_hour = event["timestamp"].hour
    ist_hour = (utc_hour + 5) % 24  # simplified, ignoring the 30 min
    if ist_hour < 6 or ist_hour >= 23:
        return {
            "rule": "UNUSUAL_HOURS",
            "severity": "MEDIUM",
            "description": f"{event['actor']} active at {event['timestamp'].strftime('%H:%M')} UTC (approx {ist_hour}:XX IST)",
            "event": event
        }
    return None

def detect_self_deletion(event):
    """Account deleting itself — covering tracks"""
    if event["action"] == "DeleteUser":
        target_user = event["target"].replace("user:", "")
        if target_user == event["actor"]:
            return {
                "rule": "SELF_DELETION",
                "severity": "CRITICAL",
                "description": f"{event['actor']} deleted its own account",
                "event": event
            }
    return None

def detect_concurrent_sessions(events):
    """Detect same user active from different IPs within a short time window"""
    findings = []
    
    # Group events by actor
    by_actor = {}
    for event in events:
        actor = event["actor"]
        if actor not in by_actor:
            by_actor[actor] = []
        by_actor[actor].append(event)
 
    # For each user, check if they used multiple IPs close together
    for actor, actor_events in by_actor.items():
        actor_events.sort(key=lambda e: e["timestamp"])
        
        for i in range(len(actor_events)):
            for j in range(i + 1, len(actor_events)):
                e1 = actor_events[i]
                e2 = actor_events[j]
                
                if e1["source_ip"] != e2["source_ip"]:
                    # Skip if one IP is "local" (sudo commands on same host)
                    if e1["source_ip"] == "local" or e2["source_ip"] == "local":
                        continue
                    gap = abs((e2["timestamp"] - e1["timestamp"]).total_seconds())
                    if gap < 1800:  # Within 30 minutes
                        findings.append({
                            "rule": "CONCURRENT_SESSION",
                            "severity": "CRITICAL",
                            "description": f"{actor} active from {e1['source_ip']} and {e2['source_ip']} within {int(gap/60)} minutes",
                            "event": e2
                        })
                        return findings  # One finding is enough to prove it
    
    return findings

# Master list of all detection rules
ALL_RULES = [
    detect_no_mfa_login,
    detect_privilege_escalation,
    detect_cloudtrail_tampering,
    detect_sensitive_data_access,
    detect_unusual_hour,
    detect_self_deletion,
]

def run_detection(events):
    """Run all detection rules against all events. Return list of findings."""
    findings = []
    
    # Per-event rules
    for event in events:
        for rule in ALL_RULES:
            result = rule(event)
            if result:
                findings.append(result)
    
    # Multi-event rules (need full event list)
    multi_results = detect_concurrent_sessions(events)
    findings.extend(multi_results)
    
    multi_results = detect_impossible_travel(events)
    findings.extend(multi_results)

    multi_results = detect_ip_anomaly(events)
    findings.extend(multi_results)

    multi_results = detect_persistence(events)
    findings.extend(multi_results)

    multi_results = detect_volume_anomaly(events)
    findings.extend(multi_results)

    multi_results = detect_breadth_anomaly(events)
    findings.extend(multi_results)

    multi_results = detect_ssh_brute_force(events)
    findings.extend(multi_results)

    multi_results = detect_suspicious_sudo(events)
    findings.extend(multi_results)
    
    return findings

def detect_suspicious_sudo(events):
    """Detect sudo commands that indicate malicious activity"""
    findings = []
    
    suspicious_patterns = {
        "/etc/shadow": ("CREDENTIAL_ACCESS", "CRITICAL", "Accessed password hashes"),
        "/etc/passwd": ("CREDENTIAL_ACCESS", "HIGH", "Accessed user account info"),
        "useradd": ("PRIVILEGE_ESCALATION", "CRITICAL", "Created new user account"),
        "usermod": ("PRIVILEGE_ESCALATION", "HIGH", "Modified user privileges"),
        "passwd ": ("PRIVILEGE_ESCALATION", "HIGH", "Changed user password"),
        ".ssh/id_rsa": ("CREDENTIAL_ACCESS", "CRITICAL", "Stole SSH private key"),
        "db-credentials": ("CREDENTIAL_ACCESS", "CRITICAL", "Accessed database credentials"),
        "api-keys": ("CREDENTIAL_ACCESS", "HIGH", "Accessed API keys"),
        "stop auditd": ("AUDIT_TRAIL_TAMPERING", "CRITICAL", "Stopped audit daemon"),
        "truncate": ("AUDIT_TRAIL_TAMPERING", "CRITICAL", "Cleared log files"),
        "tar czf": ("DATA_EXFILTRATION", "HIGH", "Archived data for exfiltration"),
        "nmap": ("RECONNAISSANCE", "HIGH", "Network scanning tool executed"),
    }
    
    for event in events:
        if event["action"] == "SudoCommand":
            target = event["target"]
            for pattern, (rule, severity, description) in suspicious_patterns.items():
                if pattern in target:
                    findings.append({
                        "rule": rule,
                        "severity": severity,
                        "description": f"{event['actor']} ran: {target} — {description}",
                        "event": event
                    })
                    break  # One match per command is enough
    
    return findings

def detect_impossible_travel(events):
    """Detect same user in different AWS regions within impossible timeframes"""
    findings = []
    
    by_actor = {}
    for event in events:
        actor = event["actor"]
        if actor not in by_actor:
            by_actor[actor] = []
        by_actor[actor].append(event)
    
    for actor, actor_events in by_actor.items():
        sorted_events = sorted(actor_events, key=lambda e: e["timestamp"])
        
        # Only compare actual geographic regions
        geo_regions = ["ap-south-1", "ap-south-2", "us-east-1", "us-east-2", 
                       "us-west-1", "us-west-2", "eu-west-1", "eu-west-2",
                       "eu-central-1", "ap-southeast-1", "ap-northeast-1"]
        
        for i in range(1, len(sorted_events)):
            prev = sorted_events[i - 1]
            curr = sorted_events[i]
            
            # Skip if either region is not a geographic AWS region
            if prev["region"] not in geo_regions or curr["region"] not in geo_regions:
                continue
            
            if prev["region"] != curr["region"]:
                gap_minutes = (curr["timestamp"] - prev["timestamp"]).total_seconds() / 60
                if gap_minutes < 60:
                    findings.append({
                        "rule": "IMPOSSIBLE_TRAVEL",
                        "severity": "HIGH",
                        "description": f"{actor} switched from {prev['region']} to {curr['region']} in {int(gap_minutes)} minutes",
                        "event": curr
                    })
                    break
    
    return findings

def detect_volume_anomaly(events):
    """Detect users downloading significantly more files than others"""
    findings = []
    
    # Count GetObject events per user
    download_counts = {}
    for event in events:
        if event["action"] == "GetObject":
            actor = event["actor"]
            if actor in download_counts:
                download_counts[actor] += 1
            else:
                download_counts[actor] = 1
    
    if len(download_counts) < 2:
        return findings  # Need at least 2 users to compare
    
    # Calculate average downloads (excluding the user being checked)
    for actor, count in download_counts.items():
        other_counts = [c for a, c in download_counts.items() if a != actor]
        avg_others = sum(other_counts) / len(other_counts)
        
        # Flag if user downloaded 3x more than average of others
        if avg_others > 0 and count >= 3 * avg_others and count >= 8:
            findings.append({
                "rule": "VOLUME_ANOMALY",
                "severity": "HIGH",
                "description": f"{actor} downloaded {count} files (others averaged {avg_others:.0f}) — {count/avg_others:.1f}x above normal",
                "event": [e for e in events if e["actor"] == actor and e["action"] == "GetObject"][0]
            })
    
    return findings

def detect_breadth_anomaly(events):
    """Detect users accessing unusually many different buckets"""
    findings = []
    
    # Count unique buckets accessed per user
    user_buckets = {}
    for event in events:
        if event["action"] == "GetObject" and event["target"] != "N/A":
            actor = event["actor"]
            bucket = event["target"].split("/")[0]  # Get just the bucket name
            if actor not in user_buckets:
                user_buckets[actor] = set()
            user_buckets[actor].add(bucket)
    
    if len(user_buckets) < 2:
        return findings
    
    for actor, buckets in user_buckets.items():
        other_bucket_counts = [len(b) for a, b in user_buckets.items() if a != actor]
        avg_others = sum(other_bucket_counts) / len(other_bucket_counts)
        
        if len(buckets) >= 4 and len(buckets) > avg_others * 2:
            findings.append({
                "rule": "BREADTH_ANOMALY",
                "severity": "HIGH",
                "description": f"{actor} accessed {len(buckets)} different buckets ({', '.join(buckets)}) — others averaged {avg_others:.0f}",
                "event": [e for e in events if e["actor"] == actor and e["action"] == "GetObject"][0]
            })
    
    return findings

def detect_ip_anomaly(events):
    """Detect user acting from an IP outside their normal pattern"""
    findings = []
    
    by_actor = {}
    for event in events:
        actor = event["actor"]
        if actor not in by_actor:
            by_actor[actor] = []
        by_actor[actor].append(event)
    
    for actor, actor_events in by_actor.items():
        # Find IPs that were used with MFA — these are trusted
        trusted_ips = set()
        for e in actor_events:
            if e["mfa_used"] == "Yes":
                trusted_ips.add(e["source_ip"])
        
        if not trusted_ips:
            continue  # No MFA baseline to compare against
        
        # Flag first event from each non-trusted IP
        flagged_ips = set()
        for e in actor_events:
            if e["source_ip"] not in trusted_ips and e["source_ip"] not in flagged_ips:
                flagged_ips.add(e["source_ip"])
                findings.append({
                    "rule": "IP_ANOMALY",
                    "severity": "HIGH",
                    "description": f"{actor} acted from untrusted IP {e['source_ip']} (trusted: {', '.join(trusted_ips)})",
                    "event": e
                })
    
    return findings

def detect_ssh_brute_force(events):
    """Detect multiple failed SSH logins from the same IP"""
    findings = []
    
    # Count failed SSH logins per IP
    failed_by_ip = {}
    for event in events:
        if event["action"] == "SSHLoginFailed":
            ip = event["source_ip"]
            if ip not in failed_by_ip:
                failed_by_ip[ip] = []
            failed_by_ip[ip].append(event)
    
    for ip, failed_events in failed_by_ip.items():
        if len(failed_events) >= 5:
            # Check if a successful login followed from same IP
            success_after = None
            last_failure = failed_events[-1]["timestamp"]
            for event in events:
                if event["source_ip"] == ip and event["action"] in ["SSHLoginPassword", "SSHLoginKey"]:
                    if event["timestamp"] >= last_failure:
                        success_after = event
                        break
            
            description = f"{len(failed_events)} failed SSH attempts from {ip}"
            if success_after:
                description += f", then successful login as {success_after['actor']}"
                severity = "CRITICAL"
            else:
                severity = "HIGH"
            
            # Use the successful login event if available, so the finding
            # groups with the compromised user's other activity
            if success_after:
                finding_event = success_after
            else:
                finding_event = failed_events[0]

            findings.append({
                "rule": "SSH_BRUTE_FORCE",
                "severity": severity,
                "description": description,
                "event": finding_event
            })
    
    return findings    

def detect_persistence(events):
    """Detect user creating access keys for their own account"""
    findings = []
    for event in events:
        if event["action"] == "CreateAccessKey":
            target_user = event["target"].replace("user:", "")
            if target_user == event["actor"]:
                findings.append({
                    "rule": "PERSISTENCE_ACCESS_KEY",
                    "severity": "HIGH",
                    "description": f"{event['actor']} created access key for their own account from {event['source_ip']}",
                    "event": event
                })
    return findings

def print_findings(findings):
    """Print findings grouped by severity"""
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_findings = [f for f in findings if f["severity"] == severity]
        if not severity_findings:
            continue
        print(f"\n{'='*60}")
        print(f" {severity} ({len(severity_findings)} findings)")
        print(f"{'='*60}")
        for f in severity_findings:
            t = f["event"]["timestamp"].strftime("%H:%M:%S")
            print(f"\n  [{t}] {f['rule']}")
            print(f"  {f['description']}")

def detect_attack_chains(findings, sessions):
    """Look for multi-step attack patterns across findings and sessions"""
    chains = []

    # Group findings by actor
    by_actor = {}
    for f in findings:
        actor = f["event"]["actor"]
        if actor not in by_actor:
            by_actor[actor] = []
        by_actor[actor].append(f)

    # Check each actor's findings for attack patterns
    for actor, actor_findings in by_actor.items():
        rules_triggered = set(f["rule"] for f in actor_findings)

        # Pattern 1: Account creation attack
        # Someone who escalates privileges AND whose created account accesses sensitive data
        if "PRIVILEGE_ESCALATION" in rules_triggered:
            # Find what accounts this actor created
            created_users = []
            for f in actor_findings:
                if f["event"]["action"] == "CreateUser":
                    target = f["event"]["target"].replace("user:", "")
                    created_users.append(target)

            # Check if any created account has findings
            for created_user in created_users:
                if created_user in by_actor:
                    child_rules = set(f["rule"] for f in by_actor[created_user])
                    chain = {
                        "chain_type": "ACCOUNT_CREATION_ATTACK",
                        "severity": "CRITICAL",
                        "primary_actor": actor,
                        "secondary_actor": created_user,
                        "description": f"{actor} created account '{created_user}' which then triggered: {', '.join(child_rules)}",
                        "findings": actor_findings + by_actor[created_user],
                        "indicators": []
                    }

                    # Add specific indicators
                    if "LOGIN_WITHOUT_MFA" in rules_triggered:
                        chain["indicators"].append("Primary actor logged in without MFA")
                    if "SENSITIVE_DATA_ACCESS" in child_rules:
                        chain["indicators"].append("Created account accessed sensitive data")
                    if "AUDIT_TRAIL_TAMPERING" in child_rules:
                        chain["indicators"].append("Created account tampered with audit trails")
                    if "SELF_DELETION" in child_rules:
                        chain["indicators"].append("Created account deleted itself")
                    if "UNUSUAL_HOURS" in child_rules:
                        chain["indicators"].append("Created account active during unusual hours")

                    chains.append(chain)

        # Pattern 2: Brute force followed by action
        login_findings = [f for f in actor_findings if f["rule"] == "LOGIN_WITHOUT_MFA"]
        if len(login_findings) >= 2:
            other_findings = [f for f in actor_findings if f["rule"] != "LOGIN_WITHOUT_MFA"]
            if other_findings:
                chain = {
                    "chain_type": "BRUTE_FORCE_AND_ACT",
                    "severity": "HIGH",
                    "primary_actor": actor,
                    "secondary_actor": None,
                    "description": f"{actor} made {len(login_findings)} login attempts without MFA, then performed {len(other_findings)} suspicious actions",
                    "findings": actor_findings,
                    "indicators": [f"Multiple login attempts ({len(login_findings)})"]
                }
                chains.append(chain)

    # Pattern 3: Compromised credentials
        has_concurrent = "CONCURRENT_SESSION" in rules_triggered
        has_impossible_travel = "IMPOSSIBLE_TRAVEL" in rules_triggered
        has_ip_anomaly = "IP_ANOMALY" in rules_triggered

        if has_concurrent or has_impossible_travel:
            chain = {
                "chain_type": "COMPROMISED_CREDENTIALS",
                "severity": "CRITICAL",
                "primary_actor": actor,
                "secondary_actor": None,
                "description": f"{actor}'s credentials appear compromised — account used from multiple locations simultaneously",
                "findings": actor_findings,
                "indicators": []
            }
            if has_concurrent:
                chain["indicators"].append("Active from multiple IPs within short timeframe")
            if has_impossible_travel:
                chain["indicators"].append("Impossible geographic travel between regions")
            if has_ip_anomaly:
                chain["indicators"].append("Activity from untrusted IPs")
            if "LOGIN_WITHOUT_MFA" in rules_triggered:
                chain["indicators"].append("Login without MFA from unusual IP")
            if "SENSITIVE_DATA_ACCESS" in rules_triggered:
                chain["indicators"].append("Sensitive data accessed from unusual location")
            if "PERSISTENCE_ACCESS_KEY" in rules_triggered:
                chain["indicators"].append("Access keys created for persistence")
            if "UNUSUAL_HOURS" in rules_triggered:
                chain["indicators"].append("Activity during unusual hours")
            chains.append(chain)

    # Pattern 4: Departing employee data theft
        has_volume = "VOLUME_ANOMALY" in rules_triggered
        has_breadth = "BREADTH_ANOMALY" in rules_triggered

        if has_volume and has_breadth:
            chain = {
                "chain_type": "DATA_HOARDING",
                "severity": "HIGH",
                "primary_actor": actor,
                "secondary_actor": None,
                "description": f"{actor} downloaded an abnormal volume of files across multiple sensitive buckets",
                "findings": actor_findings,
                "indicators": []
            }
            chain["indicators"].append("Download volume significantly above peers")
            chain["indicators"].append("Accessed unusually many different data sources")
            if "SENSITIVE_DATA_ACCESS" in rules_triggered:
                sensitive_count = len([f for f in actor_findings if f["rule"] == "SENSITIVE_DATA_ACCESS"])
                chain["indicators"].append(f"Accessed {sensitive_count} sensitive files")
            if "PERSISTENCE_ACCESS_KEY" in rules_triggered:
                chain["indicators"].append("Created access key for continued access after departure")
            chains.append(chain)

    # Pattern 5: SSH compromise chain
        has_brute_force = "SSH_BRUTE_FORCE" in rules_triggered
        has_credential_access = "CREDENTIAL_ACCESS" in rules_triggered
        has_audit_tampering = "AUDIT_TRAIL_TAMPERING" in rules_triggered

        if has_brute_force and (has_credential_access or has_audit_tampering):
            chain = {
                "chain_type": "SSH_COMPROMISE",
                "severity": "CRITICAL",
                "primary_actor": actor,
                "secondary_actor": None,
                "description": f"SSH brute force succeeded against {actor}, followed by credential theft and system compromise",
                "findings": actor_findings,
                "indicators": []
            }
            chain["indicators"].append("SSH brute force with successful login")
            if has_credential_access:
                cred_count = len([f for f in actor_findings if f["rule"] == "CREDENTIAL_ACCESS"])
                chain["indicators"].append(f"Accessed {cred_count} credential sources")
            if "PRIVILEGE_ESCALATION" in rules_triggered:
                chain["indicators"].append("Created backdoor user account")
            if has_audit_tampering:
                chain["indicators"].append("Tampered with audit logs to cover tracks")
            if "DATA_EXFILTRATION" in rules_triggered:
                chain["indicators"].append("Archived data for exfiltration")
            if "RECONNAISSANCE" in rules_triggered:
                chain["indicators"].append("Performed network reconnaissance")
            chains.append(chain)

    return chains


def print_chains(chains):
    """Print detected attack chains"""
    if not chains:
        print("\nNo attack chains detected.")
        return

    print(f"\n{'#'*60}")
    print(f" ATTACK CHAIN ANALYSIS — {len(chains)} chain(s) detected")
    print(f"{'#'*60}")

    for i, chain in enumerate(chains, 1):
        print(f"\n{'='*60}")
        print(f" Chain {i}: {chain['chain_type']} [{chain['severity']}]")
        print(f"{'='*60}")
        print(f" Primary actor:   {chain['primary_actor']}")
        if chain["secondary_actor"]:
            print(f" Secondary actor: {chain['secondary_actor']}")
        print(f" {chain['description']}")

        print(f"\n Indicators:")
        for ind in chain["indicators"]:
            print(f"   - {ind}")

        print(f"\n Event sequence:")
        sorted_findings = sorted(chain["findings"], key=lambda f: f["event"]["timestamp"])
        for f in sorted_findings:
            t = f["event"]["timestamp"].strftime("%H:%M:%S")
            print(f"   [{t}] {f['severity']:8s} | {f['rule']:25s} | {f['event']['actor']}")