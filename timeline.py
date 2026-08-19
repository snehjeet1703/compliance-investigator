from datetime import timedelta

def build_timeline(events):
    """Sort events chronologically and return them"""
    return sorted(events, key=lambda e: e["timestamp"])

def group_into_sessions(events, gap_minutes=30):
    """Group events by user. A new session starts when there's a gap of more than gap_minutes between events."""
    # First, separate events by user
    by_user = {}
    for event in events:
        actor = event["actor"]
        if actor not in by_user:
            by_user[actor] = []
        by_user[actor].append(event)

    # Now group each user's events into sessions
    all_sessions = []

    for actor, user_events in by_user.items():
        user_events.sort(key=lambda e: e["timestamp"])

        current_session = [user_events[0]]

        for i in range(1, len(user_events)):
            time_gap = user_events[i]["timestamp"] - user_events[i - 1]["timestamp"]

            if time_gap > timedelta(minutes=gap_minutes):
                # Gap too large — save current session, start new one
                all_sessions.append({
                    "actor": actor,
                    "start": current_session[0]["timestamp"],
                    "end": current_session[-1]["timestamp"],
                    "events": current_session
                })
                current_session = [user_events[i]]
            else:
                current_session.append(user_events[i])

        # Don't forget the last session
        all_sessions.append({
            "actor": actor,
            "start": current_session[0]["timestamp"],
            "end": current_session[-1]["timestamp"],
            "events": current_session
        })

    # Sort sessions by start time
    all_sessions.sort(key=lambda s: s["start"])
    return all_sessions

def print_sessions(sessions):
    """Print sessions in a readable format"""
    for i, session in enumerate(sessions, 1):
        start = session["start"].strftime("%H:%M:%S")
        end = session["end"].strftime("%H:%M:%S")
        duration = session["end"] - session["start"]
        count = len(session["events"])

        print(f"\n{'='*60}")
        print(f"Session {i}: {session['actor']}")
        print(f"Time: {start} - {end} ({duration}) | {count} events")
        print(f"{'-'*60}")

        for e in session["events"]:
            t = e["timestamp"].strftime("%H:%M:%S")
            print(f"  [{t}] {e['action']:25s} | {e['target']}")
    
def summarize_session(session):
    """Generate a plain-English summary of what happened in a session"""
    actor = session["actor"]
    events = session["events"]
    count = len(events)
    start = session["start"].strftime("%H:%M")
    end = session["end"].strftime("%H:%M")

    # Collect what happened
    actions = [e["action"] for e in events]
    targets = [e["target"] for e in events if e["target"] != "N/A"]
    services = list(set(e["service"] for e in events))

    # Check for login
    login_count = actions.count("ConsoleLogin")
    mfa_values = [e["mfa_used"] for e in events if e["action"] == "ConsoleLogin"]

    # Check for reconnaissance (List* actions)
    recon_actions = [a for a in actions if a.startswith("List") or a.startswith("Get") and "Policy" in a]

    # Check for privilege escalation
    priv_actions = [a for a in actions if a in ["CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy"]]

    # Check for data access
    data_downloads = [e["target"] for e in events if e["action"] == "GetObject"]

    # Check for destructive actions
    destructive = [a for a in actions if a.startswith("Delete") or a.startswith("Stop")]

    # Build summary
    parts = []

    # Opening
    parts.append(f"{actor} was active from {start} to {end} ({count} events across {', '.join(services)})")

    # Login info
    if login_count > 0:
        if login_count > 1:
            parts.append(f"Multiple console login attempts ({login_count})")
        if "No" in mfa_values:
            parts.append("Login without MFA")
        elif "Yes" in mfa_values:
            parts.append("Login with MFA")

    # Reconnaissance
    if len(recon_actions) >= 3:
        parts.append(f"Performed reconnaissance: {', '.join(recon_actions)}")

    # Privilege escalation
    if priv_actions:
        priv_targets = [e["target"] for e in events if e["action"] in priv_actions]
        parts.append(f"Privilege escalation: {', '.join(priv_actions)} targeting {', '.join(priv_targets)}")

    # Data access
    if data_downloads:
        buckets = list(set(d.split("/")[0] for d in data_downloads))
        parts.append(f"Downloaded {len(data_downloads)} file(s) from {', '.join(buckets)}")

    # Destructive actions
    if destructive:
        dest_targets = [e["target"] for e in events if e["action"] in destructive]
        parts.append(f"Destructive actions: {', '.join(destructive)} on {', '.join(dest_targets)}")

    return ". ".join(parts) + "."