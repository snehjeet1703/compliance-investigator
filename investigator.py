from ai_engine import ask_ai

def build_investigation_context(events, sessions, findings, chains, compliance_results):
    """Build a text summary of all investigation data for AI context"""
    context = []
    
    context.append("=== INVESTIGATION DATA ===\n")
    
    # Timeline summary
    context.append(f"Total events: {len(events)}")
    context.append(f"Time window: {events[0]['timestamp']} to {events[-1]['timestamp']}")
    
    # All users and their IPs
    user_ips = {}
    for e in events:
        actor = e["actor"]
        if actor not in user_ips:
            user_ips[actor] = set()
        user_ips[actor].add(e["source_ip"])
    
    context.append(f"\nUsers ({len(user_ips)}):")
    for user, ips in user_ips.items():
        event_count = len([e for e in events if e["actor"] == user])
        ip_list = []
        for ip in ips:
            if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168.") or ip == "local":
                ip_list.append(f"{ip} [INTERNAL]")
            else:
                ip_list.append(f"{ip} [EXTERNAL]")
        context.append(f"  {user}: {event_count} events from {', '.join(ip_list)}")
    
    # Full timeline
    context.append(f"\nTimeline ({len(events)} events):")
    for e in events:
        t = e["timestamp"].strftime("%H:%M:%S")
        source = e.get("source_file", "unknown")
        context.append(f"  [{t}] [{source}] {e['actor']} | {e['action']} | {e['target']} | IP:{e['source_ip']} | MFA:{e['mfa_used']}")
    
    # Sessions
    from timeline import summarize_session
    context.append(f"\nSessions ({len(sessions)}):")
    for i, session in enumerate(sessions, 1):
        summary = summarize_session(session)
        context.append(f"  Session {i}: {summary}")
    
    # Findings
    context.append(f"\nFindings ({len(findings)}):")
    for f in findings:
        t = f["event"]["timestamp"].strftime("%H:%M:%S")
        context.append(f"  [{t}] {f['severity']} | {f['rule']} | {f['description']}")
    
    # Attack chains
    context.append(f"\nAttack Chains ({len(chains)}):")
    for i, chain in enumerate(chains, 1):
        context.append(f"  Chain {i}: {chain['chain_type']} [{chain['severity']}]")
        context.append(f"    Primary actor: {chain['primary_actor']}")
        if chain["secondary_actor"]:
            context.append(f"    Secondary actor: {chain['secondary_actor']}")
        context.append(f"    Description: {chain['description']}")
        context.append(f"    Indicators: {', '.join(chain['indicators'])}")
    
    # Compliance
    context.append(f"\nCompliance Impact:")
    for result in compliance_results:
        context.append(f"  {result['framework']}: {result['total_failed']} controls failed")
        for control_id, details in result["failed_controls"].items():
            context.append(f"    {control_id} — {details['title']}")
    
    return "\n".join(context)

def interactive_investigation(context):
    """Run interactive investigation loop"""
    system_prompt = f"""You are a senior security investigator conducting an interactive investigation.
You have access to the complete investigation data below. Use it to answer questions accurately.

RULES:
- Only state facts that are supported by the investigation data
- If something is an inference, say so
- If the data doesn't contain enough information to answer, say so
- Reference specific events, timestamps, and actors when answering
- Be concise and direct

{context}"""
    
    print("\n" + "=" * 60)
    print(" INTERACTIVE INVESTIGATION MODE")
    print(" Type your questions. Type 'exit' to quit.")
    print("=" * 60)
    
    while True:
        print()
        question = input("Investigator> ").strip()
        
        if not question:
            continue
        if question.lower() in ["exit", "quit", "q"]:
            print("\nEnding investigation session.")
            break
        
        response = ask_ai(question, system_prompt)
        print(f"\n{response}")