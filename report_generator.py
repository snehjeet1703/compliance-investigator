import os
from datetime import datetime

def generate_report(events, sessions, findings, chains, compliance_results, ai_executive_summary, ai_root_causes):
    """Generate a complete investigation report as Markdown"""
    report = []

    # Header
    report.append("# Security Incident Investigation Report")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Classification:** CONFIDENTIAL")
    report.append(f"**Status:** Draft — Pending Review")
    report.append("")

    # Executive Summary
    report.append("---")
    report.append("## 1. Executive Summary")
    report.append("")
    report.append(ai_executive_summary)
    report.append("")

    # Incident Overview
    report.append("---")
    report.append("## 2. Incident Overview")
    report.append("")
    first = events[0]
    last = events[-1]
    duration = last["timestamp"] - first["timestamp"]
    unique_actors = list(set(e["actor"] for e in events))
    unique_ips = list(set(e["source_ip"] for e in events))

    report.append(f"- **Investigation Window:** {first['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} to {last['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"- **Duration:** {duration}")
    report.append(f"- **Total Events Analyzed:** {len(events)}")
    report.append(f"- **Sessions Identified:** {len(sessions)}")
    report.append(f"- **Users Involved:** {', '.join(unique_actors)}")
    report.append(f"- **Source IPs:** {', '.join(unique_ips)}")
    report.append(f"- **Findings:** {len(findings)}")
    report.append(f"- **Attack Chains:** {len(chains)}")
    report.append("")

    # Timeline
    report.append("---")
    report.append("## 3. Timeline of Events")
    report.append("")
    report.append("| Time (UTC) | Actor | Action | Target | MFA |")
    report.append("|------------|-------|--------|--------|-----|")
    for e in events:
        t = e["timestamp"].strftime("%H:%M:%S")
        target = e["target"][:50] if len(e["target"]) > 50 else e["target"]
        report.append(f"| {t} | {e['actor']} | {e['action']} | {target} | {e['mfa_used']} |")
    report.append("")

    # Session Analysis
    report.append("---")
    report.append("## 4. Session Analysis")
    report.append("")
    from timeline import summarize_session
    for i, session in enumerate(sessions, 1):
        summary = summarize_session(session)
        report.append(f"**Session {i}:** {summary}")
        report.append("")

    # Investigation Findings
    report.append("---")
    report.append("## 5. Investigation Findings")
    report.append("")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_findings = [f for f in findings if f["severity"] == severity]
        if not severity_findings:
            continue
        report.append(f"### {severity} ({len(severity_findings)} findings)")
        report.append("")
        for f in severity_findings:
            t = f["event"]["timestamp"].strftime("%H:%M:%S")
            report.append(f"- **[{t}] {f['rule']}** — {f['description']}")
        report.append("")

    # Attack Chain Analysis
    report.append("---")
    report.append("## 6. Attack Chain Analysis")
    report.append("")
    for i, chain in enumerate(chains, 1):
        report.append(f"### Chain {i}: {chain['chain_type']} [{chain['severity']}]")
        report.append("")
        report.append(f"- **Primary Actor:** {chain['primary_actor']}")
        if chain["secondary_actor"]:
            report.append(f"- **Secondary Actor:** {chain['secondary_actor']}")
        report.append(f"- **Description:** {chain['description']}")
        report.append("")
        report.append("**Indicators:**")
        for ind in chain["indicators"]:
            report.append(f"- {ind}")
        report.append("")
        report.append("**Event Sequence:**")
        report.append("")
        report.append("| Time | Severity | Rule | Actor |")
        report.append("|------|----------|------|-------|")
        sorted_findings = sorted(chain["findings"], key=lambda f: f["event"]["timestamp"])
        for f in sorted_findings:
            t = f["event"]["timestamp"].strftime("%H:%M:%S")
            report.append(f"| {t} | {f['severity']} | {f['rule']} | {f['event']['actor']} |")
        report.append("")

    # Root Cause Analysis
    report.append("---")
    report.append("## 7. Root Cause Analysis")
    report.append("")
    for i, rca in enumerate(ai_root_causes, 1):
        report.append(f"### Chain {i}")
        report.append("")
        report.append(rca)
        report.append("")

    # Compliance Impact
    report.append("---")
    report.append("## 8. Compliance Impact")
    report.append("")
    for result in compliance_results:
        report.append(f"### {result['framework']} — {result['total_failed']} Controls Failed")
        report.append("")
        for control_id, details in result["failed_controls"].items():
            report.append(f"**{control_id} — {details['title']}**")
            report.append("")
            report.append(f"Requirement: {details['requirement']}")
            report.append("")
            report.append("Failures:")
            for failure in details["failures"]:
                report.append(f"- {failure}")
            report.append("")
            report.append(f"Evidence ({len(details['triggered_by'])} events):")
            for trigger in details["triggered_by"]:
                report.append(f"- [{trigger['timestamp']}] {trigger['severity']} — {trigger['rule']} by {trigger['actor']}")
            report.append("")

    # Confidence and Assumptions
    report.append("---")
    report.append("## 9. Confidence Rating and Assumptions")
    report.append("")
    report.append("### Confidence: HIGH")
    report.append("")
    report.append("The attack chain is supported by direct evidence from CloudTrail logs showing a clear sequence of unauthorized actions from initial access through data exfiltration to evidence destruction.")
    report.append("")
    report.append("### Assumptions")
    report.append("")
    report.append("- CloudTrail logs have not been tampered with prior to the StopLogging event")
    report.append("- Timestamps in the logs are accurate and synchronized")
    report.append("- The IP addresses in the logs accurately reflect the source of actions")
    report.append("- No additional attacker activity occurred after CloudTrail was disabled")
    report.append("")
    report.append("### Evidence Gaps")
    report.append("")
    report.append("- No network flow logs were available to confirm data exfiltration volume")
    report.append("- No endpoint logs from the attacker's machine")
    report.append("- Activity between CloudTrail deletion (13:29) and the late-night session (22:15) is unmonitored")
    report.append("- No VPC flow logs to determine if data left the network")
    report.append("")

    # End
    report.append("---")
    report.append("*End of Report*")

    return "\n".join(report)

def save_report(report_text, filename="output/investigation_report.md"):
    """Save report to file"""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as f:
        f.write(report_text)
    print(f"\nReport saved to: {filename}")