import sys
from correlator import correlate_sources, print_correlations
from normalizer import load_logs, normalize_all
from linux_normalizer import load_linux_logs, normalize_all_linux
from app_normalizer import load_app_logs, normalize_all_app
from timeline import build_timeline, group_into_sessions, summarize_session
from detector import run_detection, print_findings, detect_attack_chains, print_chains
from compliance import load_all_frameworks, map_findings_to_compliance, print_compliance_report
from ai_engine import ai_root_cause, ai_executive_summary
from report_generator import generate_report, save_report
from investigator import build_investigation_context, interactive_investigation

# Multiple log files — add as many as you want
log_files = [
    "cloudtrail_50.json",
    "app_admin.log",
]

# Load and normalize each file, then merge
all_events = []
for log_file in log_files:
    if log_file.endswith(".json"):
        raw = load_logs(log_file)
        events = normalize_all(raw)
    elif log_file == "linux_auth.log" or "auth" in log_file:
        lines = load_linux_logs(log_file)
        events = normalize_all_linux(lines)
    else:
        lines = load_app_logs(log_file)
        events = normalize_all_app(lines)
    
    print(f"  {log_file}: {len(events)} events")
    all_events.extend(events)

# Merge into one timeline
events = build_timeline(all_events)
print(f"  First event source: {events[0].get('source_file', 'NOT FOUND')}")

sessions = group_into_sessions(events)
print(f"Sessions: {len(sessions)}")

findings = run_detection(events)
print(f"Findings: {len(findings)}")

chains = detect_attack_chains(findings, sessions)
for i, chain in enumerate(chains, 1):
    print(f"  Chain {i}: {chain['chain_type']} [{chain['severity']}] — {chain['primary_actor']}")
print(f"Attack chains: {len(chains)}")

# Cross-source correlation
if len(log_files) > 1:
    correlations = correlate_sources(events)
    print_correlations(correlations)

frameworks = load_all_frameworks()
compliance_results = map_findings_to_compliance(findings, frameworks)
print(f"Frameworks assessed: {len(compliance_results)}")

context = build_investigation_context(events, sessions, findings, chains, compliance_results)

# Debug: print first 3 lines of context that contain [AdminPortal]
for line in context.split("\n"):
    if "AdminPortal" in line:
        print(line)
        break

print(f"\n=== Pipeline Complete ===")
print(f"  Log files: {len(log_files)}")
print(f"  Events: {len(events)}")
print(f"  Sessions: {len(sessions)}")
print(f"  Findings: {len(findings)}")
print(f"  Attack Chains: {len(chains)}")

print("\nOptions:")
print("  1. Generate report (with AI analysis)")
print("  2. Interactive investigation")
print("  3. Both")
print("  4. Skip AI")

choice = input("\nChoose (1/2/3/4): ").strip()

if choice in ["1", "3"]:
    print("\nRunning AI analysis...")
    exec_summary = ai_executive_summary(len(findings), chains, compliance_results)
    print("  Executive summary: done")
    root_causes = []
    for i, chain in enumerate(chains, 1):
        rca = ai_root_cause(chain)
        root_causes.append(rca)
        print(f"  Root cause analysis chain {i}: done")
    report = generate_report(events, sessions, findings, chains, compliance_results, exec_summary, root_causes)
    save_report(report)
    print("  Report saved to: output/investigation_report.md")

if choice in ["2", "3"]:
    interactive_investigation(context)

if choice == "4":
    print("Done.")