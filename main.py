import sys
from generic_normalizer import load_config, normalize_with_config
from linux_normalizer import load_linux_logs, normalize_all_linux
from app_normalizer import load_app_logs, normalize_all_app
from timeline import build_timeline, group_into_sessions, summarize_session
from detector import run_detection, print_findings, detect_attack_chains, print_chains
from compliance import load_all_frameworks, map_findings_to_compliance, print_compliance_report
from correlator import correlate_sources
from ai_engine import ai_root_cause, ai_executive_summary
from report_generator import generate_report, save_report
from investigator import build_investigation_context, interactive_investigation

# Multiple log files — add as many as you want
log_files = [
    "cloudtrail_50.json",
]

# Map file types to their configs or normalizers
config_map = {
    "cloudtrail": "log_configs/cloudtrail.json",
}

def detect_and_load(log_file):
    """Detect log type and load accordingly"""
    filename = log_file.lower()
    
    # Linux auth logs
    if "auth" in filename and filename.endswith(".log"):
        lines = load_linux_logs(log_file)
        return normalize_all_linux(lines)
    
    # Application admin logs
    if "app" in filename and filename.endswith(".log"):
        lines = load_app_logs(log_file)
        return normalize_all_app(lines)
    
    # JSON files — detect which config to use
    if filename.endswith(".json"):
        if "azure" in filename:
            config = load_config("log_configs/azure_activity.json")
        elif "gcp" in filename:
            config = load_config("log_configs/gcp_audit.json")
        else:
            config = load_config("log_configs/cloudtrail.json")
        return normalize_with_config(log_file, config)
    
    print(f"  Unknown log format: {log_file}")
    return []

# Load and normalize each file, then merge
all_events = []
for log_file in log_files:
    events = detect_and_load(log_file)
    print(f"  {log_file}: {len(events)} events")
    all_events.extend(events)

# Merge into one timeline
events = build_timeline(all_events)
print(f"\nTotal events: {len(events)}")

sessions = group_into_sessions(events)
print(f"Sessions: {len(sessions)}")

findings = run_detection(events)
print(f"Findings: {len(findings)}")

chains = detect_attack_chains(findings, sessions)
print(f"Attack chains: {len(chains)}")

for i, chain in enumerate(chains, 1):
    print(f"  Chain {i}: {chain['chain_type']} [{chain['severity']}] — {chain['primary_actor']}")

frameworks = load_all_frameworks()
compliance_results = map_findings_to_compliance(findings, frameworks)
print(f"Frameworks assessed: {len(compliance_results)}")

# Cross-source correlation
if len(log_files) > 1:
    correlations = correlate_sources(events)
    from correlator import print_correlations
    print_correlations(correlations)

# Build investigation context for AI
context = build_investigation_context(events, sessions, findings, chains, compliance_results)

print(f"\n=== Pipeline Complete ===")
print(f"  Log files: {len(log_files)}")
print(f"  Events: {len(events)}")
print(f"  Sessions: {len(sessions)}")
print(f"  Findings: {len(findings)}")
print(f"  Attack Chains: {len(chains)}")
print(f"  Compliance Controls Failed: {sum(r['total_failed'] for r in compliance_results)}")

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