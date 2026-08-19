import json
import os

def load_framework(filepath):
    """Load a compliance framework mapping from JSON"""
    with open(filepath, "r") as f:
        return json.load(f)

def load_all_frameworks(directory="compliance_mappings"):
    """Load all framework files from the mappings directory"""
    frameworks = []
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            filepath = os.path.join(directory, filename)
            frameworks.append(load_framework(filepath))
    return frameworks

def map_findings_to_compliance(findings, frameworks):
    """For each finding, identify which compliance controls failed"""
    compliance_results = []

    for framework in frameworks:
        framework_name = framework["framework"]
        failed_controls = {}

        for finding in findings:
            rule = finding["rule"]
            if rule in framework["mappings"]:
                for control in framework["mappings"][rule]:
                    control_id = control["control"]
                    if control_id not in failed_controls:
                        failed_controls[control_id] = {
                            "control": control_id,
                            "title": control["title"],
                            "requirement": control["requirement"],
                            "failures": [],
                            "triggered_by": []
                        }
                    failed_controls[control_id]["failures"].append(control["failure"])
                    failed_controls[control_id]["triggered_by"].append({
                        "rule": rule,
                        "severity": finding["severity"],
                        "timestamp": finding["event"]["timestamp"].strftime("%H:%M:%S"),
                        "actor": finding["event"]["actor"]
                    })

        # Deduplicate failures
        for control_id in failed_controls:
            failed_controls[control_id]["failures"] = list(set(failed_controls[control_id]["failures"]))

        compliance_results.append({
            "framework": framework_name,
            "failed_controls": failed_controls,
            "total_failed": len(failed_controls)
        })

    return compliance_results

def print_compliance_report(compliance_results):
    """Print compliance impact report"""
    for result in compliance_results:
        print(f"\n{'#'*60}")
        print(f" {result['framework']}")
        print(f" Failed Controls: {result['total_failed']}")
        print(f"{'#'*60}")

        for control_id, details in result["failed_controls"].items():
            print(f"\n  {control_id} — {details['title']}")
            print(f"  Requirement: {details['requirement'][:120]}...")
            print(f"  Failures:")
            for failure in details["failures"]:
                print(f"    - {failure}")
            print(f"  Evidence ({len(details['triggered_by'])} events):")
            for trigger in details["triggered_by"]:
                print(f"    [{trigger['timestamp']}] {trigger['severity']} — {trigger['rule']} by {trigger['actor']}")