from collections import Counter
import json

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def print_findings(findings):
    if not findings:
        print("No findings detected.")
        return

    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    print("\nFindings:")
    print("-" * 50)

    for finding in findings:
        print(f"[{finding.severity}] {finding.service} | {finding.resource_id}")
        print(f"Issue: {finding.issue}")
        print(f"Recommendation: {finding.recommendation}\n")

    counts = Counter(f.severity for f in findings)

    print("Summary:")
    print(f"{len(findings)} findings detected")
    for severity in ["HIGH", "MEDIUM", "LOW"]:
        if severity in counts:
            print(f"- {severity}: {counts[severity]}")

def print_json(findings):
    findings_data = [f.to_dict() for f in findings]
    print(json.dumps(findings_data, indent=2))