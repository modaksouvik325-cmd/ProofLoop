import json

from security_scanner import run_full_security_scan
from security_analyzer import analyze_security_findings


if __name__ == "__main__":
    print("Running security scan...")

    scan_report = run_full_security_scan(
        "scanner_samples",
        "requirements.txt"
    )

    print("Sending findings to AI analyst...")

    analysis = analyze_security_findings(scan_report)

    print("\n========== AI SECURITY ANALYSIS ==========")
    print(json.dumps(analysis, indent=2))