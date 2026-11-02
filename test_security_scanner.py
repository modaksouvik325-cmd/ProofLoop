from security_scanner import scan_repository

if __name__ == "__main__":
    report = scan_repository("scanner_samples")

    print("\n========== PROOFLOOP SECURITY SCAN ==========")
    print("Total findings:", report["total_findings"])

    for finding in report["findings"]:
        print("\nRule:", finding["rule_id"])
        print("Severity:", finding["severity"])
        print("File:", finding["file"])
        print("Line:", finding["line"])
        print("Description:", finding["description"])