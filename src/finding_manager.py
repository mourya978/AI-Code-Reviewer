SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def sort_findings(findings):
    """
    Sort findings from highest to lowest severity.
    """

    return sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(
            finding.get("severity", "INFO"),
            4
        )
    )


def count_findings(findings):
    """
    Count findings by severity.
    """

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")

        if severity in counts:
            counts[severity] += 1

    return counts
def summarize_findings(findings):
    """
    Create a summary of detected findings.
    """

    counts = count_findings(findings)

    highest_severity = "INFO"

    for severity in SEVERITY_ORDER:
        if counts[severity] > 0:
            highest_severity = severity
            break

    return {
        "total": len(findings),
        "counts": counts,
        "highest_severity": highest_severity,
    }