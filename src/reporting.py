import json


def generate_json_report(findings, summary):
    """
    Generate a machine-readable JSON security report.
    """

    report = {
        "tool": "AI Code Reviewer",
        "summary": summary,
        "findings": findings,
    }

    return json.dumps(
        report,
        indent=4
    )