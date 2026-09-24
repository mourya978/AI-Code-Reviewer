def explain_finding(finding):
    """
    Generate an explanation for a security finding.

    This is the interface that will later connect
    to an actual LLM.
    """

    return {
        "rule": finding["rule"],
        "severity": finding["severity"],
        "explanation": finding["message"],
        "recommendation": finding["recommendation"],
    }