import ast


def check_insecure_random(node):
    """
    Detect use of the standard random module for
    potentially security-sensitive random values.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "random"
                and node.func.attr in {
                    "random",
                    "randint",
                    "randrange",
                    "choice",
                    "choices",
                }
            ):
                issues.append({
                    "rule": "PY009",
                    "type": "security",
                    "severity": "MEDIUM",
                    "line": node.lineno,
                    "message": (
                        f"Use of random.{node.func.attr}() may be insecure "
                        "for security-sensitive values."
                    ),
                    "recommendation": (
                        "Use Python's secrets module for security-sensitive "
                        "random values such as tokens, passwords, or "
                        "authentication codes."
                    )
                })

    return issues