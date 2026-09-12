import ast


def check_hardcoded_secret(node):
    """
    Detect possible hardcoded passwords and secrets.
    """

    issues = []

    if isinstance(node, ast.Assign):
        for target in node.targets:

            if isinstance(target, ast.Name):
                variable_name = target.id.lower()

                if "password" in variable_name or "secret" in variable_name:
                    issues.append({
                        "rule": "PY002",
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": "Possible hardcoded password or secret.",
                        "recommendation": "Use environment variables or a secure secrets manager."
                    })

    return issues