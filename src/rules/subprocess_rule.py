import ast


def check_dangerous_subprocess(node):
    """
    Detect potentially dangerous subprocess usage.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        issues.append({
                            "rule": "PY003",
                            "type": "security",
                            "severity": "HIGH",
                            "line": node.lineno,
                            "message": "subprocess is being used with shell=True.",
                            "recommendation": (
                                "Avoid shell=True when possible. "
                                "Pass commands as a list of arguments instead."
                            )
                        })

    return issues