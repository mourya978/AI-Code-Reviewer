import ast


def check_insecure_pickle(node):
    """
    Detect potentially unsafe use of pickle deserialization.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "pickle"
                and node.func.attr in {"load", "loads"}
            ):
                issues.append({
                    "rule": "PY005",
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": (
                        f"Use of pickle.{node.func.attr}() can be unsafe "
                        "when processing untrusted data."
                    ),
                    "recommendation": (
                        "Avoid deserializing untrusted data with pickle. "
                        "Use a safer data format such as JSON when possible."
                    )
                })

    return issues