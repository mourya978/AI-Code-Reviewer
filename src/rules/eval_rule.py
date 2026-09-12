import ast


def check_eval(node):
    """
    Detect unsafe use of eval().
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                issues.append({
                    "rule": "PY001",
                    "type": "security",
                    "severity": "HIGH",
                    "line": node.lineno,
                    "message": "Use of eval() can execute untrusted code.",
                    "recommendation": "Avoid eval(). Use safer parsing or explicit operations instead."
                })

    return issues