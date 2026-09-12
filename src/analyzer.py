import ast


def analyze_code(code):
    """
    Analyze Python source code and return detected issues.
    """

    issues = []

    try:
        tree = ast.parse(code)
    except SyntaxError as error:
        issues.append({
            "type": "syntax_error",
            "line": error.lineno,
            "message": "The Python code contains a syntax error."
        })

        return issues

    for node in ast.walk(tree):

        # Detect eval()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    issues.append({
                        "type": "security",
                        "line": node.lineno,
                        "message": "Use of eval() can execute untrusted code."
                    })

        # Detect hardcoded passwords
        if isinstance(node, ast.Assign):
            for target in node.targets:

                if isinstance(target, ast.Name):
                    variable_name = target.id.lower()

                    if "password" in variable_name or "secret" in variable_name:
                        issues.append({
                            "type": "security",
                            "line": node.lineno,
                            "message": "Possible hardcoded password or secret."
                        })

    return issues