import ast


def check_path_traversal(node):
    """
    Detect potentially unsafe file paths built using
    string concatenation or f-strings.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in {"open"} and node.args:

                path_argument = node.args[0]

                # Detect f-strings:
                # open(f"/var/data/{filename}")
                if isinstance(path_argument, ast.JoinedStr):
                    issues.append({
                        "rule": "PY007",
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": (
                            "File path is built using an f-string and may "
                            "be vulnerable to path traversal."
                        ),
                        "recommendation": (
                            "Validate user-controlled paths and use safe "
                            "path handling such as pathlib.Path.resolve()."
                        )
                    })

                # Detect string concatenation:
                # open("/var/data/" + filename)
                elif (
                    isinstance(path_argument, ast.BinOp)
                    and isinstance(path_argument.op, ast.Add)
                ):
                    issues.append({
                        "rule": "PY007",
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": (
                            "File path is built using string concatenation "
                            "and may be vulnerable to path traversal."
                        ),
                        "recommendation": (
                            "Validate user-controlled paths and use safe "
                            "path handling such as pathlib.Path.resolve()."
                        )
                    })

    return issues