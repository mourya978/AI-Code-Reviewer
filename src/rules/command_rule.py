import ast


def check_command_injection(node):
    """
    Detect potentially unsafe command execution using
    user-controlled input.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in {"system", "popen"}
            ):
                if node.args:
                    command = node.args[0]

                    # Detect f-strings:
                    # os.system(f"ping {host}")
                    if isinstance(command, ast.JoinedStr):
                        issues.append({
                            "rule": "PY008",
                            "type": "security",
                            "severity": "CRITICAL",
                            "line": node.lineno,
                            "message": (
                                "Command execution uses an f-string and may "
                                "be vulnerable to command injection."
                            ),
                            "recommendation": (
                                "Avoid constructing shell commands from "
                                "user-controlled data. Use subprocess with "
                                "a list of arguments and validate input."
                            )
                        })

                    # Detect string concatenation:
                    # os.system("ping " + host)
                    elif (
                        isinstance(command, ast.BinOp)
                        and isinstance(command.op, ast.Add)
                    ):
                        issues.append({
                            "rule": "PY008",
                            "type": "security",
                            "severity": "CRITICAL",
                            "line": node.lineno,
                            "message": (
                                "Command execution uses string concatenation "
                                "and may be vulnerable to command injection."
                            ),
                            "recommendation": (
                                "Avoid constructing shell commands from "
                                "user-controlled data. Use subprocess with "
                                "a list of arguments and validate input."
                            )
                        })

    return issues