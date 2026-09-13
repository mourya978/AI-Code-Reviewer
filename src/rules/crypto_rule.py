import ast


def check_weak_crypto(node):
    """
    Detect weak cryptographic hashing algorithms.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr in {"md5", "sha1"}
            ):
                algorithm = node.func.attr.upper()

                issues.append({
                    "rule": "PY004",
                    "type": "security",
                    "severity": "MEDIUM",
                    "line": node.lineno,
                    "message": f"Use of weak hashing algorithm: {algorithm}.",
                    "recommendation": (
                        "Use a stronger algorithm such as SHA-256 "
                        "or SHA-3 for security-sensitive applications."
                    )
                })

    return issues