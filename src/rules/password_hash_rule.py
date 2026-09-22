import ast


def check_weak_password_hash(node):
    """
    Detect potentially weak password hashing using fast
    general-purpose hashing algorithms.

    The rule only flags hashes when the input appears to be
    password-related, avoiding legitimate uses such as file hashing.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "hashlib"
                and node.func.attr in {"md5", "sha1", "sha256"}
            ):

                if not node.args:
                    return issues

                hash_input = node.args[0]

                password_related = False

                # Example:
                # hashlib.sha256(password.encode())
                if isinstance(hash_input, ast.Call):
                    if isinstance(hash_input.func, ast.Attribute):
                        if (
                            hash_input.func.attr == "encode"
                            and isinstance(hash_input.func.value, ast.Name)
                            and "password" in hash_input.func.value.id.lower()
                        ):
                            password_related = True

                # Example:
                # hashlib.sha256(password)
                elif isinstance(hash_input, ast.Name):
                    if "password" in hash_input.id.lower():
                        password_related = True

                if password_related:
                    issues.append({
                        "rule": "PY010",
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": (
                            f"Password may be hashed using hashlib."
                            f"{node.func.attr}(), which is not designed "
                            "for secure password storage."
                        ),
                        "recommendation": (
                            "Use a dedicated password-hashing algorithm such "
                            "as Argon2, bcrypt, scrypt, or PBKDF2."
                        )
                    })

    return issues