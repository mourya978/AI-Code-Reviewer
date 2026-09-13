import ast


def check_sql_injection(node):
    """
    Detect potentially unsafe SQL queries built using
    string interpolation or concatenation.
    """

    issues = []

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"execute", "executemany"}:

                if not node.args:
                    return issues

                query = node.args[0]

                # Detect f-strings such as:
                # cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
                if isinstance(query, ast.JoinedStr):
                    issues.append({
                        "rule": "PY006",
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": (
                            "SQL query may be vulnerable to SQL injection "
                            "because an f-string is used to build the query."
                        ),
                        "recommendation": (
                            "Use parameterized queries with placeholders "
                            "instead of inserting variables directly into SQL."
                        )
                    })

                # Detect string concatenation such as:
                # cursor.execute("SELECT * FROM users WHERE id=" + user_id)
                elif isinstance(query, ast.BinOp) and isinstance(query.op, ast.Add):
                    issues.append({
                        "rule": "PY006",
                        "type": "security",
                        "severity": "HIGH",
                        "line": node.lineno,
                        "message": (
                            "SQL query may be vulnerable to SQL injection "
                            "because string concatenation is used to build the query."
                        ),
                        "recommendation": (
                            "Use parameterized queries with placeholders "
                            "instead of concatenating user-controlled data."
                        )
                    })

    return issues