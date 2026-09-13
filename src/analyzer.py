import ast

from src.rules import SECURITY_RULES


def analyze_code(code):
    """
    Analyze Python source code and return detected issues.
    """

    issues = []

    try:
        tree = ast.parse(code)
    except SyntaxError as error:
        issues.append({
            "rule": "PY000",
            "type": "syntax_error",
            "severity": "HIGH",
            "line": error.lineno,
            "message": "The Python code contains a syntax error.",
            "recommendation": "Fix the syntax error before running the code."
        })

        return issues

    for node in ast.walk(tree):

        for rule in SECURITY_RULES:
            issues.extend(rule(node))

    return issues