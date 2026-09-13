import ast

from src.rules.eval_rule import check_eval
from src.rules.secret_rule import check_hardcoded_secret
from src.rules.subprocess_rule import check_dangerous_subprocess
from src.rules.crypto_rule import check_weak_crypto

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

        # Run eval security rule
        issues.extend(check_eval(node))

        # Run hardcoded secret rule
        issues.extend(check_hardcoded_secret(node))

        # Run dangerous subprocess rule
        issues.extend(check_dangerous_subprocess(node))

        # Run weak cryptography rule
        issues.extend(check_weak_crypto(node))
    return issues