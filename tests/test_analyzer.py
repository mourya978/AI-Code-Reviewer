from src.analyzer import analyze_code


def test_detects_eval():
    code = """
user_input = input("Enter something: ")
result = eval(user_input)
"""

    issues = analyze_code(code)

    assert any(
        issue["type"] == "security"
        and "eval" in issue["message"]
        for issue in issues
    )


def test_detects_hardcoded_password():
    code = """
password = "mysecret123"
"""

    issues = analyze_code(code)

    assert any(
        issue["type"] == "security"
        and "password" in issue["message"].lower()
        for issue in issues
    )


def test_clean_code_has_no_security_issues():
    code = """
name = input("Enter your name: ")
print(f"Hello {name}")
"""

    issues = analyze_code(code)

    assert issues == []


def test_detects_syntax_error():
    code = """
if True
    print("Hello")
"""

    issues = analyze_code(code)

    assert any(
        issue["type"] == "syntax_error"
        for issue in issues
    )
def test_detects_dangerous_subprocess():
    code = """
import subprocess

subprocess.run(user_command, shell=True)
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY003"
        and issue["severity"] == "HIGH"
        for issue in issues
    )