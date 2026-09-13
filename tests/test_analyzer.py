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
def test_detects_md5():
    code = """
import hashlib

hashlib.md5(data)
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY004"
        and "MD5" in issue["message"]
        for issue in issues
    )


def test_detects_sha1():
    code = """
import hashlib

hashlib.sha1(data)
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY004"
        and "SHA1" in issue["message"]
        for issue in issues
    )
def test_allows_sha256():
    code = """
import hashlib

hashlib.sha256(data)
"""

    issues = analyze_code(code)

    assert not any(
        issue["rule"] == "PY004"
        for issue in issues
    )
def test_detects_insecure_pickle():
    code = """
import pickle

data = pickle.loads(untrusted_data)
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY005"
        and issue["severity"] == "HIGH"
        for issue in issues
    )


def test_findings_are_sorted_by_severity():
    code = """
import hashlib
import pickle
import subprocess

password = "secret123"

hashlib.md5(data)

subprocess.run(command, shell=True)

pickle.loads(data)
"""

    issues = analyze_code(code)

    severities = [issue["severity"] for issue in issues]

    assert severities == [
        "HIGH",
        "HIGH",
        "HIGH",
        "MEDIUM",
    ]