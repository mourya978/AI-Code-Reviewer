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
def test_detects_sql_injection_f_string():
    code = """
import sqlite3

user_id = input("Enter user ID: ")

cursor.execute(
    f"SELECT * FROM users WHERE id={user_id}"
)
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY006"
        and issue["severity"] == "HIGH"
        for issue in issues
    )


def test_allows_parameterized_sql_query():
    code = """
import sqlite3

user_id = input("Enter user ID: ")

cursor.execute(
    "SELECT * FROM users WHERE id=?",
    (user_id,)
)
"""

    issues = analyze_code(code)

    assert not any(
        issue["rule"] == "PY006"
        for issue in issues
    )
def test_detects_path_traversal_f_string():
    code = """
filename = input("Enter filename: ")

with open(f"/var/data/{filename}", "r") as file:
    data = file.read()
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY007"
        and issue["severity"] == "HIGH"
        for issue in issues
    )


def test_allows_safe_static_file_path():
    code = """
with open("/var/data/config.json", "r") as file:
    data = file.read()
"""

    issues = analyze_code(code)

    assert not any(
        issue["rule"] == "PY007"
        for issue in issues
    )
def test_detects_command_injection_f_string():
    code = """
import os

host = input("Enter host: ")

os.system(f"ping {host}")
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY008"
        and issue["severity"] == "CRITICAL"
        for issue in issues
    )


def test_allows_static_os_command():
    code = """
import os

os.system("whoami")
"""

    issues = analyze_code(code)

    assert not any(
        issue["rule"] == "PY008"
        for issue in issues
    )
def test_detects_insecure_random():
    code = """
import random

token = random.randint(100000, 999999)
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY009"
        and issue["severity"] == "MEDIUM"
        for issue in issues
    )


def test_allows_secrets_module():
    code = """
import secrets

token = secrets.randbelow(900000)
"""

    issues = analyze_code(code)

    assert not any(
        issue["rule"] == "PY009"
        for issue in issues
    )    
def test_detects_weak_password_hash():
    code = """
import hashlib

password_hash = hashlib.sha256(password.encode()).hexdigest()
"""

    issues = analyze_code(code)

    assert any(
        issue["rule"] == "PY010"
        and issue["severity"] == "HIGH"
        for issue in issues
    )


def test_allows_sha256_for_non_password_use():
    code = """
import hashlib

file_hash = hashlib.sha256(file_data).hexdigest()
"""

    issues = analyze_code(code)

    assert not any(
        issue["rule"] == "PY010"
        for issue in issues
    )
def test_summarize_findings():
    from src.finding_manager import summarize_findings

    findings = [
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "HIGH"},
        {"severity": "CRITICAL"},
    ]

    summary = summarize_findings(findings)

    assert summary["total"] == 4
    assert summary["counts"]["CRITICAL"] == 1
    assert summary["counts"]["HIGH"] == 2
    assert summary["counts"]["MEDIUM"] == 1
    assert summary["counts"]["LOW"] == 0
    assert summary["counts"]["INFO"] == 0
    assert summary["highest_severity"] == "CRITICAL"