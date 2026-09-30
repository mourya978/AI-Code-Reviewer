def build_explanation_prompt(finding, code_context):
    prompt = f"""
You are a cybersecurity code-review assistant.

Analyze the security finding below and explain it clearly and accurately.

Security Rule:
{finding["rule"]}

Severity:
{finding["severity"]}

Finding:
{finding["message"]}

Recommendation:
{finding["recommendation"]}

Relevant Code:
```python
{code_context}

Provide exactly these sections:

Explanation

Explain the vulnerability in simple technical terms.

Security Impact

Explain what an attacker could potentially achieve.

Why This Code Is Risky

Explain specifically why the provided code is unsafe.

Recommended Fix

Explain how to fix the vulnerability.

Important Security Rules
Never recommend the vulnerable function or pattern as the fix.
For PY001 involving eval(), NEVER use eval() in the fix.
For eval(), recommend ast.literal_eval() for Python literals or json.loads() for JSON data.
The fix must completely remove eval().
For PY003 involving subprocess with shell=True, NEVER use shell=True in the fix.
Never execute arbitrary user input using python -c, cmd, powershell, bash, sh, or another interpreter.
For PY003, recommend an allowlist of permitted commands and pass fixed arguments as a list.
The safer example must actually remove the vulnerable pattern.
Do not claim that try/except makes a dangerous function safe.
Do not invent vulnerabilities that are not supported by the finding or code.
Safer Code Example

Provide corrected Python code that does NOT contain the vulnerable pattern.

For PY003, use a fixed allowlisted command, for example:

import subprocess

allowed_commands = {{
    "python_version": ["python", "--version"]
}}

command = allowed_commands.get("python_version")

if command:
    subprocess.run(command, check=True)
Do not use shell=True and do not execute arbitrary user input.

For PY001, use ast.literal_eval() or json.loads() as appropriate.

Keep the explanation technically accurate, practical, and concise.
"""
    return prompt