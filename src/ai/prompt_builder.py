def build_explanation_prompt(finding, code_context):
    """
    Build a structured prompt for an AI security explanation.
    """

    prompt = f"""
You are a cybersecurity code-review assistant.

Analyze the security finding below and explain it clearly to a software developer.

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
Provide your response using exactly these sections:

Explanation

Explain the vulnerability in simple technical terms.

Security Impact

Explain what an attacker could potentially achieve.

Why This Code Is Risky

Explain specifically why the provided code is unsafe.

Recommended Fix

Explain how to fix the vulnerability.

IMPORTANT:

Never recommend the vulnerable function or pattern as the fix.
For PY001 involving eval(), NEVER use eval() in the recommended fix.
For eval(), recommend ast.literal_eval() for Python literals or json.loads() for JSON data.
The recommended fix must actually remove the vulnerable use of eval().
Do not claim that eval() becomes safe merely by putting it inside try/except.
Do not invent vulnerabilities that are not supported by the finding or code.
Safer Code Example

Provide a corrected Python example that does NOT contain the vulnerable pattern.

Keep the explanation technically accurate, practical, and concise.
"""
    return prompt