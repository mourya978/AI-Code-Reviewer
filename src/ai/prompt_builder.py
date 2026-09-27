def build_explanation_prompt(finding, code_context):
    """
    Build a concise, structured prompt for an AI security explanation.
    """

    prompt = f"""
You are a cybersecurity code-review assistant.

Analyze the security finding below and explain it to a software developer.

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

Return the response using EXACTLY these five sections:

Explanation

Explain what the vulnerability means.
Maximum 2 sentences.

Security Impact

Explain what an attacker could achieve.
Maximum 2 sentences.

Why This Code Is Risky

Explain why the provided code triggers this finding.
Use at most 3 bullet points.

Recommended Fix

Give practical advice to fix the vulnerability.
Maximum 3 sentences.

Safer Code Example

Provide a short corrected Python example.
Maximum 12 lines of code.

Rules:

Be technically accurate.
Only discuss the vulnerability supported by the finding and code.
Do not invent additional vulnerabilities.
Keep the response under 300 words.
Do not repeat the same explanation.

Do not add any sections other than the five requested sections.
"""
    return prompt