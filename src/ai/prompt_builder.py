def build_explanation_prompt(finding, code_context):
    """
    Build a structured prompt for an AI security explanation.
    """

    prompt = f"""
You are a cybersecurity code-review assistant.

Analyze the following security finding and explain it clearly
to a software developer.

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
Provide your response in the following structure:

Explanation
Security Impact
Why This Code Is Risky
Recommended Fix
Safer Code Example

Keep the explanation technically accurate and concise.

Do not invent vulnerabilities that are not supported by the finding
or the provided code.
"""
    return prompt