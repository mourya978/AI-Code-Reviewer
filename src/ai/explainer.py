from src.ai.llm_client import generate_response
from src.ai.prompt_builder import build_explanation_prompt


def explain_finding(finding):
    """
    Generate a basic explanation for a security finding.
    """

    return {
        "rule": finding["rule"],
        "severity": finding["severity"],
        "explanation": finding["message"],
        "recommendation": finding["recommendation"],
    }


def explain_finding_with_ai(finding, code_context):
    """
    Generate an AI-powered explanation for a security finding.
    """

    prompt = build_explanation_prompt(
        finding,
        code_context
    )

    response = generate_response(prompt)

    return {
        "rule": finding["rule"],
        "severity": finding["severity"],
        "ai_explanation": response,
    }