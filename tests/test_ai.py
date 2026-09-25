from src.ai import llm_client


def test_generate_response(monkeypatch):
    def fake_chat(model, messages):
        assert model == "qwen2.5-coder:7b"
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "Explain eval."

        return {
            "message": {
                "content": "eval() can execute untrusted code."
            }
        }

    monkeypatch.setattr(
        llm_client.ollama,
        "chat",
        fake_chat
    )

    response = llm_client.generate_response(
        "Explain eval."
    )

    assert response == "eval() can execute untrusted code."
def test_explain_finding_with_ai(monkeypatch):
    from src.ai.explainer import explain_finding_with_ai

    finding = {
        "rule": "PY001",
        "severity": "HIGH",
        "message": "Use of eval() can execute untrusted code.",
        "recommendation": "Avoid eval().",
    }

    def fake_generate_response(prompt):
        assert "PY001" in prompt
        assert "HIGH" in prompt
        assert "eval()" in prompt

        return "eval() can execute untrusted input and should be avoided."

    monkeypatch.setattr(
        "src.ai.explainer.generate_response",
        fake_generate_response
    )

    result = explain_finding_with_ai(
        finding,
        "result = eval(user_input)"
    )

    assert result["rule"] == "PY001"
    assert result["severity"] == "HIGH"
    assert "eval()" in result["ai_explanation"]