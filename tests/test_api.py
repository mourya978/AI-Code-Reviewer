import pytest

from fastapi.testclient import TestClient

from api import app


client = TestClient(app)


@pytest.fixture(autouse=True)
def mock_ai_explanation(monkeypatch):
    def fake_explain_finding_with_ai(finding, code_context):
        return {
            "rule": finding["rule"],
            "severity": finding["severity"],
            "ai_explanation": (
                "Mock AI explanation for testing."
            ),
        }

    monkeypatch.setattr(
        "api.explain_finding_with_ai",
        fake_explain_finding_with_ai
    )

def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "AI Code Reviewer API is running"
    }


def test_analyze_endpoint_detects_eval():
    response = client.post(
        "/analyze",
        json={
            "code": """
user_input = input("Enter something: ")
result = eval(user_input)
"""
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["summary"]["total"] == 1
    assert data["summary"]["highest_severity"] == "HIGH"

    assert data["findings"][0]["rule"] == "PY001"
    assert data["findings"][0]["severity"] == "HIGH"
    assert len(data["ai_explanations"]) == 1
    assert data["ai_explanations"][0]["rule"] == "PY001"
    assert data["ai_explanations"][0]["severity"] == "HIGH"
    assert "Mock AI explanation" in data["ai_explanations"][0]["ai_explanation"]


def test_analyze_endpoint_clean_code():
    response = client.post(
        "/analyze",
        json={
            "code": """
name = input("Enter your name: ")
print(f"Hello {name}")
"""
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["summary"]["total"] == 0
    assert data["findings"] == []


def test_analyze_endpoint_rejects_empty_code():
    response = client.post(
        "/analyze",
        json={
            "code": ""
        }
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_oversized_code():
    large_code = "a" * 100001

    response = client.post(
        "/analyze",
        json={
            "code": large_code
        }
    )

    assert response.status_code == 422

    
def test_api_handles_unexpected_errors(monkeypatch):
    from fastapi.testclient import TestClient
    from api import app

    def raise_error(code):
        raise RuntimeError("test error")

    monkeypatch.setattr("api.analyze_code", raise_error)

    test_client = TestClient(
        app,
        raise_server_exceptions=False
    )

    response = test_client.post(
        "/analyze",
        json={
            "code": "print('hello')"
        }
    )

    assert response.status_code == 500

    data = response.json()

    assert data["error"] == "Internal server error"
    assert data["message"] == (
        "An unexpected error occurred while processing the request."
    )