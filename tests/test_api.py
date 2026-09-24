from fastapi.testclient import TestClient

from api import app


client = TestClient(app)


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