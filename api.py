from fastapi import FastAPI
from pydantic import BaseModel, Field

from src.analyzer import analyze_code
from src.finding_manager import summarize_findings


app = FastAPI(
    title="AI Code Reviewer API",
    description="API for analyzing Python code for security issues.",
    version="1.0.0",
)


class CodeRequest(BaseModel):
    code: str = Field(
        ...,
        min_length=1,
        max_length=100_000,
        description="Python source code to analyze."
    )


@app.get("/")
def root():
    return {
        "message": "AI Code Reviewer API is running"
    }


@app.post("/analyze")
def analyze(request: CodeRequest):
    findings = analyze_code(request.code)
    summary = summarize_findings(findings)

    return {
        "summary": summary,
        "findings": findings,
    }