from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.analyzer import analyze_code
from src.finding_manager import summarize_findings
from src.ai.explainer import explain_finding_with_ai


app = FastAPI(
    title="AI Code Reviewer API",
    description="API for analyzing Python code for security issues.",
    version="1.0.0",
)
@app.exception_handler(Exception)
async def general_exception_handler(
    request: Request,
    exc: Exception
):
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred while processing the request."
        },
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

    ai_explanations = []

    for finding in findings:
        explanation = explain_finding_with_ai(
            finding,
            request.code
        )
        ai_explanations.append(explanation)

    return {
        "summary": summary,
        "findings": findings,
        "ai_explanations": ai_explanations,
    }