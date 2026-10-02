\# AI Code Reviewer \& Security Linter



An AI-powered code security analysis tool that detects common security vulnerabilities, assigns severity levels, and provides AI-assisted explanations and remediation guidance.



\## 🚀 Features



\- Static security analysis of source code

\- Detection of multiple security vulnerabilities

\- Severity classification: CRITICAL, HIGH, MEDIUM, LOW, INFO

\- AI-assisted vulnerability explanations

\- Recommended fixes and safer alternatives

\- Security analysis summary

\- REST API using FastAPI

\- Automated testing with pytest

\- Modular and extensible security rules

\- Manual API testing scripts



\## 🔐 Security Rules



The project currently detects vulnerabilities such as:



\- Unsafe `eval()` usage

\- Command/subprocess security issues

\- SQL injection patterns

\- Hardcoded secrets

\- Weak cryptographic practices

\- Weak password hashing

\- Path traversal

\- Unsafe pickle usage

\- Insecure random number generation



Each finding contains:



\- Rule ID

\- Vulnerability type

\- Severity

\- Source-code line

\- Security message

\- Recommended remediation



\## 🤖 AI Explanation



The AI component provides detailed explanations for detected vulnerabilities, including:



1\. Why the code is vulnerable

2\. Potential security impact

3\. How the vulnerability could be exploited

4\. Recommended fixes

5\. Safer code examples



\## 🌐 API



The project provides a FastAPI endpoint:



`POST /analyze`



Example request:



```json

{

&#x20; "code": "user\_input = input('Enter expression: ')\\nresult = eval(user\_input)"

}



The API returns:



Total findings

Severity counts

Highest severity

Security findings

AI explanations



🏗️ Architecture



Source Code

&#x20;    │

&#x20;    ▼

Code Analyzer

&#x20;    │

&#x20;    ▼

Security Rules

&#x20;    │

&#x20;    ├── eval

&#x20;    ├── subprocess

&#x20;    ├── SQL

&#x20;    ├── secrets

&#x20;    ├── crypto

&#x20;    ├── password hashing

&#x20;    ├── path traversal

&#x20;    ├── pickle

&#x20;    └── random

&#x20;    │

&#x20;    ▼

Security Findings

&#x20;    │

&#x20;    ├──────────────┐

&#x20;    ▼              ▼

AI Explanation   Reporting

&#x20;    │              │

&#x20;    └───────┬──────┘

&#x20;            ▼

&#x20;       Final Report



🧪 Testing



Run the complete test suite:

pytest



Current result:

32 passed



📁 Project Structure



AI-Code-Reviewer/

│

├── src/

│   ├── ai/

│   │   ├── explainer.py

│   │   ├── llm\_client.py

│   │   └── prompt\_builder.py

│   │

│   ├── analyzer.py

│   ├── finding\_manager.py

│   ├── reporting.py

│   │

│   └── rules/

│       ├── command\_rule.py

│       ├── crypto\_rule.py

│       ├── eval\_rule.py

│       ├── password\_hash\_rule.py

│       ├── path\_rule.py

│       ├── pickle\_rule.py

│       ├── random\_rule.py

│       ├── secret\_rule.py

│       ├── sql\_rule.py

│       └── subprocess\_rule.py

│

├── tests/

│   ├── test\_ai.py

│   ├── test\_analyzer.py

│   └── test\_api.py

│

├── manual\_request.py

├── manual\_vulnerable.py

├── api.py

├── app.py

├── main.py

├── requirements.txt

├── pytest.ini

└── .gitignore



⚙️ Installation

git clone https://github.com/mourya978/AI-Code-Reviewer.git

cd AI-Code-Reviewer

python -m venv .venv



Windows:

.venv\\Scripts\\Activate.ps1

pip install -r requirements.txt



▶️ Running the API

uvicorn api:app --reload



API:

http://127.0.0.1:8000



Swagger documentation:

http://127.0.0.1:8000/docs



🛠️ Technology Stack

Python

FastAPI

Uvicorn

Pytest

HTTPX

Static Security Analysis

Rule-Based Vulnerability Detection

LLM/AI-Assisted Security Explanations

Git \& GitHub

🎯 Project Objective



The goal of this project is to combine traditional static security analysis with AI-powered explanations.



Traditional security linters can detect vulnerabilities, but developers may not always understand why the code is dangerous or how to fix it.



This project bridges that gap by combining automated vulnerability detection with clear, human-readable AI security explanations.



🔮 Future Improvements

GitHub Pull Request integration

GitHub Actions integration

VS Code extension

Security dashboard

CWE/CVE mapping

Support for additional programming languages

Automatic secure-code suggestions

Docker deployment

Improved vulnerability confidence scoring



👨‍💻 Author



Mourya Manjunath Gaonkar



Computer Science Engineering Student

BMS Institute of Technology and Management

