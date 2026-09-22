from src.analyzer import analyze_code
from src.finding_manager import summarize_findings


code = """
password = "mypassword123"

user_input = input("Enter something: ")

result = eval(user_input)
"""


issues = analyze_code(code)
summary = summarize_findings(issues)


print("AI Code Reviewer")
print("================")
print()

print(f"Total issues: {summary['total']}")
print(f"Critical:     {summary['counts']['CRITICAL']}")
print(f"High:         {summary['counts']['HIGH']}")
print(f"Medium:       {summary['counts']['MEDIUM']}")
print(f"Low:          {summary['counts']['LOW']}")
print(f"Info:         {summary['counts']['INFO']}")
print(f"Highest:      {summary['highest_severity']}")

print()
print("Findings")
print("--------")

for issue in issues:
    print(
        f"[{issue['severity']}] "
        f"{issue['rule']} | "
        f"Line {issue['line']}: "
        f"{issue['message']}"
    )