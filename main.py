from src.analyzer import analyze_code


code = """
password = "mypassword123"

user_input = input("Enter something: ")

result = eval(user_input)
"""


issues = analyze_code(code)


print("Code Review Results")
print("-------------------")

for issue in issues:
    print(
        f"[{issue['type'].upper()}] "
        f"Line {issue['line']}: "
        f"{issue['message']}"
    )