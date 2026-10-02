import requests

code = 'user_input = input("Enter expression: ")\nresult = eval(user_input)'

response = requests.post(
    "http://127.0.0.1:8000/analyze",
    json={"code": code},
    timeout=180
)

print(response.status_code)
print(response.text)