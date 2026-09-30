import requests

code = '''import subprocess
subprocess.run("echo test", shell=True)'''

response = requests.post(
    "http://127.0.0.1:8000/analyze",
    json={"code": code},
    timeout=180
)

print(response.status_code)
print(response.text)