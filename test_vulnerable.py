import subprocess
import pickle

user_input = input("Enter command: ")
subprocess.run(user_input, shell=True)

data = input("Enter data: ")
pickle.loads(data)