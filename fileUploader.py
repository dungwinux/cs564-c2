import requests
import sys

if len(sys.argv) != 2:
    sys.exit()

url = 'https://file.io/'
data = {
    "file": open(sys.argv[1], "rb"),
}
response = requests.post(url, files=data)
res = response.json()
print(res["link"])