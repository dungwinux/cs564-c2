import requests
import sys

url = 'https://file.io/'
data = {
    "file": open(sys.argv[1], "rb"),
}
response = requests.post(url, files=data)
res = response.json()
print(res["link"])