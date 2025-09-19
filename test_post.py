import requests

url = 'http://127.0.0.1:5006/add_item'
data = {
    "itemname": "LG Monitor",
    "itemqty": 2,
    "itemprice": 15000
}

response = requests.post(url, json=data)

print("Status Code:", response.status_code)
print("Response:", response.json())
