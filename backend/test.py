import requests

url = 'http://localhost:8000/api/analyze/phishing'
response = requests.post(url, data={'url_or_text': ''})
print(response.status_code, response.text)
