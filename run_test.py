import requests
import time
time.sleep(1)
try:
    response = requests.get('http://localhost:8081/events/latest')
    print("API Response:", response.json())
except Exception as e:
    print(f"Error: {e}")
