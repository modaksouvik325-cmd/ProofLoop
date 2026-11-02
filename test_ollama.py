import requests

response = requests.post(
    "http://localhost:11434/api/chat",
    json={
        "model": "llama3.2:1b",
        "messages": [
            {
                "role": "user",
                "content": "Write a Python function called add that accepts two numbers and returns their sum. Return only the code."
            }
        ],
        "stream": False
    }
)

print(response.json()["message"]["content"])