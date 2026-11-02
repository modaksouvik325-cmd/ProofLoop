
from model_client import generate_response


messages = [
    {
        "role": "user",
        "content": "Write a Python function that adds two numbers. Return only code."
    }
]

result = generate_response(messages)

print("Model response:")
print(result)
