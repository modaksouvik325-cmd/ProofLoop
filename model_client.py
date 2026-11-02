
import os
import requests
from dotenv import load_dotenv
from google import genai

load_dotenv()

MODEL_PROVIDER = os.getenv("MODEL_PROVIDER", "gemini").lower()

# Ollama configuration
OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434"
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "llama3.2:3b"
)

# Gemini configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.8-flash"
)


def generate_response(messages, provider=None):

    selected_provider = (provider or MODEL_PROVIDER).lower()

    if selected_provider == "ollama":

        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False
            },
            timeout=180
        )

        response.raise_for_status()

        return response.json()["message"]["content"]

    elif selected_provider == "gemini":

        if not GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is missing from .env"
            )

        client = genai.Client(api_key=GEMINI_API_KEY)

        prompt = "\n\n".join(
            f"{message['role'].upper()}:\n{message['content']}"
            for message in messages
        )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )

        if not response.text:
            raise ValueError("Gemini returned an empty response.")

        return response.text

    else:
        raise ValueError(
            f"Unsupported model provider: {selected_provider}"
        )
