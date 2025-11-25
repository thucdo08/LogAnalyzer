from dotenv import load_dotenv
import os
from openai import OpenAI

def test_openai_ping():
    load_dotenv()
    api_key = os.getenv("OPENAI_API_KEY")
    assert api_key, "Chưa thấy OPENAI_API_KEY trong .env"

    client = OpenAI(api_key=api_key)
    r = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Say OK"}],
        temperature=0,
        max_tokens=5,
    )
    print("OpenAI says:", r.choices[0].message.content)