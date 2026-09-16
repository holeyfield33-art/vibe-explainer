"""Synthetic AI application used only to demonstrate current report structure."""

import os
from openai import OpenAI

SYSTEM_PROMPT = "Answer only from approved context."
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def answer(question: str) -> str:
    response = client.chat.completions.create(
        model="example-model",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
    )
    return response.choices[0].message.content
