import logging

from openai import OpenAI

logger = logging.getLogger(__name__)
client = OpenAI()


def validate(x):
    return x


def ask(question: str) -> str:
    logger.info("asking model")
    validate(question)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": question}],
    )
    return response.choices[0].message.content
