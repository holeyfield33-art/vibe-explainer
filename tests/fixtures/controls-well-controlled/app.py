import logging
import os

from openai import OpenAI
from pydantic import BaseModel

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


class AskRequest(BaseModel):
    question: str


def audit_log(event: str) -> None:
    logging.info(event)


def ask(payload: dict) -> str:
    request = AskRequest.model_validate(payload)
    audit_log("ai_call_started")
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[{"role": "user", "content": request.question}],
    )
    audit_log("ai_call_finished")
    return response.choices[0].message.content
