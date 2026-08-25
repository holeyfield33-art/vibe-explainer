import requests

WEBHOOK_URL = "https://example.com/webhook"


def notify(payload: dict) -> None:
    requests.post(WEBHOOK_URL, json=payload)


def fetch_status() -> dict:
    resp = requests.get("https://example.com/status")
    return resp.json()
