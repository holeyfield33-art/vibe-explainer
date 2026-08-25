import requests
from flask import app, request


@app.route("/webhook/incoming", methods=["POST"])
def handle_webhook():
    payload = request.json
    return notify(payload)


def notify(payload: dict) -> None:
    requests.post("https://example.com/notify", json=payload)


def fetch_status() -> dict:
    resp = requests.get("https://example.com/status")
    return resp.json()
