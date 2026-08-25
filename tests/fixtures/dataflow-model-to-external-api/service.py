import requests
from openai import OpenAI

client = OpenAI()


def geocode_and_notify(address: str):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": f"Extract the city from: {address}"}],
    )
    city = response.choices[0].message.content
    requests.post("https://example.com/notify", json={"city": city})
    return city
