import subprocess

from openai import OpenAI

client = OpenAI()


def run_agent(command: str) -> str:
    plan = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": command}],
    )
    result = subprocess.run(
        plan.choices[0].message.content, shell=True, capture_output=True, text=True
    )
    return result.stdout
