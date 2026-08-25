import subprocess

from openai import OpenAI

client = OpenAI()


@tool
def run_shell(command: str) -> str:
    """Execute a shell command and return its output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def run_agent(user_goal: str):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_goal}],
        tool_choice="auto",
    )
    return response
