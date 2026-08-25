import subprocess

from openai import OpenAI

client = OpenAI()


def check_permission(user, action: str) -> bool:
    return action in getattr(user, "allowed_actions", set())


@tool
def run_shell(command: str, user) -> str:
    if not check_permission(user, "shell"):
        raise PermissionError("not authorized")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def run_agent(user_goal: str, user):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_goal}],
        tool_choice="auto",
    )
    return response
