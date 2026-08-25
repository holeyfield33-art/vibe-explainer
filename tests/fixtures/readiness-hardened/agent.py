import logging

from openai import OpenAI

client = OpenAI()


def check_permission(user, action: str) -> bool:
    return action in getattr(user, "allowed_actions", set())


def audit_log(event: str) -> None:
    logging.info(event)


@tool
def run_shell(command: str, user) -> str:
    if not check_permission(user, "shell"):
        raise PermissionError("not authorized")
    audit_log("shell_tool_invoked")
    import subprocess
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def run_agent(user_goal: str, user):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_goal}],
        tool_choice="auto",
    )
    return response
