from openai import OpenAI

client = OpenAI()


def run_agent(user_goal: str):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_goal}],
        tool_choice="auto",
    )
    return response
