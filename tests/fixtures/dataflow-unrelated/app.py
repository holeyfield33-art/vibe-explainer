from openai import OpenAI

client = OpenAI()

SYSTEM_PROMPT = "You are an unrelated assistant far from the call site."

# padding line 0 - unrelated code below, not connected to the prompt above
# padding line 1 - unrelated code below, not connected to the prompt above
# padding line 2 - unrelated code below, not connected to the prompt above
# padding line 3 - unrelated code below, not connected to the prompt above
# padding line 4 - unrelated code below, not connected to the prompt above
# padding line 5 - unrelated code below, not connected to the prompt above
# padding line 6 - unrelated code below, not connected to the prompt above
# padding line 7 - unrelated code below, not connected to the prompt above
# padding line 8 - unrelated code below, not connected to the prompt above
# padding line 9 - unrelated code below, not connected to the prompt above
# padding line 10 - unrelated code below, not connected to the prompt above
# padding line 11 - unrelated code below, not connected to the prompt above
# padding line 12 - unrelated code below, not connected to the prompt above
# padding line 13 - unrelated code below, not connected to the prompt above
# padding line 14 - unrelated code below, not connected to the prompt above
# padding line 15 - unrelated code below, not connected to the prompt above
# padding line 16 - unrelated code below, not connected to the prompt above
# padding line 17 - unrelated code below, not connected to the prompt above
# padding line 18 - unrelated code below, not connected to the prompt above
# padding line 19 - unrelated code below, not connected to the prompt above
# padding line 20 - unrelated code below, not connected to the prompt above
# padding line 21 - unrelated code below, not connected to the prompt above
# padding line 22 - unrelated code below, not connected to the prompt above
# padding line 23 - unrelated code below, not connected to the prompt above
# padding line 24 - unrelated code below, not connected to the prompt above
# padding line 25 - unrelated code below, not connected to the prompt above
# padding line 26 - unrelated code below, not connected to the prompt above
# padding line 27 - unrelated code below, not connected to the prompt above
# padding line 28 - unrelated code below, not connected to the prompt above
# padding line 29 - unrelated code below, not connected to the prompt above
# padding line 30 - unrelated code below, not connected to the prompt above
# padding line 31 - unrelated code below, not connected to the prompt above
# padding line 32 - unrelated code below, not connected to the prompt above
# padding line 33 - unrelated code below, not connected to the prompt above
# padding line 34 - unrelated code below, not connected to the prompt above
# padding line 35 - unrelated code below, not connected to the prompt above
# padding line 36 - unrelated code below, not connected to the prompt above
# padding line 37 - unrelated code below, not connected to the prompt above
# padding line 38 - unrelated code below, not connected to the prompt above
# padding line 39 - unrelated code below, not connected to the prompt above

def ask(question: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": question}],
    )
    return response.choices[0].message.content
