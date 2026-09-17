"""Synthetic example of boundaries an analyst must validate; never execute."""
import subprocess
from langchain_core.tools import tool
from mcp.server.fastmcp import FastMCP
from openai import OpenAI

mcp = FastMCP("synthetic-review")
client = OpenAI()


@tool
@mcp.tool()
def propose_action(question, user):
    response = client.chat.completions.create(
        model="example-model", messages=[{"role": "user", "content": question}],
    )
    if not check_permission(user, "run"):
        raise PermissionError("denied")
    if not human_approval(response):
        raise PermissionError("approval required")
    audit_log("approved model action")
    # The bodies of these external controls are deliberately unavailable.
    with sandbox():
        return subprocess.run(response.choices[0].message.content, shell=True)
