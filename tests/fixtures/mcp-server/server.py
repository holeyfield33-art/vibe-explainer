from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-server")


@mcp.tool()
def get_weather(city: str) -> str:
    """Return the current weather for a city."""
    return f"Sunny in {city}"


if __name__ == "__main__":
    mcp.run()
