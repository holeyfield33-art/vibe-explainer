"""Entry point for the sample task API (intentionally sparse)."""

from src.server import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5055)
