from flask import Flask, jsonify, request

from .tasks import TaskStore


def create_app():
    app = Flask(__name__)
    store = TaskStore()

    @app.get("/health")
    def health():
        return jsonify({"ok": True})

    @app.get("/tasks")
    def list_tasks():
        return jsonify(store.list())

    @app.post("/tasks")
    def add_task():
        data = request.get_json(force=True, silent=True) or {}
        title = data.get("title") or "untitled"
        task = store.add(title)
        return jsonify(task), 201

    return app
