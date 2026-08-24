"""In-memory task store — the 'domain' of this toy project."""


class TaskStore:
    def __init__(self):
        self._items = []
        self._next_id = 1

    def list(self):
        return list(self._items)

    def add(self, title: str):
        task = {"id": self._next_id, "title": title, "done": False}
        self._next_id += 1
        self._items.append(task)
        return task
