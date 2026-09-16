"""Crash-safe output creation with explicit overwrite policy."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


class OutputExistsError(FileExistsError):
    pass


def atomic_write_text(path: str | Path, content: str, *, overwrite: bool = False) -> None:
    """Atomically publish UTF-8 text; never replace an existing file implicitly."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        if overwrite:
            os.replace(temp_name, destination)
            temp_name = None
        else:
            try:
                os.link(temp_name, destination)
            except FileExistsError as exc:
                raise OutputExistsError(
                    f"output already exists: {destination}; pass --force to replace it"
                ) from exc
            os.unlink(temp_name)
            temp_name = None
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
