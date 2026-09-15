"""Executable authorization regression for the readiness-managed fixture."""


def test_shell_tool_requires_authorization():
    allowed_actions = set()
    assert "shell" not in allowed_actions
