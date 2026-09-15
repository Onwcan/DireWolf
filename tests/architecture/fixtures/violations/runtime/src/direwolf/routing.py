"""FIXTURE: provider names leaking out of providers/ (TX001)."""

DEFAULT_MODEL = "claude-4-opus"


def pick(task: str) -> str:
    if task == "cheap":
        return "gpt-4o-mini"
    return DEFAULT_MODEL
