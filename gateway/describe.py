"""Turn a tool call into a short human-readable line, e.g. "Bash: ls -la"."""
import json

MAX_LEN = 120

# Which input field best describes each Claude Code tool.
KEY_FIELD = {
    "Bash": "command",
    "Read": "file_path",
    "Write": "file_path",
    "Edit": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
    "Glob": "pattern",
    "Grep": "pattern",
    "WebFetch": "url",
    "WebSearch": "query",
    "Task": "description",
    "Agent": "description",
}


def key_detail(call, max_len=MAX_LEN):
    """The most telling part of the tool input (e.g. the command), on one line, at most max_len chars."""
    field = KEY_FIELD.get(call.name)
    if field and field in call.input:
        detail = str(call.input[field])
    else:
        detail = json.dumps(call.input, ensure_ascii=False)
    detail = " ".join(detail.split())  # collapse newlines so it stays on one line
    if len(detail) > max_len:
        detail = detail[: max_len - 3] + "..."
    return detail


def describe(call):
    return f"{call.name}: {key_detail(call)}"
