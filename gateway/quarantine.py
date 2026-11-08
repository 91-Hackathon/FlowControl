"""Quarantine on read (recovery 5.1): replace a poisoned source's content before the model sees it.

The agent client resends the whole conversation on every request, so a tool result the agent once
read stays in the prompt. When a source is quarantined, the gateway rewrites the request body on
*every* request, replacing the content of the tool_result blocks that came from that source with a
neutral placeholder — so the model is never (again) influenced by it.

The placeholder is plain, factual, and carries no instructions: models treat tool-result content as
untrusted data and may ignore or flag instructions placed there (threat model §5.1). Guidance to the
agent, if any, goes in a separate user-turn message, not here.

rewrite_body returns (new_body_bytes, withheld_sources). It never raises; on any parse problem it
returns the body unchanged (the response gate and egress policy are the enforcement, not this).
"""
import json


def placeholder(source):
    return f"[withheld by FlowControl gateway: quarantined source {source}]"


def rewrite_body(body, session):
    if not session.quarantined or not body:
        return body, []
    try:
        msg = json.loads(body)
    except ValueError:
        return body, []
    if not isinstance(msg, dict) or not isinstance(msg.get("messages"), list):
        return body, []
    withheld, changed = [], False
    for message in msg["messages"]:
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            source = session.quarantined_id(block.get("tool_use_id"))
            if not source:
                continue
            block["content"] = placeholder(source)
            block.pop("is_error", None)
            changed = True
            withheld.append((block.get("tool_use_id"), source))
    if not changed:
        return body, []
    return json.dumps(msg, ensure_ascii=False).encode(), withheld
