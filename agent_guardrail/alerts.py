"""Ready-made block alerts for the Agent Control Plane.

`ControlPlane(..., on_block=cb)` calls `cb(action, reason)` whenever the gate blocks an action. This
module supplies drop-in callbacks so wiring an alert is one line:

    from agent_guardrail.alerts import webhook_alert
    ControlPlane(agent_id, policy, on_block=webhook_alert("https://hooks.slack.com/services/..."))

The callback is best-effort: a slow or dead endpoint never breaks the gate (the Control Plane also
guards on_block, so this is belt-and-suspenders). Uses only the standard library.
"""
from __future__ import annotations

import json
import urllib.request


def _summarize(action) -> str:
    return (getattr(action, "cmd", "") or
            f"{getattr(action, 'op', '')} {getattr(action, 'branch', '')}".strip() or
            getattr(action, "path", "") or "action")


def webhook_alert(url: str, timeout: float = 5.0):
    """Return an on_block callback that POSTs a JSON alert to `url` (Slack-compatible `text` field).
    Network failures are swallowed so alerting can never break the gate."""
    def _alert(action, reason: str) -> None:
        what = _summarize(action)
        body = json.dumps({
            "text": f"agent-guardrail BLOCKED: {what}  ({reason})",
            "verdict": "BLOCK",
            "action": what,
            "reason": reason,
        }).encode()
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=timeout).read()
        except Exception:
            pass
    return _alert
