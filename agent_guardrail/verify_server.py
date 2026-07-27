"""`agent-guardrail-serve` -- a tiny HTTP receipt-verification service.

Relying parties do not want to run Python to check a receipt. This exposes the same
`verify_receipt` logic over HTTP: the operator (or the relying party) runs the server with the policy
THEY hold, and anyone can `POST /verify` a receipt to get a signed yes/no.

    POST /verify   body: {"receipt": {...}, "witness": {...}?}   -> {"ok": bool, "reason": str, ...}
    GET  /health                                                 -> {"status": "ok"}

The server holds the policy (and optionally a pinned-key registry), so the soundness re-run and the
identity check are meaningful -- exactly the same trust model as the CLI, just reachable over HTTP.
Stdlib only; no framework.
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from .control_plane import Policy, Receipt, verify_receipt
from .registry import Registry


class _VerifyHandler(BaseHTTPRequestHandler):
    policy = None
    pinned = None
    registry = None

    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(200, {"service": "agent-guardrail-verify", "policy": self.policy.policy_id,
                             "endpoints": ["POST /verify", "GET /health"]})

    def do_POST(self):
        if self.path != "/verify":
            self._send(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n))
        except Exception:
            self._send(400, {"error": "body must be JSON"})
            return
        # accept the receipt at the top level or nested under "receipt"
        raw_receipt = payload.get("receipt", payload) if isinstance(payload, dict) else payload
        witness = payload.get("witness") if isinstance(payload, dict) else None
        try:
            receipt = Receipt.from_json(json.dumps(raw_receipt))
        except Exception as e:
            self._send(400, {"error": f"malformed receipt: {e}"})
            return

        pin = self.pinned
        if self.registry is not None and not pin:
            pin = self.registry.key_for(receipt.agent_id)
            if pin is None:
                self._send(200, {"ok": False, "reason": f"agent '{receipt.agent_id}' is not registered"})
                return

        res = verify_receipt(receipt, self.policy, pinned_public_key=pin, witness=witness)
        self._send(200, {
            "ok": res.ok, "reason": res.reason,
            "agent_id": receipt.agent_id, "policy_id": receipt.policy_id,
            "actions": len(receipt.entries),
            "blocked": sum(e.verdict == "BLOCK" for e in receipt.entries),
        })

    def log_message(self, *a):
        pass


def build_server(policy: Policy, host: str = "127.0.0.1", port: int = 8787,
                 pinned: str | None = None, registry: Registry | None = None) -> HTTPServer:
    """Create (but do not start) the HTTP server. Call `serve_forever()` on the result, or use it in a
    thread for tests."""
    handler = type("_H", (_VerifyHandler,), {"policy": policy, "pinned": pinned, "registry": registry})
    return HTTPServer((host, port), handler)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent-guardrail-serve",
                                description="Serve receipt verification over HTTP.")
    p.add_argument("--policy-id", default="default-policy", help="the policy id THIS verifier holds")
    p.add_argument("--policy-version", default="1")
    p.add_argument("--policy-spec", help="path to a PolicySpec JSON THIS verifier holds")
    p.add_argument("--pin-key", help="hex Ed25519 public key to require for all receipts")
    p.add_argument("--registry", help="path to an agent-identity registry YOU control")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    args = p.parse_args(argv)

    spec = None
    if args.policy_spec:
        from .guardrail import PolicySpec
        spec = PolicySpec.from_json(open(args.policy_spec).read())
    policy = Policy(args.policy_id, args.policy_version, spec)
    registry = Registry.load(args.registry) if args.registry else None

    srv = build_server(policy, args.host, args.port, pinned=args.pin_key, registry=registry)
    print(f"agent-guardrail-verify listening on http://{args.host}:{args.port}  "
          f"(policy {policy.policy_id}, root {policy.root()[:12]}...)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
