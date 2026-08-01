#!/usr/bin/env bash
# One command, no install beyond qedra itself: watch a hijacked Claude Code session
# get gated by qedra in real time, then see the signed receipt verified and a forged
# one rejected. Uses the REAL production hook (qedra.claude_code_hook) — not a mock.
#
#   ./claude-integration.sh
#
# Reviewer-friendly: no API key, no network, runs in ~1s.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! python3 -c "import qedra" 2>/dev/null; then
  echo "qedra not importable. Install it first:  pip install -e ." >&2
  exit 1
fi

exec python3 demo_claude_hook.py
