"""Backward-compatible shim.

The MCP server now lives in the package as ``qedra.mcp_server``. Prefer the
console script after ``pip install 'qedra[mcp]'``:

    qedra-mcp

or in an MCP client config:

    "qedra": {
      "command": "qedra-mcp",
      "env": {"GUARDRAIL_WORKSPACE": "/path/to/your/repo"}
    }

This file is kept so existing configs that reference its path still work.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from qedra.mcp_server import build_server, main  # noqa: E402

# Exposed so an MCP client can also import this module and access `mcp` directly.
mcp = None
try:
    mcp = build_server()
except SystemExit:
    # The `mcp` extra is not installed; the console-script path gives a clear message.
    pass

if __name__ == "__main__":
    if mcp is not None:
        mcp.run()
    else:
        main()  # not installed with the mcp extra; raises a clear message
