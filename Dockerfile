# Runs the qedra MCP server over stdio. Used by MCP hosts and by Glama's
# introspection check (the server starts and responds to a list-tools request).
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY qedra ./qedra
COPY integrations ./integrations

RUN pip install --no-cache-dir ".[mcp]"

ENV GUARDRAIL_WORKSPACE=/workspace
RUN mkdir -p /workspace

# stdio MCP server
CMD ["python", "integrations/mcp_server.py"]
