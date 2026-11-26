#!/usr/bin/env bash
set -euo pipefail

main() {
    command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; return 1; }
    local dir="${LOCAL_COMMANDER_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/local-commander}"
    local staging
    umask 077
    mkdir -p -- "$dir"
    staging=$(mktemp -d "$dir/.install.XXXXXXXX")
    trap 'rm -rf -- "$staging"' RETURN
    cat > "$staging/server.py" <<'LOCAL_COMMANDER_PYTHON'
"""Local Commander MCP server using newline-delimited JSON-RPC over stdio."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAX_OUTPUT = 8192
PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
DEFAULT_COMMANDS = {
    "python_version": [sys.executable, "--version"],
    "git_status": ["git", "--no-optional-locks", "status", "--short", "--branch"],
}
WORKSPACE = Path(os.environ.get("LOCAL_COMMANDER_WORKSPACE", os.getcwd())).resolve()


def load_commands():
    config = os.environ.get("LOCAL_COMMANDER_CONFIG")
    if not config:
        return DEFAULT_COMMANDS
    commands = json.loads(Path(config).read_text(encoding="utf-8"))
    if not isinstance(commands, dict) or not commands:
        raise ValueError("Expected an object mapping tool names to argv arrays.")
    for name, argv in commands.items():
        if not name or not isinstance(argv, list) or not argv or not all(
            isinstance(item, str) and item and "\0" not in item for item in argv
        ):
            raise ValueError(f"Invalid command configuration for {name!r}.")
    return commands


def run_command(argv):
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.run(
                argv, cwd=WORKSPACE, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, timeout=15,
                shell=False,
            )
            status = f"Exit code {process.returncode}"
            failed = process.returncode != 0
        except subprocess.TimeoutExpired:
            status, failed = "Timed out after 15 seconds.", True
        except OSError as error:
            return {"content": [{"type": "text", "text": str(error)}], "isError": True}
        output.seek(0)
        data = output.read(MAX_OUTPUT + 1)
    message = status + "\n" + data[:MAX_OUTPUT].decode("utf-8", errors="replace")
    if len(data) > MAX_OUTPUT:
        message += "\n[Output truncated]"
    return {"content": [{"type": "text", "text": message}], "isError": failed}


def handle(request, commands):
    request_id = request.get("id")
    method = request.get("method")
    if "id" not in request:
        return None
    reply = {"jsonrpc": "2.0", "id": request_id}
    params = request.get("params", {})
    if not isinstance(params, dict):
        return {**reply, "error": {"code": -32602, "message": "Invalid parameters"}}
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {
            "protocolVersion": version if isinstance(version, str) and version in PROTOCOLS else "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "local-commander", "version": "0.1.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{
            "name": "run_local_tool",
            "description": "Run a command configured by the local machine owner in the designated workspace.",
            "inputSchema": {
                "type": "object",
                "properties": {"tool": {"type": "string", "enum": sorted(commands)}},
                "required": ["tool"],
                "additionalProperties": False,
            },
        }]}
    elif method == "tools/call":
        arguments = params.get("arguments")
        if (
            params.get("name") != "run_local_tool"
            or not isinstance(arguments, dict)
            or set(arguments) != {"tool"}
            or not isinstance(arguments["tool"], str)
            or arguments["tool"] not in commands
        ):
            return {**reply, "error": {"code": -32602, "message": "Choose a configured local tool."}}
        result = run_command(commands[arguments["tool"]])
    else:
        return {**reply, "error": {"code": -32601, "message": "Method not found"}}
    return {**reply, "result": result}


def main():
    commands = load_commands()
    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
                reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
            else:
                reply = handle(request, commands)
        if reply is not None:
            print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
LOCAL_COMMANDER_PYTHON
    cat > "$staging/connect.py" <<'LOCAL_COMMANDER_CONNECT'
"""Poll an HTTPS relay and run the built-in Local Commander tools."""

import argparse
import getpass
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from server import DEFAULT_COMMANDS, WORKSPACE, run_command


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relay", help="Origin of your Cloudflare Worker")
    args = parser.parse_args()
    origin = args.relay.rstrip("/")
    url = urlsplit(origin)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        parser.error("Provide an HTTPS origin with no path.")
    token = getpass.getpass("Relay host token: ")
    if len(token) < 32:
        parser.error("The relay host token must have at least 32 characters.")
    opener = build_opener(NoRedirects())

    def post(path, data):
        request = Request(origin + path, data=json.dumps(data).encode(), headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        })
        with opener.open(request, timeout=10) as response:
            return None if response.status == 204 else json.loads(response.read(16_384))

    print(f"Polling {origin} for tools in {WORKSPACE}. Press Ctrl-C to stop.", file=sys.stderr)
    while True:
        try:
            job = post("/host/poll", {})
            if job:
                command = DEFAULT_COMMANDS.get(job.get("tool"))
                if command is None:
                    raise ValueError("Relay returned an unknown tool.")
                if job["tool"] == "git_status":
                    command = [command[0], "-c", "core.fsmonitor=false", *command[1:]]
                result = run_command(command)
                post("/host/result", {
                    "id": job["id"],
                    "text": result["content"][0]["text"],
                    "failed": result["isError"],
                })
        except (ValueError, KeyError, URLError, TimeoutError) as error:
            print(f"Relay request failed: {error}", file=sys.stderr)
            if isinstance(error, HTTPError) and error.code in {401, 403, 404}:
                return 1
        time.sleep(5)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
LOCAL_COMMANDER_CONNECT
    python3 "$staging/connect.py" --help >/dev/null
    python3 "$staging/server.py" </dev/null
    rm -rf -- "$staging/__pycache__"
    mv -f -- "$staging/server.py" "$dir/server.py"
    mv -f -- "$staging/connect.py" "$dir/connect.py"
    printf 'Installed Local Commander. Use this MCP command with tunnel-client:\n'
    printf 'python3 %q\n' "$dir/server.py"
    printf 'For the Cloudflare relay: python3 %q https://YOUR-WORKER.workers.dev\n' "$dir/connect.py"
}
main "$@"
