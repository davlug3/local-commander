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
"""Sign in through the browser, then run the built-in Local Commander tools."""

import argparse
import base64
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import select
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser

from server import DEFAULT_COMMANDS, WORKSPACE, run_command


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OAuth:
    def __init__(self, origin):
        self.origin = origin
        self.resource = origin + "/mcp"
        self.opener = build_opener(NoRedirects())

    def post(self, path, data, access_token=None, form=False):
        headers = {"User-Agent": "LocalCommander/0.3", "Accept": "application/json"}
        if access_token:
            headers["Authorization"] = "Bearer " + access_token
        if form:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(data).encode()
        else:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        request = Request(self.origin + path, data=body, headers=headers)
        with self.opener.open(request, timeout=10) as response:
            return None if response.status == 204 else json.loads(response.read(65_536))

    def sign_in(self):
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).decode().rstrip("=")
        callback = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                url = urlsplit(self.path)
                values = parse_qs(url.query)
                if url.path != "/callback" or values.get("state") != [state]:
                    self.send_error(400, "Invalid sign-in callback")
                    return
                callback.update(values)
                self.send_response(200)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Return to your Local Commander terminal.")

        with HTTPServer(("127.0.0.1", 0), Handler) as listener:
            listener.timeout = 1
            redirect = f"http://127.0.0.1:{listener.server_port}/callback"
            registration = self.post("/register", {
                "client_name": "Local Commander host",
                "redirect_uris": [redirect],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            })
            self.client_id = registration["client_id"]
            login = self.origin + "/authorize?" + urlencode({
                "client_id": self.client_id, "redirect_uri": redirect, "resource": self.resource,
                "response_type": "code", "scope": "host:connect", "state": state,
                "code_challenge": challenge, "code_challenge_method": "S256",
            })
            print("Open this URL in a browser on this computer:", login, file=sys.stderr)
            webbrowser.open(login)
            deadline = time.monotonic() + 300
            while not callback and time.monotonic() < deadline:
                listener.handle_request()

        if len(callback.get("code", [])) != 1 or callback.get("iss") != [self.origin]:
            raise ValueError("Sign-in was denied, timed out, or returned an invalid issuer.")
        return self.post("/token", {
            "grant_type": "authorization_code", "client_id": self.client_id,
            "redirect_uri": redirect, "code": callback["code"][0], "code_verifier": verifier,
            "resource": self.resource,
        }, form=True)

    def refresh(self, tokens):
        if not tokens.get("refresh_token"):
            return self.sign_in()
        return self.post("/token", {
            "grant_type": "refresh_token", "client_id": self.client_id,
            "refresh_token": tokens["refresh_token"], "resource": self.resource,
        }, form=True)


def tool_result(text, failed=False):
    return {"content": [{"type": "text", "text": text}], "isError": failed}


def run_job(job, allow_shell, poll_started, session_approvals, approve_all=False):
    tool = job.get("tool")
    if tool == "run_shell_command":
        if not allow_shell:
            return tool_result("Restart the host client with --allow-shell to approve shell commands.", True)
        command = job.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 8192 or "\0" in command:
            return tool_result("Invalid shell command.", True)
        permission = job.get("permission", "session" if approve_all else "once")
        if permission not in ("once", "session"):
            return tool_result("Invalid permission level.", True)
        remaining = job.get("remainingMs", 0)
        if not isinstance(remaining, int):
            return tool_result("Invalid approval deadline.", True)
        deadline = poll_started + remaining / 1000 - 20
        wait = min(40, deadline - time.monotonic())
        if wait <= 0:
            return tool_result("Command approval expired.", True)
        argv = ["/bin/bash", "--noprofile", "--norc", "-c", command]
        if permission == "session" and (approve_all or command in session_approvals):
            print(f"Running approved shell command in {json.dumps(str(WORKSPACE))}: "
                  f"{json.dumps(command)}", file=sys.stderr, flush=True)
            return run_command(argv)
        approval = "yes " + secrets.token_hex(3)
        scope = "once" if permission == "once" else "this exact command for the current session"
        try:
            with open("/dev/tty", encoding="utf-8") as terminal:
                print(f"\nLocal Commander shell request in {json.dumps(str(WORKSPACE))}\n"
                      f"{json.dumps(command)}\n"
                      f"Type {approval} to approve {scope} and share the output: ",
                      file=sys.stderr, flush=True)
                ready, _, _ = select.select([terminal], [], [], max(0, min(wait, deadline - time.monotonic())))
                if not ready or terminal.readline().strip() != approval or time.monotonic() >= deadline:
                    return tool_result("Command denied or approval expired.", True)
        except OSError:
            return tool_result("Local approval requires an interactive terminal.", True)
        if permission == "session":
            session_approvals.add(command)
        return run_command(argv)
    command = DEFAULT_COMMANDS.get(tool)
    if command is None:
        return tool_result("Unknown local tool.", True)
    if tool == "git_status":
        command = [command[0], "-c", "core.fsmonitor=false", *command[1:]]
    return run_command(command)


def confirm_session_shell(origin):
    phrase = "approve all " + secrets.token_hex(3)
    try:
        with open("/dev/tty", encoding="utf-8") as terminal:
            print(f"Session-wide shell access for {origin}\n"
                  f"Starting directory: {json.dumps(str(WORKSPACE))}\n"
                  "Authorized clients can run any Bash command as your user using the host default or session approval "
                  "until you stop this client.\n"
                  f"Type {phrase} to enable it: ", file=sys.stderr, flush=True)
            return terminal.readline().strip() == phrase
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relay", help="Origin of your Cloudflare Worker")
    parser.add_argument("--allow-shell", action="store_true", help="Enable shell requests with local approval")
    parser.add_argument("--approve-all-session", action="store_true",
                        help="Confirm once locally to approve commands using the host default or session approval until this client exits")
    args = parser.parse_args()
    if args.approve_all_session and not args.allow_shell:
        parser.error("--approve-all-session requires --allow-shell")
    url = urlsplit(args.relay.rstrip("/"))
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        parser.error("Provide an HTTPS origin with no path.")
    origin = f"https://{url.netloc.lower()}"
    oauth = OAuth(origin)
    if args.approve_all_session and not confirm_session_shell(origin):
        sys.exit("Session-wide shell access was not approved.")
    tokens = oauth.sign_in()
    session_approvals = set()
    print(f"Signed in. Polling {origin} for tools in {WORKSPACE}. Press Ctrl-C to stop.", file=sys.stderr)
    while True:
        try:
            poll_started = time.monotonic()
            job = oauth.post("/mcp/host/poll", {}, tokens["access_token"])
            if job:
                result = run_job(job, args.allow_shell, poll_started, session_approvals, args.approve_all_session)
                oauth.post("/mcp/host/result", {
                    "id": job["id"],
                    "text": result["content"][0]["text"],
                    "failed": result["isError"],
                }, tokens["access_token"])
        except HTTPError as error:
            if error.code == 401:
                session_approvals.clear()
                tokens = oauth.refresh(tokens)
                continue
            if error.code in {403, 404}:
                raise
            print(f"Relay request failed: {error}", file=sys.stderr)
        except (ValueError, KeyError, URLError, TimeoutError) as error:
            print(f"Relay request failed: {error}", file=sys.stderr)
        time.sleep(5)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except (ValueError, KeyError, URLError, TimeoutError) as error:
        sys.exit(f"Local Commander: {error}")
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
