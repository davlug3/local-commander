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
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json
import os
import signal
import shutil
import subprocess
import tempfile
from threading import RLock, Thread
from uuid import uuid4
import select
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser

from server import DEFAULT_COMMANDS, WORKSPACE, run_command


def terminal_message(title, *lines, color="36"):
    stream = sys.stderr
    colored = stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    heading = f"\x1b[1;{color}m{title}\x1b[0m" if colored else title
    divider = "-" * 40
    print("\n" + heading, divider, *lines, divider, sep="\n", file=stream, flush=True)


def terminal_result(title, result, *details):
    text = result["content"][0]["text"]
    safe_text = "".join(
        char if char.isprintable() or char in "\n\t" else ascii(char)[1:-1]
        for char in text
    )
    terminal_message(title, *details, "", safe_text.rstrip("\n") or "(No output)",
                     color="31" if result["isError"] else "32")


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def open_sign_in_browser(url):
    termux_opener = shutil.which("termux-open-url")
    if termux_opener:
        try:
            result = subprocess.run([termux_opener, url], check=False, timeout=5)
            if result.returncode == 0:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        webbrowser.open(url)
    except webbrowser.Error:
        pass


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
            terminal_message("Local Commander | Sign in", "Open this URL on this device:", login)
            open_sign_in_browser(login)
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


JOB_CONSOLE = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Commander · Job console</title>
<style>
:root { color-scheme: dark; background: #101918; color: #e5f3ef; font: 16px system-ui, sans-serif; }
main { max-width: 76rem; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.4rem; }
#state { color: #afe5d1; }
pre { min-height: 50vh; border: 1px solid #456258; border-radius: .6rem; padding: 1rem;
      background: #0b1211; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
<main>
<h1>Local Commander · Job console</h1>
<p id="state" role="status">Connecting…</p>
<pre id="output" tabindex="0" aria-label="Command output"></pre>
</main>
<script>
const state = document.querySelector("#state");
const output = document.querySelector("#output");
async function refresh() {
  try {
    const response = await fetch(location.pathname + "/status", { cache: "no-store" });
    if (response.status === 404) {
      state.textContent = "This job is no longer available.";
      return;
    }
    if (!response.ok) throw new Error("Request failed");
    const result = await response.json();
    const following = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 24;
    if (state.textContent !== result.state) state.textContent = result.state;
    if (output.textContent !== result.output) output.textContent = result.output;
    if (following) window.scrollTo(0, document.documentElement.scrollHeight);
    if (result.state !== "Running") return;
  } catch {
    state.textContent = "Connection lost. Reconnecting…";
  }
  setTimeout(refresh, 1000);
}
refresh();
</script>
</html>"""


def start_job_console(jobs):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            host = f"127.0.0.1:{self.server.server_port}"
            parts = self.path.split("/")
            if (self.headers.get("Host") != host or len(parts) not in (3, 4)
                    or parts[:2] != ["", "jobs"] or (len(parts) == 4 and parts[3] != "status")):
                self.send_error(404)
                return
            result = jobs.snapshot(parts[2])
            if result is None:
                self.send_error(404)
                return
            if len(parts) == 4:
                state, output, _ = result
                body = json.dumps({"state": state, "output": output})
                content_type = "application/json"
            else:
                body = JOB_CONSOLE
                content_type = "text/html; charset=utf-8"
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                             "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(payload)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except OSError:
        terminal_message("Live job console unavailable", "Could not open a localhost port.", color="33")
        return None
    Thread(target=server.serve_forever, daemon=True).start()
    return server


class ShellJobs:
    def __init__(self):
        self.jobs = {}
        self.reported = set()
        self.lock = RLock()
        self.console = None

    def start(self, argv):
        with self.lock:
            return self.start_job(argv)

    def start_job(self, argv):
        if len(self.jobs) >= 16:
            for job_id, (process, output) in self.jobs.items():
                if process.poll() is not None:
                    self.report_completed()
                    output.close()
                    self.reported.discard(job_id)
                    del self.jobs[job_id]
                    break
            else:
                return tool_result("All 16 background job slots are busy.", True)
        output = tempfile.TemporaryFile()
        try:
            process = subprocess.Popen(
                argv, cwd=WORKSPACE, stdin=subprocess.DEVNULL, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True,
            )
        except OSError as error:
            output.close()
            return tool_result(f"Could not start background command: {error}", True)
        job_id = uuid4().hex
        self.jobs[job_id] = (process, output)
        details = [f"Job ID: {job_id}"]
        if self.console:
            details.extend(("", f"Live console: http://127.0.0.1:{self.console.server_port}/jobs/{job_id}"))
        terminal_message("Background job started", *details, color="32")
        return tool_result(f"Background job started. Job ID: {job_id}")

    def snapshot(self, job_id):
        with self.lock:
            if not isinstance(job_id, str) or job_id not in self.jobs:
                return None
            process, output = self.jobs[job_id]
            code = process.poll()
            size = os.fstat(output.fileno()).st_size
            tail = os.pread(output.fileno(), 8192, max(0, size - 8192))
        summary = "Running" if code is None else f"Finished with exit code {code}"
        text = tail.decode("utf-8", errors="replace")
        if size > 8192:
            text = "[Showing the last 8192 bytes]\n" + text
        return summary, text, code not in (None, 0)

    def status(self, job_id):
        result = self.snapshot(job_id)
        if result is None:
            return tool_result("Unknown background job in this client session.", True)
        summary, output, failed = result
        return tool_result(summary + "\n" + output, failed)

    def report_completed(self):
        for job_id, (process, _) in self.jobs.items():
            if job_id not in self.reported and process.poll() is not None:
                terminal_result("Background job finished", self.status(job_id), f"Job ID: {job_id}")
                self.reported.add(job_id)

    def close(self):
        if self.console:
            self.console.shutdown()
            self.console.server_close()
        with self.lock:
            self.close_jobs()

    def close_jobs(self):
        for process, output in self.jobs.values():
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            output.close()
        self.jobs.clear()


def run_job(job, allow_shell, poll_started, session_approvals, approve_all=False, jobs=None):
    tool = job.get("tool")
    if tool == "get_shell_job_status":
        return jobs.status(job.get("job_id"))
    if tool == "run_shell_command":
        if not allow_shell:
            return tool_result("Restart the host client with --allow-shell to approve shell commands.", True)
        command = job.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 8192 or "\0" in command:
            return tool_result("Invalid shell command.", True)
        mode = job.get("mode", "foreground")
        if mode not in ("foreground", "background"):
            return tool_result("Invalid shell execution mode.", True)
        execute = jobs.start if mode == "background" else run_command
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
        bash = shutil.which("bash")
        if not bash:
            return tool_result("Bash was not found on the host PATH.", True)
        argv = [bash, "--noprofile", "--norc", "-c", command]
        if permission == "session" and (approve_all or command in session_approvals):
            terminal_message("Running approved shell command",
                             f"Mode: {mode}", f"Workspace: {json.dumps(str(WORKSPACE))}",
                             f"Command: {json.dumps(command)}", color="32")
            return execute(argv)
        approval = "yes " + secrets.token_hex(3)
        scope = "once" if permission == "once" else "this exact command for the current session"
        try:
            with open("/dev/tty", encoding="utf-8") as terminal:
                terminal_message("Shell approval required", f"Mode: {mode}",
                                 f"Workspace: {json.dumps(str(WORKSPACE))}",
                                 f"Command: {json.dumps(command)}", "",
                                 f"Type {approval} to approve {scope} and share the output.", color="33")
                ready, _, _ = select.select([terminal], [], [], max(0, min(wait, deadline - time.monotonic())))
                if not ready or terminal.readline().strip() != approval or time.monotonic() >= deadline:
                    return tool_result("Command denied or approval expired.", True)
        except OSError:
            return tool_result("Local approval requires an interactive terminal.", True)
        if permission == "session":
            session_approvals.add(command)
        return execute(argv)
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
            terminal_message("Session-wide shell approval", f"Relay: {origin}",
                             f"Workspace: {json.dumps(str(WORKSPACE))}", "",
                             "Authorized clients can run any Bash command as your user using",
                             "the host default or session approval until you stop this client.", "",
                             f"Type {phrase} to enable it.", color="33")
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
    terminal_message("Signed in. Polling for tools", f"Relay: {origin}",
                     f"Workspace: {json.dumps(str(WORKSPACE))}", "Press Ctrl-C to stop.", color="32")
    jobs = ShellJobs()
    if args.allow_shell:
        jobs.console = start_job_console(jobs)
    try:
        return poll(oauth, tokens, args, session_approvals, jobs)
    finally:
        jobs.close()


def poll(oauth, tokens, args, session_approvals, jobs):
    while True:
        try:
            jobs.report_completed()
            poll_started = time.monotonic()
            job = oauth.post("/mcp/host/poll", {}, tokens["access_token"])
            if job:
                result = run_job(job, args.allow_shell, poll_started, session_approvals, args.approve_all_session, jobs)
                if job.get("tool") != "get_shell_job_status" and (
                    job.get("mode") != "background" or result["isError"]
                ):
                    terminal_result("Command result", result)
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
            terminal_message("Relay request failed", json.dumps(str(error)), color="31")
        except (ValueError, KeyError, URLError, TimeoutError) as error:
            terminal_message("Relay request failed", json.dumps(str(error)), color="31")
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
