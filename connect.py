"""Sign in through the browser, then run the built-in Local Commander tools."""

import argparse
import base64
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
import subprocess
import tempfile
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


class ShellJobs:
    def __init__(self):
        self.jobs = {}

    def start(self, argv):
        if len(self.jobs) >= 16:
            for job_id, (process, output) in self.jobs.items():
                if process.poll() is not None:
                    output.close()
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
        return tool_result(f"Background job started. Job ID: {job_id}")

    def status(self, job_id):
        if not isinstance(job_id, str) or job_id not in self.jobs:
            return tool_result("Unknown background job in this client session.", True)
        process, output = self.jobs[job_id]
        code = process.poll()
        size = os.fstat(output.fileno()).st_size
        tail = os.pread(output.fileno(), 8192, max(0, size - 8192))
        summary = "Running" if code is None else f"Finished with exit code {code}"
        prefix = "\n[Showing the last 8192 bytes]\n" if size > 8192 else "\n"
        return tool_result(summary + prefix + tail.decode("utf-8", errors="replace"), code not in (None, 0))

    def close(self):
        for process, output in self.jobs.values():
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            output.close()


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
        argv = ["/bin/bash", "--noprofile", "--norc", "-c", command]
        if permission == "session" and (approve_all or command in session_approvals):
            print(f"Running approved shell command in {json.dumps(str(WORKSPACE))}: "
                  f"{json.dumps(command)}", file=sys.stderr, flush=True)
            return execute(argv)
        approval = "yes " + secrets.token_hex(3)
        scope = "once" if permission == "once" else "this exact command for the current session"
        try:
            with open("/dev/tty", encoding="utf-8") as terminal:
                print(f"\nLocal Commander {mode} shell request in {json.dumps(str(WORKSPACE))}\n"
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
    jobs = ShellJobs()
    try:
        return poll(oauth, tokens, args, session_approvals, jobs)
    finally:
        jobs.close()


def poll(oauth, tokens, args, session_approvals, jobs):
    while True:
        try:
            poll_started = time.monotonic()
            job = oauth.post("/mcp/host/poll", {}, tokens["access_token"])
            if job:
                result = run_job(job, args.allow_shell, poll_started, session_approvals, args.approve_all_session, jobs)
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
