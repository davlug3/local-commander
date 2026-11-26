"""Sign in through the browser, then run the built-in Local Commander tools."""

import argparse
import base64
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import heapq
import os
import select
import stat
import secrets
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser

from server import DEFAULT_COMMANDS, MAX_OUTPUT, WORKSPACE, run_command


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
            return None if response.status == 204 else json.loads(response.read(32_768))

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


def largest_files():
    deadline = time.monotonic() + 10
    def sizes():
        for folder, directories, filenames in os.walk(WORKSPACE):
            if time.monotonic() >= deadline:
                raise TimeoutError
            directories[:] = [name for name in directories if name != ".git"]
            for filename in filenames:
                if time.monotonic() >= deadline:
                    raise TimeoutError
                path = os.path.join(folder, filename)
                try:
                    entry = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(entry.st_mode):
                    yield entry.st_size, os.path.relpath(path, WORKSPACE)
    try:
        largest = heapq.nlargest(20, sizes())
    except TimeoutError:
        return tool_result("The workspace scan exceeded 10 seconds.", True)
    lines = [f"{size:>12} B  {json.dumps(path)}" for size, path in largest]
    text = "\n".join(lines) or "No readable regular files found."
    return tool_result(text if len(text) <= MAX_OUTPUT else text[:MAX_OUTPUT] + "\n[Output truncated]")


def run_job(job, allow_shell, poll_started):
    tool = job.get("tool")
    if tool == "largest_files":
        return largest_files()
    if tool == "run_shell_command":
        if not allow_shell:
            return tool_result("Restart the host client with --allow-shell to approve shell commands.", True)
        command = job.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 2048 or "\0" in command:
            return tool_result("Invalid shell command.", True)
        remaining = job.get("remainingMs", 0)
        if not isinstance(remaining, int):
            return tool_result("Invalid approval deadline.", True)
        deadline = poll_started + remaining / 1000 - 20
        wait = min(40, deadline - time.monotonic())
        if wait <= 0:
            return tool_result("Command approval expired.", True)
        approval = "yes " + secrets.token_hex(3)
        try:
            with open("/dev/tty", encoding="utf-8") as terminal:
                print(f"\nLocal Commander shell request in {json.dumps(str(WORKSPACE))}\n"
                      f"{json.dumps(command)}\n"
                      f"Type {approval} to run this command and share its output: ",
                      file=sys.stderr, flush=True)
                ready, _, _ = select.select([terminal], [], [], max(0, min(wait, deadline - time.monotonic())))
                if not ready or terminal.readline().strip() != approval or time.monotonic() >= deadline:
                    return tool_result("Command denied or approval expired.", True)
        except OSError:
            return tool_result("Local approval requires an interactive terminal.", True)
        return run_command(["/bin/bash", "--noprofile", "--norc", "-c", command])
    command = DEFAULT_COMMANDS.get(tool)
    if command is None:
        return tool_result("Unknown local tool.", True)
    if tool == "git_status":
        command = [command[0], "-c", "core.fsmonitor=false", *command[1:]]
    return run_command(command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("relay", help="Origin of your Cloudflare Worker")
    parser.add_argument("--allow-shell", action="store_true", help="Enable shell requests with local approval")
    args = parser.parse_args()
    url = urlsplit(args.relay.rstrip("/"))
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        parser.error("Provide an HTTPS origin with no path.")
    origin = f"https://{url.netloc.lower()}"
    oauth = OAuth(origin)
    tokens = oauth.sign_in()
    print(f"Signed in. Polling {origin} for tools in {WORKSPACE}. Press Ctrl-C to stop.", file=sys.stderr)
    while True:
        try:
            poll_started = time.monotonic()
            job = oauth.post("/mcp/host/poll", {}, tokens["access_token"])
            if job:
                result = run_job(job, args.allow_shell, poll_started)
                oauth.post("/mcp/host/result", {
                    "id": job["id"],
                    "text": result["content"][0]["text"],
                    "failed": result["isError"],
                }, tokens["access_token"])
        except HTTPError as error:
            if error.code == 401:
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
