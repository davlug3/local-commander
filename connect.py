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
