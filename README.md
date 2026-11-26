# Local Commander

Requires Python 3 on the machine that will run commands. Git is optional unless
you use the built-in Git status tool. The server communicates over MCP stdio.

## Local Codex or another stdio MCP client

Unzip this package on your machine. In Codex, register the local server with
your actual absolute paths:

```bash
codex mcp add local-commander \
  --env LOCAL_COMMANDER_WORKSPACE=/absolute/path/to/project \
  -- python3 /absolute/path/to/local-commander/server.py
```

Restart the client and ask “Use Local Commander to run git_status.” Other stdio
MCP clients launch the same Python script with the same environment variable.
When no workspace is configured, commands use the server's starting directory.

## Choose local commands

By default the server provides `git_status` and `python_version`. To supply
your own list, set `LOCAL_COMMANDER_CONFIG` to an absolute path to a JSON
file you control. The file replaces the defaults. Each key is a tool choice
and each value is a fixed executable and argument list:

```json
{
  "git_status": ["git", "--no-optional-locks", "status", "--short", "--branch"],
  "python_version": ["python3", "--version"]
}
```

The AI chooses a configured name. The local server controls arguments and the
working directory. Commands inherit the local process's permissions and have
a 15-second timeout and an 8 KiB returned output limit.

## ChatGPT web

On accounts that support OpenAI Secure MCP Tunnel, create a private tunnel,
then run OpenAI's tunnel client on the same machine as the Python server.
Set the workspace and optional configuration in the tunnel client's environment.
Use the stdio setup from the official
[Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
with `python3 /absolute/path/to/local-commander/server.py` as the MCP command.
Connect the tunnel in the app configuration and keep the client running while
ChatGPT uses it.

## Cloudflare option

Workers Free can host an HTTPS relay. For ChatGPT, that route needs a remote
MCP HTTP endpoint with compatible authentication and a way to reach the local
runner, such as Cloudflare Tunnel. This package implements the local stdio
server. The OpenAI tunnel option above uses that server directly.
