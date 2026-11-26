# Local Commander

Local Commander connects ChatGPT to a machine you control through a Cloudflare
Worker. The Python host client polls over HTTPS. It exposes Git status and the
Python version, and can run Bash commands when you enable shell access.

## ChatGPT web with Cloudflare

1. Deploy the Worker and configure GitHub sign-in, a passphrase, or both. See
   the [Cloudflare deployment guide](relay/README.md#1-deploy-the-relay).
2. On the paired machine, install the client:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/davlug3/local-commander/main/install.sh | bash
   ```

3. Start it from the project directory. Replace the URL with your Worker origin:

   ```bash
   python3 "${XDG_DATA_HOME:-$HOME/.local/share}/local-commander/connect.py" \
     --allow-shell https://YOUR-WORKER.workers.dev
   ```

4. Sign in through the browser and leave the host client running. In ChatGPT,
   add the Worker's `/mcp` URL as a custom MCP server using OAuth with dynamic
   client registration. See [Connect ChatGPT](relay/README.md#3-connect-chatgpt).

Omit `--allow-shell` to use only the built-in tools. To approve shell commands
once at startup, add `--approve-all-session` and enter the startup confirmation
in your terminal. Ordinary shell requests then follow the host default. An
explicit one-time request still prompts. See [approval modes](relay/README.md#shell-approval-modes).

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

## Configure stdio tools

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

## ChatGPT web with OpenAI Secure MCP Tunnel

On accounts that support OpenAI Secure MCP Tunnel, create a private tunnel,
then run OpenAI's tunnel client on the same machine as the Python server.
Set the workspace and optional configuration in the tunnel client's environment.
Use the stdio setup from the official
[Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels)
with `python3 /absolute/path/to/local-commander/server.py` as the MCP command.
Connect the tunnel in the app configuration and keep the client running while
ChatGPT uses it.
