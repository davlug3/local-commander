# Cloudflare relay setup

Deploy a Worker in your Cloudflare account. The Worker handles MCP and OAuth.
The Python client makes outbound HTTPS requests and offers
`git_status` and `python_version`. It can also run Bash
commands after local approval when started with `--allow-shell`. The workspace defaults to the directory
where you launch the client.

## 1. Deploy the relay

From this directory, with Node.js 24 and npm:

```bash
npm ci
npx wrangler login
npx wrangler kv namespace create OAUTH_KV
```

Copy the namespace ID into `wrangler.toml`. Set `RELAY_ORIGIN` to the exact
origin of your Worker using your Cloudflare Workers subdomain. Use lowercase
and omit the trailing slash. If you change the Worker name, update the origin
to match.

Configure one or both sign-in methods. To keep passphrase sign-in, retain
your existing `OWNER_PASSPHRASE` secret. For a new installation, generate it
with `openssl rand -hex 32` and upload it with:

```bash
npx wrangler secret put OWNER_PASSPHRASE
```

For GitHub sign-in, [register a GitHub OAuth app](https://github.com/settings/applications/new).
Use your Worker origin as its homepage and the same origin plus
`/github/callback` as its authorization callback URL. For the davlug3 deployment,
the callback is `https://local-commander.davlug3.workers.dev/github/callback`.
In the `[vars]` section of `wrangler.toml`, add the app client ID and your numeric
GitHub user ID. The Worker compares the numeric ID during sign-in.

```toml
GITHUB_CLIENT_ID = "YOUR_GITHUB_OAUTH_APP_CLIENT_ID"
GITHUB_OWNER_ID = "112188845"
```

Upload the app's client secret through Wrangler. The GitHub button appears
when the client ID and secret are configured.

```bash
npx wrangler secret put GITHUB_CLIENT_SECRET
npx wrangler deploy
```

The updated Worker uses OAuth for host polling and tool calls. Once you've
verified the new host client, you can delete the obsolete `HOST_TOKEN`
secret with `npx wrangler secret delete HOST_TOKEN`. Use one host client
per Worker. An idle client polls every five seconds, or about 17,280
requests per day.

## 2. Connect the machine

On the computer that should run the tools:

```bash
curl -fsSL https://raw.githubusercontent.com/davlug3/local-commander/main/install.sh | bash
cd /path/to/your/project
python3 "${XDG_DATA_HOME:-$HOME/.local/share}/local-commander/connect.py" \
  https://local-commander.davlug3.workers.dev
```

Use your own Worker origin if you deployed a separate copy.

The client opens a browser on your computer. Choose **Sign in with GitHub**
or **Sign in with passphrase**, then return to the terminal. Leave the client running. If you used
`LOCAL_COMMANDER_INSTALL_DIR`, use the path printed by the installer.

## 3. Connect ChatGPT

In **Plugins → + → Add custom MCP server**, choose the HTTPS connection and
enter your Worker URL with `/mcp` appended. Select OAuth with dynamic client
registration. If the form asks for a scope, use `mcp:read`. Verify the Worker
hostname and choose either configured sign-in method to authorize the plugin. Test it by asking
“Use Local Commander to run `python_version`.”

Stopping the Python client stops local tool execution. The original stdio
server is also available for local Codex and OpenAI Secure MCP Tunnel.


## Shell commands

Start `connect.py` with `--allow-shell` to enable Bash requests. When ChatGPT
omits the permission and blanket approval is off, the host requests one-time
approval. You can explicitly request session approval for repeat runs of the
exact command. The terminal shows the command and workspace before approval.
Session approvals are kept in memory and clear on client exit or token renewal.
A one-run request always asks for local confirmation.

Bash runs as your current user, with the workspace as its starting directory.
Commands have a 15-second execution timeout and an 8 KiB output limit.

### Approve all session commands

Start the client with both `--allow-shell` and `--approve-all-session` and
enter the startup confirmation in your terminal. After sign-in, any OAuth
client authorized to invoke shell tools on this relay can run any valid Bash
command without another prompt when the request uses the host default or
explicitly requests session approval. The terminal still displays each command.
Explicit one-time requests always prompt. This setting clears when you stop the
client.
