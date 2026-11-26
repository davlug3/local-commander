# Cloudflare relay setup

Deploy a Worker in your Cloudflare account. The Worker handles MCP and OAuth.
The Python client makes outbound HTTPS requests and offers only
`git_status` and `python_version`. The workspace defaults to the directory
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

Generate **two different** random secrets with `openssl rand -hex 32`. Keep
them in a password manager. Deploy the Worker, then enter each secret at the
corresponding Wrangler prompt:

```bash
npx wrangler deploy
npx wrangler secret put OWNER_PASSPHRASE
npx wrangler secret put HOST_TOKEN
```

The owner passphrase authorizes the OAuth connection. The host token pairs the
local host. Use one host client per Worker. One client polls every five seconds
while idle, which is about 17,280 Worker requests per day.

## 2. Connect the machine

On the computer that should run the tools:

```bash
curl -fsSL https://raw.githubusercontent.com/davlug3/local-commander/main/install.sh | bash
cd /path/to/your/project
python3 "${XDG_DATA_HOME:-$HOME/.local/share}/local-commander/connect.py" \
  https://local-commander.YOUR-SUBDOMAIN.workers.dev
```

Enter the `HOST_TOKEN` at the prompt. Leave the client running. If you used
`LOCAL_COMMANDER_INSTALL_DIR`, use the path printed by the installer.

## 3. Connect ChatGPT

In **Plugins → + → Add custom MCP server**, choose the HTTPS connection and
enter your Worker URL with `/mcp` appended. Select OAuth with dynamic client
registration. When the Worker prompts you, verify its hostname and enter
the `OWNER_PASSPHRASE` to authorize the plugin. Test it by asking
“Use Local Commander to run `python_version`.”

Stopping the Python client stops local tool execution. The original stdio
server is also available for local Codex and OpenAI Secure MCP Tunnel.
