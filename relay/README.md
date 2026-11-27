# Cloudflare relay setup

Deploy a Worker in your Cloudflare account. The Worker handles MCP and OAuth.
The Python client makes outbound HTTPS requests and offers
`git_status` and `python_version`. It can also run Bash
commands after local approval when started with `--allow-shell`. The workspace defaults to the directory
where you launch the client.

## 1. Deploy the relay

From the repository's `relay/` directory, with Node.js 24 and npm:

```bash
npm ci
npx wrangler login
npx wrangler kv namespace create OAUTH_KV
```

Reuse the namespace ID if you already created it. Copy the ID into `wrangler.toml`. Set `RELAY_ORIGIN` to the exact
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
GITHUB_OWNER_ID = "YOUR_NUMERIC_GITHUB_USER_ID"
```

You can find your numeric user ID with `gh api users/YOUR_LOGIN --jq .id`.

Upload the app's client secret through Wrangler. The GitHub button appears
when the client ID and secret are configured.

```bash
npx wrangler secret put GITHUB_CLIENT_SECRET
```

Deploy the Worker after configuring your sign-in method:

```bash
npx wrangler deploy
```

Use one host client per device name. An idle client polls every five seconds, or
about 17,280 requests per day.

## 2. Connect the machine

On the computer that should run the tools:

```bash
curl -fsSL https://raw.githubusercontent.com/davlug3/local-commander/main/install.sh | bash
cd /path/to/your/project
python3 "${XDG_DATA_HOME:-$HOME/.local/share}/local-commander/connect.py" \
  https://YOUR-WORKER.workers.dev
```

Replace the placeholder with your Worker origin.

The client opens a browser on your computer. Choose **Sign in with GitHub**
or **Sign in with passphrase**, then return to the terminal. Leave the client running. If you used
`LOCAL_COMMANDER_INSTALL_DIR`, use the path printed by the installer.

On Android, install the [Termux prerequisites](../README.md#android-with-termux)
and run the same host-client command from Termux.

## 3. Connect ChatGPT

In **Plugins → + → Add custom MCP server**, choose the HTTPS connection and
enter your Worker URL with `/mcp` appended. Select OAuth with dynamic client
registration. If the form asks for a scope, use `mcp:read`. Verify the Worker
hostname and choose either configured sign-in method to authorize the plugin. Test it by asking
“Use Local Commander to run `python_version`.”

Stopping the Python client stops local tool execution. The original stdio
server is also available for local Codex and OpenAI Secure MCP Tunnel.

## Shell approval modes

Append `--allow-shell` when starting the client to enable Bash requests.
For blanket approval, start it with both flags:

```bash
python3 "${XDG_DATA_HOME:-$HOME/.local/share}/local-commander/connect.py" \
  --allow-shell --approve-all-session https://YOUR-WORKER.workers.dev
```

Type the full `approve all <code>` phrase shown in the terminal, then sign in.
This grants any OAuth client with shell access on the relay permission to run
Bash commands as your local user under the host default or session mode.
The terminal displays commands run without prompting. Stop the client to clear
the startup approval.

| Request permission | With `--allow-shell` | With both flags and startup approval |
| --- | --- | --- |
| Omitted (host default) | Prompt once for that run | Run without another prompt |
| `once` | Prompt for that run | Prompt for that run |
| `session` | Prompt the first time for each exact command | Run without another prompt |

Exact-command approvals clear when the client exits or renews its OAuth token.
Bash starts in the client workspace and runs with the current user's permissions.
Commands have a 15-second execution timeout and an 8 KiB output limit.

## Update an existing setup

From the repository root, pull and redeploy the Worker:

```bash
git pull --ff-only && (cd relay && npx wrangler deploy)
```

Stop the old client, rerun the installer from [Connect the machine](#2-connect-the-machine),
and restart with your preferred flags. Refresh the plugin from its ChatGPT
details page after a tool schema change. If the terminal says it is asking you
to approve a command **once**, the caller explicitly requested one-time approval.
To use the host default, ask ChatGPT to omit the permission argument.

## Background shell jobs

Use background mode for installs, builds, renders, or any other long-running
shell command. Ask ChatGPT to start the command in background mode and report
the job ID. The usual approval policy applies. Check that ID with
`get_shell_job_status` to see whether it is running, the exit code when it
finishes, and the most recent 8 KiB of combined output.

Foreground commands still have a 15-second limit. Background jobs run while
the host client stays open. They have no Local Commander execution timeout.
Output is spooled to a temporary file and job IDs are available only in the
current client process. The client retains up to 16 jobs and discards a
completed job when it needs a slot. Stop the client to terminate running jobs.

When a job starts, click its **Live console** URL in the host terminal, or
paste it into a browser on the same device. The console refreshes once per
second and shows the latest 8 KiB of output. Output appears when the command
flushes it. The link works only while that client and job record are available.

## Multiple devices

Run one client per device with a unique name on the same relay, for example:

```bash
python3 "${XDG_DATA_HOME:-$HOME/.local/share}/local-commander/connect.py" \\
  --device laptop --allow-shell https://YOUR-WORKER.workers.dev
```

If you omit `--device`, the client uses its computer hostname, lowercased and
normalized to fit the device naming rules. The terminal prints the selected
name after sign-in. Use `--device` to override it, especially if two devices
would have the same name. Names are 1–32 lowercase letters, digits, or hyphens
and start with a letter or digit. Sign
in on each device. To route a tool call, specify its name in ChatGPT, for
example “Run pwd on device laptop.” Use that same device for background-job
status. Tool calls without a device still route to the legacy `default` queue. Start
one client with `--device default` if you want to keep that behavior.

## Dashboards

The host prints a **Local dashboard** URL after sign-in. It shows that device's
workspace and background jobs, with links to live output. Open it on the same
device.

Open your Worker origin with `/dashboard` appended for the remote dashboard.
Sign in with an existing Worker sign-in method to view device names and their
last check-in. A host is marked offline after 90 seconds without a check-in.
Update and restart each client to enable reporting. Job output stays on the
local dashboard. The remote dashboard has no shell execution controls.
