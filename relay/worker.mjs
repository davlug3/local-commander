import { DurableObject } from "cloudflare:workers";
import { OAuthProvider, authorizationErrorRedirect } from "@cloudflare/workers-oauth-provider";

const devicePattern = /^[a-z0-9][a-z0-9-]{0,31}$/;
const deviceField = {
  type: "string", pattern: devicePattern.source,
  description: "Paired device name. Omit to use the default device.",
};

const tools = ["git_status", "python_version"];
const schema = {
  name: "run_local_tool",
  description: "Check Git status or Python version on the paired machine.",
  inputSchema: {
    type: "object",
    properties: { tool: { type: "string", enum: tools }, device: deviceField },
    required: ["tool"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
};

const shellSchema = {
  name: "run_shell_command",
  description: "Run a Bash command using the paired host’s approval policy. Omit permission unless the user explicitly requests one-time or session approval. Use background mode for installs, builds, or other long-running commands. An explicit one-time request always prompts on the host.",
  inputSchema: {
    type: "object",
    properties: {
      device: deviceField,
      command: { type: "string", minLength: 1, maxLength: 8192 },
      mode: { type: "string", enum: ["foreground", "background"] },
      permission: {
        type: "string", enum: ["once", "session"],
        description: "Omit to use the host default. Use once or session only when the user requests it.",
      },
    },
    required: ["command"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
};

const listDevicesSchema = {
  name: "list_devices",
  description: "List Local Commander devices with online status and last check-in.",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
  annotations: { readOnlyHint: true },
};

const jobStatusSchema = {
  name: "get_shell_job_status",
  description: "Check a background shell job by ID on the same device that started it. Returns its current status, final exit code when available, and recent output.",
  inputSchema: {
    type: "object",
    properties: { job_id: { type: "string", pattern: "^[0-9a-f]{32}$" }, device: deviceField },
    required: ["job_id"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true },
};

function json(value, status = 200) {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}

async function matches(candidate, secret) {
  if (typeof candidate !== "string" || !secret || secret.length < 32 || candidate.length > 256) return false;
  const encode = (value) => crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const [left, right] = await Promise.all([encode(candidate), encode(secret)]);
  return crypto.subtle.timingSafeEqual(left, right);
}

const hostScope = "host:connect";
const hostPrefix = "/mcp/host/";


function roleFor(auth, origin) {
  const redirect = new URL(auth.redirectUri);
  if (auth.scope.includes("dashboard:read")) {
    if (auth.scope.length !== 1) throw new Error("Use only the dashboard scope.");
    return "dashboard";
  }
  if (!auth.scope.includes(hostScope)) return "mcp";
  const device = deviceFor(auth);
  const loopback = redirect.protocol === "http:" && redirect.hostname === "127.0.0.1" &&
    Boolean(redirect.port) && !redirect.pathname.startsWith("/pair/");
  const headless = redirect.origin === origin && redirect.pathname.startsWith("/pair/");
  if (auth.scope.length !== 1 || (!loopback && !headless) ||
      !device || redirect.search || redirect.hash || redirect.username || redirect.password) {
    throw new Error("Host authorization requires the local client callback.");
  }
  return "host";
}

function deviceFor(auth) {
  const path = new URL(auth.redirectUri).pathname;
  if (path === "/callback") return "default";
  const device = path.startsWith("/callback/") ? path.slice(10) :
    path.startsWith("/pair/") ? path.slice(6) : "";
  return devicePattern.test(device) ? device : null;
}

function githubEnabled(env) {
  return Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]
  ));
}

async function approve(provider, auth, headers, origin) {
  const role = roleFor(auth, origin);
  const { redirectTo } = await provider.completeAuthorization({
    request: auth,
    userId: "owner",
    metadata: {},
    scope: auth.scope,
    props: { owner: true, role, ...(role === "host" ? { device: deviceFor(auth) } : {}) },
  });
  const redirect = new URL(redirectTo);
  if (role === "host" && redirect.origin === origin && redirect.pathname.startsWith("/pair/")) {
    redirect.hash = redirect.search.slice(1);
    redirect.search = "";
  }
  headers.set("Location", redirect.href);
  return new Response(null, { status: 303, headers });
}

async function githubCallback(provider, request, env, setStage) {
  setStage("github-callback-state");
  const { request: auth, data, headers } = await provider.finishUpstream(request);
  const code = new URL(request.url).searchParams.get("code");
  if (!code) {
    headers.set("Location", authorizationErrorRedirect(auth, "access_denied"));
    return new Response(null, { status: 303, headers });
  }
  setStage("github-token-exchange/request-failed");
  const body = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    redirect_uri: env.RELAY_ORIGIN + "/github/callback",
    code,
    code_verifier: data.verifier,
  }).toString();
  let token;
  try {
    token = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "LocalCommander",
      },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(12_000),
    });
  } catch (error) {
    const kinds = {
      TimeoutError: "timeout",
      AbortError: "aborted",
      TypeError: "fetch-type-error",
      NetworkError: "network-error",
    };
    setStage("github-token-exchange/" + (Object.hasOwn(kinds, error?.name) ? kinds[error.name] : "transport-error"));
    throw error;
  }
  setStage("github-token-exchange/http-" + token.status);
  const { access_token, error } = await token.json().catch(() => ({}));
  if (!token.ok || !access_token) {
    const known = [
      "incorrect_client_credentials", "redirect_uri_mismatch", "bad_verification_code",
      "bad_code_verifier", "unverified_user_email",
    ];
    if (known.includes(error)) setStage("github-token-exchange/" + error);
    throw new Error("GitHub token exchange failed.");
  }
  setStage("github-user-lookup/request-failed");
  const user = await fetch("https://api.github.com/user", {
    method: "GET",
    headers: {
      Authorization: "Bearer " + access_token,
      "User-Agent": "LocalCommander",
      Accept: "application/vnd.github+json",
    },
    redirect: "manual",
    signal: AbortSignal.timeout(12_000),
  });
  setStage("github-user-lookup/http-" + user.status);
  if (!user.ok) throw new Error("GitHub user lookup failed.");
  const profile = await user.json();
  if (!Number.isSafeInteger(profile.id)) throw new Error("GitHub user ID missing.");
  if (String(profile.id) !== String(env.GITHUB_OWNER_ID)) {
    setStage("github-owner-mismatch");
    throw new Error("GitHub owner verification failed.");
  }
  setStage("localcommander-grant");
  return approve(provider, auth, headers, env.RELAY_ORIGIN);
}

const UI_STYLES = `:root{color-scheme:dark;--bg:#0f172a;--card:#1b2336;--ink:#f8fafc;--muted:#a8b7ca;--edge:#475569;--accent:#86efac;font:16px/1.55 system-ui,sans-serif;background:var(--bg);color:var(--ink)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;padding:clamp(16px,4vw,48px);background:radial-gradient(ellipse at 70% 0,#1c3c43,transparent 55%),var(--bg)}
main{width:min(100%,68rem);margin:clamp(16px,6vh,70px) auto;padding:clamp(19px,4vw,40px);border:1px solid var(--edge);border-radius:22px;background:var(--card);box-shadow:0 24px 68px #0004}
body.auth{display:grid;place-items:center}
.auth main{max-width:30rem;margin:0}
.brand{display:flex;align-items:center;gap:11px;color:var(--muted);font-weight:650;font-size:.9rem}
.mark{display:grid;place-items:center;width:36px;height:36px;border:1px solid #467061;border-radius:10px;background:#173936;color:var(--accent);font:700 .95rem ui-monospace,monospace}
h1{font-size:clamp(1.65rem,4.5vw,2.45rem);line-height:1.12;letter-spacing:-.035em;margin:20px 0 8px}
h2{font-size:1.1rem;margin:24px 0 8px}
p{color:var(--muted);margin:0 0 17px;overflow-wrap:anywhere}
form{display:grid;gap:10px;margin:0}
label{font-size:.9rem;font-weight:650}
button,input,textarea{font:inherit;border-radius:10px;min-height:46px}
button,input{padding:9px 13px}
input,textarea,pre{background:#10192b;color:var(--ink);border:1px solid var(--edge)}
input,textarea{width:100%;min-width:0}
textarea{padding:12px;font-family:ui-monospace,monospace;resize:vertical;overflow-wrap:anywhere}
button{cursor:pointer;background:#26354a;color:var(--ink);border:1px solid var(--edge);font-weight:650}
button:hover{background:#33465d}
button:disabled{opacity:.65;cursor:wait}
button.primary,#sign-in,#copy{background:var(--accent);border-color:var(--accent);color:var(--bg)}
button.primary:hover,#sign-in:hover,#copy:hover{background:#bbf7d0}
#copy{margin-top:10px;width:100%}
a{color:var(--accent);overflow-wrap:anywhere}
:focus-visible{outline:3px solid #fff;outline-offset:3px}
.separator{display:flex;align-items:center;gap:12px;margin:18px 0;color:var(--muted);font-size:.87rem}
.separator::before,.separator::after{content:"";height:1px;flex:1;background:var(--edge)}
details{border-top:1px solid var(--edge);padding-top:13px;margin-top:22px;color:var(--muted);font-size:.9rem}
summary{cursor:pointer;min-height:44px;display:list-item;padding:9px 0}
code{display:block;overflow-wrap:anywhere}
ul{list-style:none;padding:0;margin:14px 0 0;display:grid;gap:9px}
li{padding:12px 14px;border-radius:11px;background:#10192b;border:1px solid var(--edge);overflow-wrap:anywhere}
li a{display:inline-flex;align-items:center;min-height:44px;margin:-9px 8px -9px 0}
pre{font: .88rem/1.55 ui-monospace,monospace;padding:clamp(12px,3vw,24px);min-height:48vh;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere}
#state{color:var(--accent)}
#device,#workspace{font-family:ui-monospace,monospace}
[hidden]{display:none!important}`;

function signInPage({ title, description, body, headers = new Headers(), status = 200 }) {
  const nonce = crypto.randomUUID();
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("Referrer-Policy", "same-origin");
  headers.append("Content-Security-Policy",
    "default-src 'none'; style-src 'nonce-" + nonce + "'; base-uri 'none'; frame-ancestors 'none'");
  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · Local Commander</title>
<style nonce="${nonce}">${UI_STYLES}</style>
</head>
<body class="auth">
<main>
<div class="brand"><span class="mark" aria-hidden="true">&gt;_</span>Local Commander</div>
<h1>${escapeHtml(title)}</h1>
<p>${escapeHtml(description)}</p>
${body}
</main>
</body>
</html>`, { status, headers });
}

async function authorize(request, env) {
  const url = new URL(request.url);
  const provider = env.OAUTH_PROVIDER;
  let stage = "authorization-request";
  try {
    if (url.pathname === "/github/callback" && request.method === "GET" && githubEnabled(env)) {
      return await githubCallback(provider, request, env, (step) => { stage = step; });
    }
    if (url.pathname !== "/authorize") return new Response(null, { status: 404 });
    if (request.method === "GET") {
      const auth = await provider.parseAuthRequest(request);
      const role = roleFor(auth, url.origin);
      const { handle, headers } = await provider.beginConsent(auth);
      const hidden = `<input type="hidden" name="handle" value="${escapeHtml(handle)}">`;
      const github = githubEnabled(env) ? `<form method="post" action="/authorize">${hidden}
<button class="primary" type="submit" name="method" value="github">Sign in with GitHub</button></form>` : "";
      const passphrase = env.OWNER_PASSPHRASE ? `<form method="post" action="/authorize">${hidden}
<label for="passphrase">Owner passphrase</label>
<input id="passphrase" required type="password" name="passphrase" autocomplete="current-password">
<button type="submit" name="method" value="passphrase">Sign in with passphrase</button></form>` : "";
      const separator = github && passphrase ? '<div class="separator">or</div>' : "";
      const methods = github || passphrase ? github + separator + passphrase : "<p>Ask the relay owner to configure a sign-in method.</p>";
      return signInPage({
        title: role === "host" ? "Pair your computer" : "Connect Local Commander",
        description: role === "host" ? "Sign in to pair this computer with your relay." :
          "Sign in to let this client request tools on your paired computer.",
        body: methods + `<details><summary>Connection details</summary>
<code>${escapeHtml(auth.redirectUri)}</code></details>`,
        headers,
      });
    }
    if (request.method !== "POST") return new Response(null, { status: 405 });
    if (request.headers.get("Origin") !== url.origin) {
      return signInPage({
        title: "Sign-in request rejected",
        description: "Open a fresh sign-in link from Local Commander and submit the form on this site.",
        body: "",
        status: 403,
      });
    }
    const form = await request.formData();
    const method = form.get("method");
    if (method === "github" && githubEnabled(env)) {
      stage = "github-consent";
      const approved = await provider.approveConsent(request, String(form.get("handle")));
      stage = "github-redirect";
      const verifier = crypto.randomUUID() + crypto.randomUUID();
      const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      const challenge = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const { state, headers } = await provider.beginUpstream(approved.request, { data: { verifier }, headers: approved.headers });
      const login = new URL("https://github.com/login/oauth/authorize");
      login.search = new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        redirect_uri: env.RELAY_ORIGIN + "/github/callback",
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      headers.set("Location", login);
      return new Response(null, { status: 303, headers });
    }
    if (method !== "passphrase" || !(await matches(form.get("passphrase"), env.OWNER_PASSPHRASE))) {
      return signInPage({ title: "Sign-in failed", description: "The owner passphrase was incorrect. Restart the connection to try again.", body: "", status: 403 });
    }
    const approved = await provider.approveConsent(request, String(form.get("handle")));
    return await approve(provider, approved.request, approved.headers, url.origin);
  } catch (error) {
    const consentErrors = {
      "Missing transaction handle": "missing-handle",
      "This authorization was not started in this browser; start again": "missing-browser-cookie",
      "This authorization belongs to a different browser session; start again": "browser-cookie-mismatch",
      "This authorization expired or was already used; start again": "expired-or-used",
    };
    const detail = error?.description;
    if (stage === "github-consent" && Object.hasOwn(consentErrors, detail)) {
      const reason = consentErrors[detail];
      const description = reason.includes("cookie")
        ? "Restart the connection and open the new link in the same browser with cookies enabled."
        : "Restart the connection and submit the new sign-in form once.";
      return signInPage({
        title: "Sign-in could not continue",
        description,
        body: "<code>github-consent/" + reason + "</code>",
        status: 400,
      });
    }
    return new Response(`Authorization failed (${stage}). Restart the connection from your client.`, {
      status: 400, headers: { "Cache-Control": "no-store" },
    });
  }
}

async function hostRequest(request, env, path, device) {
  if (path === hostPrefix + "poll") {
    if (request.headers.get("X-Local-Commander-Heartbeat") === "1") {
      await relay(env, "/heartbeat", { device }, "@dashboard");
    }
    return relay(env, "/poll", {}, device);
  }
  if (path !== hostPrefix + "result") return new Response(null, { status: 404 });
  const raw = await request.text();
  if (raw.length > 100_000) return new Response(null, { status: 413 });
  try { return await relay(env, "/result", JSON.parse(raw), device); }
  catch { return new Response(null, { status: 400 }); }
}

const oauthOptions = {
  apiRoute: "/mcp",
  apiHandler: {
    async fetch(request, env, ctx) {
      const path = new URL(request.url).pathname;
      if (request.method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST" } });
      if (ctx.props?.owner !== true) return new Response(null, { status: 403 });
      if (path.startsWith(hostPrefix)) {
        if (ctx.props.role !== "host") return new Response(null, { status: 403 });
        return hostRequest(request, env, path, ctx.props.device ?? "default");
      }
      if (path === "/mcp/dashboard") {
        if (ctx.props.role !== "dashboard") return new Response(null, { status: 403 });
        return relay(env, "/devices", {}, "@dashboard");
      }
      if (path !== "/mcp") return new Response(null, { status: 404 });
      if (ctx.props.role === "host" || ctx.props.role === "dashboard") return new Response(null, { status: 403 });
      const raw = await request.text();
      if (raw.length > 65536) return new Response(null, { status: 413 });
      let message;
      try { message = JSON.parse(raw); } catch { return rpc(null, null, -32700, "Parse error"); }
      if (message?.jsonrpc !== "2.0" || typeof message.method !== "string") {
        return rpc(null, null, -32600, "Invalid request");
      }
      const { id, method, params } = message;
      if (id === undefined) return new Response(null, { status: 202 });
      if (method === "initialize") {
        const supported = ["2025-03-26", "2025-06-18", "2025-11-25"];
        const version = params?.protocolVersion;
        return rpc(id, {
          protocolVersion: supported.includes(version) ? version : supported.at(-1),
          capabilities: { tools: {} },
          serverInfo: { name: "local-commander", version: "0.2.0" },
        });
      }
      if (method === "ping") return rpc(id, {});
      if (method === "tools/list") return rpc(id, { tools: [schema, shellSchema, jobStatusSchema, listDevicesSchema] });
      if (method !== "tools/call") return rpc(id, null, -32601, "Method not found");
      const args = params?.arguments ?? {};
      if (params?.name === listDevicesSchema.name && typeof args === "object" &&
          !Array.isArray(args) && Object.keys(args).length === 0) {
        const registry = await relay(env, "/devices", {}, "@dashboard");
        const { devices } = await registry.json();
        const now = Date.now();
        const rows = devices.map(({ name, lastSeen }) =>
          name + " · " + (now - lastSeen < 90_000 ? "Online" : "Offline") + " · " + new Date(lastSeen).toISOString());
        return rpc(id, { content: [{ type: "text", text: rows.join("\n") || "No devices have checked in yet." }] });
      }
      if (!args || typeof args !== "object" || Array.isArray(args)) return rpc(id, null, -32602, "Invalid arguments");
      const { device = "default", ...toolArgs } = args;
      if (typeof device !== "string" || !devicePattern.test(device)) {
        return rpc(id, null, -32602, "Invalid device name");
      }
      let job;
      if (params.name === schema.name && Object.keys(toolArgs).length === 1 && tools.includes(toolArgs.tool)) {
        job = { tool: toolArgs.tool };
      } else if (params.name === shellSchema.name && Object.keys(toolArgs).every((key) => ["command", "permission", "mode"].includes(key)) &&
          (toolArgs.permission === undefined || ["once", "session"].includes(toolArgs.permission)) &&
          (toolArgs.mode === undefined || ["foreground", "background"].includes(toolArgs.mode)) && typeof toolArgs.command === "string" &&
          toolArgs.command.length <= 8192 && toolArgs.command.trim() && !toolArgs.command.includes("\0")) {
        job = { tool: shellSchema.name, command: toolArgs.command, permission: toolArgs.permission, mode: toolArgs.mode };
      } else if (params.name === jobStatusSchema.name && Object.keys(toolArgs).length === 1 &&
          typeof toolArgs.job_id === "string" && /^[0-9a-f]{32}$/.test(toolArgs.job_id)) {
        job = { tool: jobStatusSchema.name, job_id: toolArgs.job_id };
      } else {
        return rpc(id, null, -32602, "Invalid tool or arguments");
      }
      const response = await relay(env, "/call", job, device);
      return rpc(id, await response.json());
    },
  },
  defaultHandler: { fetch: authorize },
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: ["mcp:read", hostScope, "dashboard:read"],
  accessTokenTTL: 3600,
  clientIdMetadataDocumentEnabled: false,
};

let oauth;

function rpc(id, result, code, message) {
  return json({ jsonrpc: "2.0", id, ...(code ? { error: { code, message } } : { result }) });
}

function relay(env, path, data, device) {
  const stub = env.RELAY.get(env.RELAY.idFromName(device === "default" ? "single-host" : "device:" + device));
  return stub.fetch("https://relay.internal" + path, { method: "POST", body: JSON.stringify(data) });
}

function failure(text) {
  return { content: [{ type: "text", text }], isError: true };
}

export class Relay extends DurableObject {
  pending = new Map();

  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/heartbeat") {
      const { device } = await request.json();
      await this.ctx.storage.put("device:" + device, Date.now());
      return new Response(null, { status: 204 });
    }
    if (pathname === "/devices") {
      const devices = await this.ctx.storage.list({ prefix: "device:", limit: 128 });
      return json({ devices: Array.from(devices, ([key, lastSeen]) => ({ name: key.slice(7), lastSeen })) });
    }
    if (pathname === "/call") {
      const payload = await request.json();
      if (this.pending.size >= 4) return json(failure("Local Commander is busy."));
      const id = crypto.randomUUID();
      const expiresAt = Date.now() + (payload.tool === shellSchema.name ? 70_000 : 25_000);
      const result = await new Promise((resolve) => {
        const timer = setTimeout(() => {
          this.pending.delete(id);
          resolve(failure("The local host did not respond. Check that connect.py is running."));
        }, expiresAt - Date.now());
        this.pending.set(id, { payload, resolve, timer, expiresAt, claimed: false });
      });
      return json(result);
    }
    if (pathname === "/poll") {
      for (const [id, job] of this.pending) {
        if (job.claimed) continue;
        job.claimed = true;
        return json({ id, ...job.payload, remainingMs: Math.max(0, job.expiresAt - Date.now()) });
      }
      return new Response(null, { status: 204 });
    }
    if (pathname !== "/result") return new Response(null, { status: 404 });
    const { id, text, failed } = await request.json();
    const job = this.pending.get(id);
    if (!job?.claimed || typeof text !== "string" || text.length > 16_384 || typeof failed !== "boolean") {
      return new Response(null, { status: 400 });
    }
    this.pending.delete(id);
    clearTimeout(job.timer);
    job.resolve({ content: [{ type: "text", text }], isError: failed });
    return new Response(null, { status: 204 });
  }
}

function remoteDashboard() {
  const nonce = crypto.randomUUID();
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Commander · Devices</title>
<style nonce="${nonce}">${UI_STYLES}</style>
<body><main><div class="brand"><span class="mark" aria-hidden="true">&gt;_</span>Local Commander</div><h1>Devices</h1><p id="state" role="status">Sign in to view your devices.</p>
<button id="sign-in">Sign in</button><ul id="devices"></ul></main>
<script nonce="${nonce}">
const statusLine = document.querySelector("#state");
const button = document.querySelector("#sign-in");
const list = document.querySelector("#devices");
const callback = location.origin + location.pathname;
const resource = location.origin + "/mcp";
const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), n => n.toString(16).padStart(2,"0")).join("");
async function post(path, body, headers={}) {
  const response = await fetch(path,{method:"POST",body,headers,cache:"no-store"});
  if (!response.ok) throw new Error("Request failed");
  return response.json();
}
button.onclick = async () => {
  button.disabled = true;
  try {
    const registration = await post("/register",JSON.stringify({
      client_name:"Local Commander dashboard",redirect_uris:[callback],
      token_endpoint_auth_method:"none",grant_types:["authorization_code"],response_types:["code"]
    }),{"Content-Type":"application/json"});
    const verifier=random(), state=random();
    const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier));
    const challenge=btoa(String.fromCharCode(...new Uint8Array(hash))).split("+").join("-").split("/").join("_").split("=")[0];
    sessionStorage.setItem("lc-dashboard-oauth",JSON.stringify({client_id:registration.client_id,verifier,state}));
    location.assign("/authorize?"+new URLSearchParams({
      client_id:registration.client_id,redirect_uri:callback,resource,response_type:"code",
      scope:"dashboard:read",state,code_challenge:challenge,code_challenge_method:"S256"
    }));
  } catch { statusLine.textContent="Could not start sign-in. Try again."; button.disabled=false; }
};
async function refresh(token) {
  try {
    const data=await post("/mcp/dashboard", "{}", {Authorization:"Bearer "+token,"Content-Type":"application/json"});
    list.replaceChildren(...data.devices.map(device => {
      const item=document.createElement("li");
      const age=Date.now()-device.lastSeen;
      item.textContent=device.name+" · "+(age < 90000 ? "Online" : "Offline")+" · "+
        new Date(device.lastSeen).toLocaleString();
      return item;
    }));
    statusLine.textContent=data.devices.length?"Last check-in shown in your local time.":"No devices have checked in yet.";
    setTimeout(()=>refresh(token),15000);
  } catch {
    list.replaceChildren();
    statusLine.textContent="Could not load devices. Sign in again.";
    button.hidden=false;
  }
}
async function finish() {
  const params=new URLSearchParams(location.search);
  if (!params.has("code") && !params.has("error")) return;
  history.replaceState(null,"",location.pathname);
  const pending=JSON.parse(sessionStorage.getItem("lc-dashboard-oauth") || "null");
  sessionStorage.removeItem("lc-dashboard-oauth");
  try {
    if (!pending || params.get("state")!==pending.state || params.get("iss")!==location.origin || !params.has("code")) throw new Error();
    const token=await post("/token",new URLSearchParams({
      grant_type:"authorization_code",client_id:pending.client_id,code_verifier:pending.verifier,
      code:params.get("code"),redirect_uri:callback,resource
    }));
    button.hidden=true;
    await refresh(token.access_token);
  } catch { statusLine.textContent="Sign-in did not complete. Try again."; }
}
finish();
</script></html>`, { headers: {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" +
      nonce + "'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  }});
}

function headlessPairPage() {
  const nonce = crypto.randomUUID();
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Commander · Pairing</title>
<style nonce="${nonce}">${UI_STYLES}</style>
<body class="auth"><main><div class="brand"><span class="mark" aria-hidden="true">&gt;_</span>Local Commander</div><h1>Pairing code</h1><p id="message">Start pairing from your terminal.</p>
<textarea id="code" rows="3" readonly hidden aria-label="One-time pairing code"></textarea><button id="copy" type="button" hidden>Copy pairing code</button></main>
<script nonce="${nonce}">
const params = new URLSearchParams(location.hash.slice(1));
history.replaceState(null, "", location.pathname);
const code = params.get("code"), state = params.get("state");
if (code && state && params.get("iss") === location.origin) {
  const field = document.getElementById("code");
  field.value = state + ":" + code;
  field.hidden = false;
  const copy = document.getElementById("copy");
  const message = document.getElementById("message");
  copy.hidden = false;
  message.textContent = "Paste this one-time code into the terminal that started pairing.";
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(field.value);
      message.textContent = "Code copied. Paste it into your terminal.";
    } catch {
      field.focus();
      field.select();
      message.textContent = "The code is selected. Copy it and paste it into your terminal.";
    }
  };
}
</script></html>`, { headers: {
    "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'nonce-" + nonce +
      "'; style-src 'nonce-" + nonce + "'; frame-ancestors 'none'; base-uri 'none'",
  }});
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.origin !== env.RELAY_ORIGIN) return new Response(null, { status: 404 });
    if (request.method === "GET" && url.pathname === "/dashboard") return remoteDashboard();
    if (request.method === "GET" && url.pathname.startsWith("/pair/") && devicePattern.test(url.pathname.slice(6))) {
      return headlessPairPage();
    }
    oauth ??= new OAuthProvider({
      ...oauthOptions,
      resourceMetadata: {
        resource: env.RELAY_ORIGIN + "/mcp",
        authorization_servers: [env.RELAY_ORIGIN],
      },
      requiredScopes: ["mcp:read"],
    });
    return oauth.fetch(request, env, ctx);
  },
};
