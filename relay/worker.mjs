import { DurableObject } from "cloudflare:workers";
import { OAuthProvider, authorizationErrorRedirect } from "@cloudflare/workers-oauth-provider";

const tools = ["git_status", "python_version"];
const schema = {
  name: "run_local_tool",
  description: "Check Git status or Python version on the paired machine.",
  inputSchema: {
    type: "object",
    properties: { tool: { type: "string", enum: tools } },
    required: ["tool"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
};

const shellSchema = {
  name: "run_shell_command",
  description: "Run a Bash command after local approval. Ask the user whether to approve one run or repeated runs of this exact command during the current host session before calling.",
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string", minLength: 1, maxLength: 8192 },
      permission: { type: "string", enum: ["once", "session"] },
    },
    required: ["command", "permission"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
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

function roleFor(auth) {
  const redirect = new URL(auth.redirectUri);
  if (!auth.scope.includes(hostScope)) return "mcp";
  if (auth.scope.length !== 1 || redirect.protocol !== "http:" ||
      redirect.hostname !== "127.0.0.1" || !redirect.port ||
      redirect.pathname !== "/callback" || redirect.search || redirect.hash) {
    throw new Error("Host authorization requires the local client callback.");
  }
  return "host";
}

function githubEnabled(env) {
  return Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]
  ));
}

async function approve(provider, auth, headers) {
  const role = roleFor(auth);
  const { redirectTo } = await provider.completeAuthorization({
    request: auth,
    userId: "owner",
    metadata: {},
    scope: auth.scope,
    props: { owner: true, role },
  });
  headers.set("Location", redirectTo);
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
  return approve(provider, auth, headers);
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
      const role = roleFor(auth);
      const { handle, headers } = await provider.beginConsent(auth);
      const hidden = `<input type="hidden" name="handle" value="${escapeHtml(handle)}">`;
      const github = githubEnabled(env) ? `<form method="post" action="/authorize">${hidden}
<button name="method" value="github">Sign in with GitHub</button></form>` : "";
      const passphrase = env.OWNER_PASSPHRASE ? `<form method="post" action="/authorize">${hidden}
<label>Owner passphrase <input required type="password" name="passphrase" autocomplete="current-password"></label>
<button name="method" value="passphrase">Sign in with passphrase</button></form>` : "";
      const description = role === "host" ? "Pair this computer to run local tools and approve shell commands." :
        "Allow the requesting client to inspect your paired workspace and propose shell commands for local approval.";
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(`<!doctype html><meta charset="utf-8"><title>Local Commander</title>
<h1>${role === "host" ? "Pair your computer" : "Connect Local Commander"}</h1>
<p>${description}</p><p>Callback <code>${escapeHtml(auth.redirectUri)}</code></p>
${github}${passphrase}`, { headers });
    }
    if (request.method !== "POST") return new Response(null, { status: 405 });
    if (request.headers.get("Origin") !== url.origin) return new Response(null, { status: 403 });
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
      return new Response("Invalid owner passphrase. Restart the connection to try again.", { status: 403 });
    }
    const approved = await provider.approveConsent(request, String(form.get("handle")));
    return await approve(provider, approved.request, approved.headers);
  } catch {
    return new Response(`Authorization failed (${stage}). Restart the connection from your client.`, {
      status: 400, headers: { "Cache-Control": "no-store" },
    });
  }
}

async function hostRequest(request, env, path) {
  if (path === hostPrefix + "poll") return relay(env, "/poll", {});
  if (path !== hostPrefix + "result") return new Response(null, { status: 404 });
  const raw = await request.text();
  if (raw.length > 100_000) return new Response(null, { status: 413 });
  try { return await relay(env, "/result", JSON.parse(raw)); }
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
        return hostRequest(request, env, path);
      }
      if (path !== "/mcp") return new Response(null, { status: 404 });
      if (ctx.props.role === "host") return new Response(null, { status: 403 });
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
      if (method === "tools/list") return rpc(id, { tools: [schema, shellSchema] });
      if (method !== "tools/call") return rpc(id, null, -32601, "Method not found");
      const args = params?.arguments;
      if (!args || typeof args !== "object" || Array.isArray(args)) return rpc(id, null, -32602, "Invalid arguments");
      let job;
      if (params.name === schema.name && Object.keys(args).length === 1 && tools.includes(args.tool)) {
        job = { tool: args.tool };
      } else if (params.name === shellSchema.name && Object.keys(args).length === 2 &&
          ["once", "session"].includes(args.permission) && typeof args.command === "string" &&
          args.command.length <= 8192 && args.command.trim() && !args.command.includes("\0")) {
        job = { tool: shellSchema.name, command: args.command, permission: args.permission };
      } else {
        return rpc(id, null, -32602, "Invalid tool or arguments");
      }
      const response = await relay(env, "/call", job);
      return rpc(id, await response.json());
    },
  },
  defaultHandler: { fetch: authorize },
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: ["mcp:read", hostScope],
  accessTokenTTL: 3600,
  clientIdMetadataDocumentEnabled: false,
};

let oauth;

function rpc(id, result, code, message) {
  return json({ jsonrpc: "2.0", id, ...(code ? { error: { code, message } } : { result }) });
}

function relay(env, path, data) {
  const stub = env.RELAY.get(env.RELAY.idFromName("single-host"));
  return stub.fetch("https://relay.internal" + path, { method: "POST", body: JSON.stringify(data) });
}

function failure(text) {
  return { content: [{ type: "text", text }], isError: true };
}

export class Relay extends DurableObject {
  pending = new Map();

  async fetch(request) {
    const { pathname } = new URL(request.url);
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.origin !== env.RELAY_ORIGIN) return new Response(null, { status: 404 });
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
