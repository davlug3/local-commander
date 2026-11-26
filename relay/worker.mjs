import { DurableObject } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";

const tools = ["git_status", "python_version"];
const schema = {
  name: "run_local_tool",
  description: "Run Git status or check the Python version on the paired machine.",
  inputSchema: {
    type: "object",
    properties: { tool: { type: "string", enum: tools } },
    required: ["tool"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, openWorldHint: false },
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

const oauthOptions = {
  apiRoute: "/mcp",
  apiHandler: {
    async fetch(request, env, ctx) {
      if (new URL(request.url).pathname !== "/mcp") return new Response(null, { status: 404 });
      if (ctx.props?.owner !== true) return new Response(null, { status: 403 });
      if (request.method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST" } });
      const raw = await request.text();
      if (raw.length > 16384) return new Response(null, { status: 413 });
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
      if (method === "tools/list") return rpc(id, { tools: [schema] });
      if (method !== "tools/call") return rpc(id, null, -32601, "Method not found");
      const args = params?.arguments;
      if (params?.name !== schema.name || !args || Object.keys(args).length !== 1 || !tools.includes(args.tool)) {
        return rpc(id, null, -32602, "Choose git_status or python_version.");
      }
      const response = await relay(env, "/call", { tool: args.tool });
      return rpc(id, await response.json());
    },
  },
  defaultHandler: {
    async fetch(request, env) {
      const url = new URL(request.url);
      if (url.pathname !== "/authorize") return new Response(null, { status: 404 });
      try {
        const provider = env.OAUTH_PROVIDER;
        if (request.method === "GET") {
          const auth = await provider.parseAuthRequest(request);
          const { handle, headers } = await provider.beginConsent(auth);
          const escape = (value) => String(value).replace(/[&<>"']/g, (char) => (
            { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]
          ));
          headers.set("Content-Type", "text/html; charset=utf-8");
          return new Response(`<!doctype html><meta charset="utf-8"><title>Local Commander</title>
<h1>Connect Local Commander</h1><p>Allow the client returning to <code>${escape(auth.redirectUri)}</code>
to check Git status and Python version on your paired machine.</p>
<form method="post" action="/authorize">
<input type="hidden" name="handle" value="${escape(handle)}">
<label>Owner passphrase <input required type="password" name="passphrase" autocomplete="current-password"></label>
<button type="submit">Allow access</button></form>`, { headers });
        }
        if (request.method !== "POST") return new Response(null, { status: 405 });
        if (request.headers.get("Origin") !== url.origin) return new Response(null, { status: 403 });
        const form = await request.formData();
        const proof = await matches(form.get("passphrase"), env.OWNER_PASSPHRASE);
        if (!proof) return new Response("Invalid owner passphrase. Restart the connection to try again.", { status: 403 });
        const approved = await provider.approveConsent(request, String(form.get("handle")));
        const { redirectTo } = await provider.completeAuthorization({
          request: approved.request,
          userId: "owner",
          metadata: {},
          scope: approved.request.scope,
          props: { owner: true },
        });
        approved.headers.set("Location", redirectTo);
        return new Response(null, { status: 303, headers: approved.headers });
      } catch {
        return new Response("Authorization failed. Restart the connection from your MCP client.", { status: 400 });
      }
    },
  },
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: ["mcp:read"],
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
      const { tool } = await request.json();
      if (this.pending.size >= 4) return json(failure("Local Commander is busy."));
      const id = crypto.randomUUID();
      const result = await new Promise((resolve) => {
        const timer = setTimeout(() => {
          this.pending.delete(id);
          resolve(failure("The local host did not respond. Check that connect.py is running."));
        }, 25_000);
        this.pending.set(id, { tool, resolve, timer, claimed: false });
      });
      return json(result);
    }
    if (pathname === "/poll") {
      for (const [id, job] of this.pending) {
        if (job.claimed) continue;
        job.claimed = true;
        return json({ id, tool: job.tool });
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
    const path = url.pathname;
    if (path !== "/host/poll" && path !== "/host/result") {
      oauth ??= new OAuthProvider({
        ...oauthOptions,
        resourceMetadata: { resource: env.RELAY_ORIGIN + "/mcp", authorization_servers: [env.RELAY_ORIGIN] },
      });
      return oauth.fetch(request, env, ctx);
    }
    if (request.method !== "POST") return new Response(null, { status: 405 });
    const auth = request.headers.get("Authorization") || "";
    if (!auth.startsWith("Bearer ") || !(await matches(auth.slice(7), env.HOST_TOKEN))) {
      return new Response(null, { status: 401 });
    }
    if (path === "/host/poll") return relay(env, "/poll", {});
    const raw = await request.text();
    if (raw.length > 100_000) return new Response(null, { status: 413 });
    try { return await relay(env, "/result", JSON.parse(raw)); }
    catch { return new Response(null, { status: 400 }); }
  },
};
