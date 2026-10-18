import "./lib/g";

import { consumeLastCapturedError } from "./lib/g";
import { renderErrorPage } from "./lib/h";

type ServerEntry = {
  fetch: (request: Request, env: unknown, ctx: unknown) => Promise<Response> | Response;
};

let serverEntryPromise: Promise<ServerEntry> | undefined;

async function getServerEntry(): Promise<ServerEntry> {
  if (!serverEntryPromise) {
    serverEntryPromise = import("@tanstack/react-start/server-entry").then(
      (m) => (m.default ?? m) as ServerEntry,
    );
  }
  return serverEntryPromise;
}

// h3 swallows in-handler throws into a normal 500 Response with body
// {"unhandled":true,"message":"HTTPError"} — try/catch alone never fires for those.
async function normalizeCatastrophicSsrResponse(response: Response): Promise<Response> {
  if (response.status < 500) return response;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return response;

  const body = await response.clone().text();
  if (!isH3SwallowedErrorBody(body)) return response;

  console.error(consumeLastCapturedError() ?? new Error(`h3 swallowed SSR error: ${body}`));
  return new Response(renderErrorPage(), {
    status: 500,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function isH3SwallowedErrorBody(body: string): boolean {
  try {
    const payload = JSON.parse(body) as { unhandled?: unknown; message?: unknown };
    return payload.unhandled === true && payload.message === "HTTPError";
  } catch {
    return false;
  }
}

/**
 * Browser security headers on every page. The CSP only allows what the site actually loads: its own code, the API,
 * Google sign-in / Firebase, and Google Fonts. Pages can never be framed (clickjacking) and the camera is limited to this site.
 */
const API_ORIGINS = [...new Set(`${import.meta.env["VITE_API_URL"] ?? ""},${import.meta.env["VITE_API_URL_FALLBACK"] ?? ""}`.split(",").map(u => { try { return new URL(u.trim()).origin; } catch { return ""; } }).filter(Boolean))].join(" ");   // primary + standby API
const AUTH_DOMAIN = (import.meta.env["VITE_FIREBASE_AUTH_DOMAIN"] as string | undefined) ?? "";
const cspFor = (nonce: string) => [
  "default-src 'self'",
  // TanStack Start inlines its hydration data: every inline <script> in a page gets this request's one-time nonce (added below), so
  // injected markup can't run. Everything else must come from these hosts.
  `script-src 'self' 'nonce-${nonce}' https://apis.google.com https://www.gstatic.com https://accounts.google.com`,
  `style-src 'self' 'nonce-${nonce}' https://accounts.google.com`,
  "style-src-attr 'unsafe-inline'",                  // React's style="…" attributes only; <style> elements need the nonce
  "font-src 'self' data:",
  `img-src 'self' data: blob: ${API_ORIGINS} https://*.googleusercontent.com https://www.gstatic.com`,
  "media-src 'self' blob:",
  `connect-src 'self' ${API_ORIGINS} https://*.googleapis.com https://*.firebaseio.com wss://*.firebaseio.com https://*.firebasedatabase.app wss://*.firebasedatabase.app https://accounts.google.com`,
  `frame-src https://accounts.google.com ${AUTH_DOMAIN ? `https://${AUTH_DOMAIN}` : ""}`,
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join("; ");

interface Rewriter { on(sel: string, h: { element(e: { setAttribute(k: string, v: string): void }): void }): Rewriter; transform(r: Response): Response }
declare const HTMLRewriter: { new (): Rewriter };
const newNonce = () => { const b = crypto.getRandomValues(new Uint8Array(16)); let t = ""; b.forEach(x => (t += String.fromCharCode(x))); return btoa(t); };

function withSecurityHeaders(response: Response): Response {
  const h = new Headers(response.headers);
  const isHtml = (h.get("content-type") ?? "").includes("text/html");
  const nonce = import.meta.env.PROD && isHtml ? newNonce() : "";
  h.set("x-content-type-options", "nosniff");
  h.set("x-frame-options", "DENY");
  h.set("referrer-policy", "strict-origin-when-cross-origin");
  h.set("permissions-policy", "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
  h.set("cross-origin-opener-policy", "same-origin-allow-popups");          // Google's sign-in popup must be able to report back
  if (import.meta.env.PROD) {
    h.set("content-security-policy", cspFor(nonce || newNonce()));
    h.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  }
  h.set("cross-origin-resource-policy", "same-origin");
  if (isHtml && !h.has("cache-control")) h.set("cache-control", "no-cache, must-revalidate");     // always revalidate pages, never serve a stale shell
  const out = new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
  return nonce ? new HTMLRewriter().on("script", { element(e) { e.setAttribute("nonce", nonce); } }).on("style", { element(e) { e.setAttribute("nonce", nonce); } }).transform(out) : out;
}

export default {
  async fetch(request: Request, env: unknown, ctx: unknown) {
    try {
      const handler = await getServerEntry();
      const response = await handler.fetch(request, env, ctx);
      return withSecurityHeaders(await normalizeCatastrophicSsrResponse(response));
    } catch (error) {
      console.error(error);
      return withSecurityHeaders(new Response(renderErrorPage(), {
        status: 500,
        headers: { "content-type": "text/html; charset=utf-8" },
      }));
    }
  },
};
