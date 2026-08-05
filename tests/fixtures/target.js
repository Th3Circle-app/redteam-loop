/**
 * A deliberately vulnerable HTTP target, and a fixed one, for the test suite.
 * Two builds of the same tiny API: `vulnerable()` fails specific attacks;
 * `hardened()` passes them all. The loop's job is to turn the first into the
 * second — the tests assert it detects the gap, and that a hardening diff
 * verified against the vulnerable build actually closes it.
 */
import { createServer } from "node:http";

function send(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

/** Vulnerable: no auth on /send, reflects any Origin, echoes input raw. */
export function vulnerable() {
  return createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");

    if (url.pathname === "/send") {
      // VULN A01: no authorization check at all.
      // VULN A05: reflects the request Origin unconditionally.
      const origin = req.headers.origin;
      if (req.method === "OPTIONS") {
        return send(res, 204, "", origin ? { "access-control-allow-origin": origin } : {});
      }
      return send(res, 200, { ok: true });
    }

    if (url.pathname === "/echo") {
      // VULN A03: reflects the query back into an HTML response unescaped.
      const q = url.searchParams.get("q") ?? "";
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(`<div>${q}</div>`);
    }

    send(res, 404, { error: "not found" });
  });
}

/** Hardened: /send requires a bearer token and never reflects Origin. */
export function hardened() {
  return createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");

    if (url.pathname === "/send") {
      if (req.method === "OPTIONS") {
        // FIX A05: only ever advertise the one allowed origin.
        return send(res, 204, "", { "access-control-allow-origin": "https://app.example" });
      }
      // FIX A01: require a properly signed token (any non-"none" alg here).
      const auth = req.headers.authorization ?? "";
      const tok = auth.replace(/^Bearer\s+/, "");
      if (!isSignedToken(tok)) return send(res, 401, { error: "unauthorized" });
      return send(res, 200, { ok: true });
    }

    if (url.pathname === "/echo") {
      const q = url.searchParams.get("q") ?? "";
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(`<div>${escapeHtml(q)}</div>`); // FIX A03
    }

    send(res, 404, { error: "not found" });
  });
}

function isSignedToken(tok) {
  const parts = tok.split(".");
  if (parts.length !== 3) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    return header.alg && header.alg !== "none" && parts[2].length > 0;
  } catch {
    return false;
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

/** Start a server on an ephemeral port and resolve with its base URL. */
export function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}
