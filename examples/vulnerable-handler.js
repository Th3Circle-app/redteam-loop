/**
 * A deliberately vulnerable request handler, used as the patch target for the
 * live loop demo. Small and self-contained so a proposed diff is easy to read.
 *
 * Three planted holes:
 *   A01 — /send has no authorization check
 *   A05 — the CORS preflight reflects whatever Origin it is given
 *   A03 — /echo writes the query into HTML without escaping
 */
import { createServer } from "node:http";

function json(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

export function handler(req, res) {
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/send") {
    if (req.method === "OPTIONS") {
      const origin = req.headers.origin;
      return json(res, 204, {}, origin ? { "access-control-allow-origin": origin } : {});
    }
    return json(res, 200, { ok: true });
  }

  if (url.pathname === "/echo") {
    const q = url.searchParams.get("q") ?? "";
    res.writeHead(200, { "content-type": "text/html" });
    return res.end(`<div>${q}</div>`);
  }

  return json(res, 404, { error: "not found" });
}

export function start(port = 0) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(port, "127.0.0.1", () => {
      resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  start(3000).then(({ baseUrl }) => console.log(`vulnerable handler on ${baseUrl}`));
}
