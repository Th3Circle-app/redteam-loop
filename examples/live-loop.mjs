/**
 * Live end-to-end: scan a running vulnerable handler, let Claude propose a
 * minimal patch for each finding against the real source file, and verify the
 * diff applies. Requires ANTHROPIC_API_KEY in the environment.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { createServer } from "node:http";
import { start } from "./vulnerable-handler.js";
import { scan } from "../src/runner.js";
import { runLoop } from "../src/loop.js";
import { toIssueMarkdown } from "../src/report.js";

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, "vulnerable-handler.js");

const { server, baseUrl } = await start();
const target = { baseUrl, authedPath: "/send", uploadPath: "/send", echoPath: "/echo" };

// Which planted holes we ask Claude to patch. Point every mapped finding at the
// one handler file — the model gets the real source and returns a real diff.
const PATCHABLE = new Set(["a01-no-token", "a05-cors-wildcard", "a03-xss-reflected"]);

const source = await readFile(SRC, "utf8");
const resolveSource = (f) => (PATCHABLE.has(f.id) ? { path: "vulnerable-handler.js", source } : null);

// Verify hook: stand up a server from the patched copy and hand back a target
// pointing at it, so the loop can re-run the exact attack against the fix.
const started = [];
async function retarget(dir) {
  const mod = await import(pathToFileURL(join(dir, "vulnerable-handler.js")).href);
  const patched = await new Promise((resolve) => {
    const s = createServer(mod.handler);
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
  started.push(patched);
  return {
    baseUrl: `http://127.0.0.1:${patched.address().port}`,
    authedPath: "/send",
    uploadPath: "/send",
    echoPath: "/echo",
  };
}

console.error("scanning…");
const { findings } = await scan(target);
console.error(`${findings.length} findings; proposing patches for ${findings.filter((f) => PATCHABLE.has(f.id)).length}…`);

const report = await runLoop(target, resolveSource, { now: null, retarget });
console.log(toIssueMarkdown(report));

server.close();
for (const s of started) s.close();
