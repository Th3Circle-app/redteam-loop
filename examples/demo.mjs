/**
 * Zero-config demo. `npm run demo` — no target to configure, no key required.
 *
 * Stands up the bundled vulnerable handler, runs the full loop against it, and
 * prints the issue it would open. With ANTHROPIC_API_KEY set it also proposes
 * real patches and verifies each one closes the hole; without a key it stops at
 * detection + triage and says so. Either way an employer sees it work in one
 * command.
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
const haveKey = Boolean(process.env.ANTHROPIC_API_KEY);

const { server, baseUrl } = await start();
const target = { baseUrl, authedPath: "/send", uploadPath: "/send", echoPath: "/echo" };

const PATCHABLE = new Set(["a01-no-token", "a05-cors-wildcard", "a03-xss-reflected"]);
const source = await readFile(SRC, "utf8");
const resolveSource = (f) => (PATCHABLE.has(f.id) ? { path: "vulnerable-handler.js", source } : null);

const started = [];
async function retarget(dir) {
  const mod = await import(pathToFileURL(join(dir, "vulnerable-handler.js")).href);
  const s = await new Promise((res) => {
    const srv = createServer(mod.handler);
    srv.listen(0, "127.0.0.1", () => res(srv));
  });
  started.push(s);
  return { baseUrl: `http://127.0.0.1:${s.address().port}`, authedPath: "/send", uploadPath: "/send", echoPath: "/echo" };
}

const bar = "─".repeat(64);
console.log(`\n${bar}\n  redteam-loop demo — a deliberately vulnerable target\n${bar}\n`);

const { findings, results } = await scan(target);
for (const r of results) {
  console.log(`  ${r.finding ? "\x1b[31mFINDING\x1b[0m" : "\x1b[32mok     \x1b[0m"}  ${r.owasp}  ${r.id.padEnd(20)} HTTP ${r.status ?? "—"}`);
}
console.log(`\n  ${findings.length} of ${results.length} attacks landed.\n`);

if (!haveKey) {
  console.log(`${bar}\n  No ANTHROPIC_API_KEY set — stopping at detection + triage.\n` +
    `  Set the key and re-run to see Claude propose and the loop verify\n  a fix for each finding.\n${bar}\n`);
  server.close();
  process.exit(findings.length ? 1 : 0);
}

console.log("  ANTHROPIC_API_KEY found — proposing and verifying patches…\n");
const report = await runLoop(target, resolveSource, { retarget });
console.log(toIssueMarkdown(report));
server.close();
for (const s of started) s.close();
process.exit(report.counts.findings ? 1 : 0);
