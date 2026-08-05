#!/usr/bin/env node
/**
 * redteam-loop CLI.
 *
 *   redteam scan  <targetConfig.json>   run the attack suite, print findings
 *   redteam loop  <targetConfig.json>   scan → triage → propose → verify, emit an issue
 *
 * targetConfig.json shape:
 *   { "baseUrl": "...", "authedPath": "...", "uploadPath": "...",
 *     "echoPath": "...", "sourceMap": { "<attackId>": "path/to/file.js" } }
 */
import { readFile } from "node:fs/promises";
import { scan } from "./runner.js";
import { runLoop, triage } from "./loop.js";
import { toIssueMarkdown } from "./report.js";

async function loadTarget(path) {
  const cfg = JSON.parse(await readFile(path, "utf8"));
  if (!cfg.baseUrl) throw new Error("target config needs a baseUrl");
  return cfg;
}

function resolveSourceFactory(cfg) {
  return async function resolveSource(finding) {
    const rel = cfg.sourceMap?.[finding.id];
    if (!rel) return null;
    return { path: rel, source: await readFile(rel, "utf8") };
  };
}

async function main() {
  const [cmd, cfgPath] = process.argv.slice(2);
  if (!cmd || !cfgPath) {
    console.error("usage: redteam <scan|loop> <targetConfig.json>");
    process.exit(2);
  }
  const cfg = await loadTarget(cfgPath);

  if (cmd === "scan") {
    const { findings, results } = await scan(cfg);
    for (const r of results) {
      const mark = r.finding ? "FINDING" : "ok     ";
      console.log(`${mark}  ${r.owasp}  ${r.id.padEnd(22)}  HTTP ${r.status ?? "—"}`);
    }
    console.log(`\n${findings.length} finding(s) of ${results.length} attacks`);
    process.exit(findings.length ? 1 : 0);
  }

  if (cmd === "loop") {
    // resolveSource is async; loop expects sync, so pre-resolve here.
    const { findings } = await scan(cfg);
    const ranked = triage(findings);
    const resolve = resolveSourceFactory(cfg);
    const files = new Map();
    for (const f of ranked) files.set(f.id, await resolve(f));

    const report = await runLoop(cfg, (f) => files.get(f.id) ?? null, { attacks: undefined });
    console.log(toIssueMarkdown(report));
    process.exit(report.counts.findings ? 1 : 0);
  }

  console.error(`unknown command: ${cmd}`);
  process.exit(2);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
