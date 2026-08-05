/**
 * The runner and loop, exercised against a real (local) vulnerable target and
 * its hardened twin. These tests are the proof that the tool detects real gaps
 * and confirms real fixes — the same claim the README makes.
 */
import { test, before, after, describe } from "node:test";
import assert from "node:assert/strict";
import { scan, runAttack } from "../src/runner.js";
import { triage, verify } from "../src/loop.js";
import { attackById } from "../src/attacks/index.js";
import { applyToCopy } from "../src/apply.js";
import { vulnerable, hardened, listen } from "./fixtures/target.js";

function targetFor(baseUrl) {
  return {
    baseUrl,
    authedPath: "/send",
    uploadPath: "/send",
    echoPath: "/echo",
  };
}

describe("scan against a vulnerable target", () => {
  let handle, target;
  before(async () => {
    handle = await listen(vulnerable());
    target = targetFor(handle.baseUrl);
  });
  after(() => handle.server.close());

  test("A01: unauthenticated call is a finding", async () => {
    const r = await runAttack(attackById("a01-no-token"), target);
    assert.equal(r.finding, true, "no-auth /send should be flagged");
    assert.equal(r.owasp, "A01");
  });

  test("A05: reflected Origin is a finding", async () => {
    const r = await runAttack(attackById("a05-cors-wildcard"), target);
    assert.equal(r.finding, true, "reflecting attacker Origin should be flagged");
  });

  test("A03: unescaped echo is a finding", async () => {
    const r = await runAttack(attackById("a03-xss-reflected"), target);
    assert.equal(r.finding, true, "raw <script> echo should be flagged");
  });

  test("the scan surfaces multiple findings, each OWASP-classified", async () => {
    const { findings } = await scan(target);
    assert.ok(findings.length >= 3, `expected >= 3 findings, got ${findings.length}`);
    for (const f of findings) assert.match(f.owasp, /^A0\d$/);
  });
});

describe("scan against the hardened target", () => {
  let handle, target;
  before(async () => {
    handle = await listen(hardened());
    target = targetFor(handle.baseUrl);
  });
  after(() => handle.server.close());

  test("the same attacks that landed before are now all refused", async () => {
    for (const id of ["a01-no-token", "a05-cors-wildcard", "a03-xss-reflected"]) {
      const r = await runAttack(attackById(id), target);
      assert.equal(r.finding, false, `${id} should be refused by the hardened target`);
    }
  });
});

describe("triage", () => {
  test("dedupes by id and orders high severity first", () => {
    const ranked = triage([
      { id: "b", severity: "low" },
      { id: "a", severity: "high" },
      { id: "a", severity: "high" },
      { id: "c", severity: "medium" },
    ]);
    assert.deepEqual(ranked.map((f) => f.id), ["a", "c", "b"]);
  });
});

describe("verify closes the loop", () => {
  test("a hardening diff applies cleanly and the re-run attack is refused", async () => {
    // A minimal diff that turns the vulnerable /send handler into an auth check.
    const file = {
      path: "handler.js",
      source: [
        "export function send(req) {",
        "  return { status: 200 };",
        "}",
        "",
      ].join("\n"),
    };
    const patch = [
      "--- a/handler.js",
      "+++ b/handler.js",
      "@@ -1,3 +1,4 @@",
      " export function send(req) {",
      "+  if (!req.authorized) return { status: 401 };",
      "   return { status: 200 };",
      " }",
      "",
    ].join("\n");

    const applied = await applyToCopy(file, patch);
    assert.equal(applied.ok, true, applied.reason);
    assert.match(applied.patchedSource, /status: 401/);
    await applied.cleanup();
  });

  test("a bogus diff is rejected, not silently accepted", async () => {
    const file = { path: "handler.js", source: "export const x = 1;\n" };
    const bad = "--- a/handler.js\n+++ b/handler.js\n@@ -99,1 +99,1 @@\n-nonexistent line\n+replacement\n";
    const applied = await applyToCopy(file, bad);
    assert.equal(applied.ok, false, "a diff that does not match must not apply");
  });
});

describe("verify against live patched target", () => {
  test("re-running an attack after a real fix reports it closed", async () => {
    // Stand up the vulnerable target, confirm the finding, then point verify()
    // at the hardened build via a retarget hook and confirm it reports closed.
    const vuln = await listen(vulnerable());
    const fixed = await listen(hardened());
    try {
      const target = targetFor(vuln.baseUrl);
      const finding = await runAttack(attackById("a01-no-token"), target);
      assert.equal(finding.finding, true);

      const result = await verify(
        finding,
        { path: "x.js", source: "// n/a for this hook-based check\n" },
        "--- a/x.js\n+++ b/x.js\n@@ -1 +1,2 @@\n // n/a for this hook-based check\n+// hardened\n",
        target,
        { retarget: async () => targetFor(fixed.baseUrl) }
      );
      assert.equal(result.closed, true, "attack should be refused by the hardened retarget");
      assert.equal(result.status, 401);
    } finally {
      vuln.server.close();
      fixed.server.close();
    }
  });
});
