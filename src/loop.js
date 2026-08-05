/**
 * The loop: detect, classify, propose, verify.
 *
 *   scan  ─▶ findings        attacks that landed, already OWASP-classified
 *   triage─▶ ranked          dedup + sort by severity
 *   patch ─▶ proposed diff   from Claude, minimal, unapplied
 *   verify─▶ re-scan         apply the patch to a throwaway copy, re-run the
 *                            one attack, confirm it now fails; revert
 *
 * The human is the merge step. This module never writes to the target repo and
 * never opens a PR on its own — it emits a report a person acts on. That
 * boundary is the honest version of "auto-patching": the machine does the
 * detection, classification, proposal, and verification; a person owns the merge.
 */
import { scan, runAttack } from "./runner.js";
import { attackById } from "./attacks/index.js";
import { proposePatch } from "./patch.js";
import { applyToCopy } from "./apply.js";

const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };

/** Sort findings by severity and drop duplicates by id. */
export function triage(findings) {
  const seen = new Set();
  return findings
    .filter((f) => (seen.has(f.id) ? false : seen.add(f.id)))
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
}

/**
 * Full loop over one target.
 * @param {object} target      target config (baseUrl + paths)
 * @param {(finding) => {path,source}|null} resolveSource  maps a finding to the file that serves it
 * @param {object} [opts]
 * @returns {Promise<Report>}
 */
export async function runLoop(target, resolveSource, opts = {}) {
  const { findings } = await scan(target, opts);
  const ranked = triage(findings);
  const items = [];

  for (const finding of ranked) {
    const file = resolveSource(finding);
    if (!file) {
      items.push({ finding, patch: null, verified: null, note: "no source mapped for this finding" });
      continue;
    }

    const { patch, model, reason } = await proposePatch(finding, file, opts);
    if (!patch) {
      items.push({ finding, patch: null, verified: null, note: reason });
      continue;
    }

    const verified = await verify(finding, file, patch, target, opts);
    items.push({ finding, patch, model, verified });
  }

  return {
    target: target.baseUrl,
    scannedAt: opts.now ?? null, // caller stamps time; keep this module deterministic
    counts: {
      attacks: (opts.attacks ?? undefined)?.length ?? null,
      findings: findings.length,
      patched: items.filter((i) => i.patch).length,
      verified: items.filter((i) => i.verified?.closed).length,
    },
    items,
  };
}

/**
 * Verify a proposed patch actually closes the hole.
 * Applies the diff to a throwaway copy of the file, re-runs the one attack
 * against a target that serves the patched copy, and reports whether it now
 * fails. The real repo is never touched.
 */
export async function verify(finding, file, patch, target, opts = {}) {
  const attack = attackById(finding.id, opts.attacks);
  if (!attack) return { closed: false, reason: "attack id not found for replay" };

  // The caller supplies how to stand the patched copy up as a target. Without
  // it we can still confirm the patch *applies* cleanly, which is a real signal.
  const applied = await applyToCopy(file, patch);
  if (!applied.ok) return { closed: false, reason: `patch did not apply: ${applied.reason}` };

  if (!opts.retarget) {
    return { closed: null, applied: true, reason: "patch applies; no retarget hook to re-run the attack" };
  }

  const patchedTarget = await opts.retarget(applied.dir, target);
  try {
    const res = await runAttack(attack, patchedTarget, opts);
    return { closed: res.held, applied: true, status: res.status };
  } finally {
    await applied.cleanup();
  }
}
