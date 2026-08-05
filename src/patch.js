/**
 * Patch proposal.
 *
 * Given a confirmed finding and the source that serves the attacked endpoint,
 * ask Claude for a minimal unified diff that closes the specific hole — no
 * refactor, no scope expansion. The model proposes; it does not apply, does not
 * merge, and does not touch the repo. Everything downstream of here is a human
 * reading a diff.
 *
 * Requires ANTHROPIC_API_KEY. When it is unset, propose() returns a null patch
 * with a reason instead of throwing, so `scan` still works with no key. The SDK
 * is imported lazily so the detection core has zero runtime dependencies.
 */

const SYSTEM = `You are a security engineer proposing the minimal fix for one confirmed vulnerability.

Rules:
- Output a single unified diff and nothing else. No prose, no fences, no commentary.
- Change the fewest lines that close this specific hole. Do not refactor, rename,
  reformat, or "improve" anything adjacent.
- The diff must apply against the file provided, with correct @@ hunk headers.
- If the file provided does not actually contain the vulnerable code, output the
  single line: NO PATCH — wrong file.
- Prefer enforcing the control at the layer that cannot be routed around
  (database, middleware) over patching one handler.`;

/**
 * @param {object} finding  a confirmed finding from the runner
 * @param {{path: string, source: string}} file  the source to patch
 * @param {object} [opts]
 * @returns {Promise<{patch: string|null, model: string|null, reason?: string}>}
 */
export async function proposePatch(finding, file, opts = {}) {
  if (!opts.client && !process.env.ANTHROPIC_API_KEY) {
    return { patch: null, model: null, reason: "ANTHROPIC_API_KEY unset — patch proposal skipped" };
  }
  const client = opts.client ?? new (await import("@anthropic-ai/sdk")).default();
  const model = opts.model ?? "claude-opus-5";

  const user = [
    `OWASP ${finding.owasp} — ${finding.title}`,
    ``,
    `The attack "${finding.id}" landed against ${finding.request.method} ${finding.request.url}.`,
    `Observed response: HTTP ${finding.status}.`,
    finding.evidence ? `Evidence: ${JSON.stringify(finding.evidence)}` : ``,
    ``,
    `File to patch: ${file.path}`,
    "```",
    file.source,
    "```",
    ``,
    `Return the minimal unified diff that makes this attack fail.`,
  ].join("\n");

  const res = await client.messages.create({
    model,
    max_tokens: 4096,
    thinking: { type: "adaptive" },
    output_config: { effort: "high" },
    system: SYSTEM,
    messages: [{ role: "user", content: user }],
  });

  const text = res.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("")
    .trim();

  if (!text || text.startsWith("NO PATCH")) {
    return { patch: null, model, reason: text || "model returned nothing" };
  }
  return { patch: stripFences(text), model };
}

/** Some models wrap diffs in ```diff fences despite instructions; tolerate it. */
function stripFences(text) {
  const fence = text.match(/^```(?:diff|patch)?\n([\s\S]*?)\n```$/);
  return fence ? fence[1] : text;
}
