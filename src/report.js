/**
 * Render a loop report as a GitHub issue body: what landed, its OWASP class,
 * the offending request, the proposed patch, and whether the patch verified.
 * Text in, text out — no side effects, so it is trivially testable.
 */
export function toIssueMarkdown(report) {
  const lines = [];
  lines.push(`## Security scan — ${report.target}`);
  lines.push("");
  lines.push(
    `**${report.counts.findings}** finding(s) · ` +
      `**${report.counts.patched}** with a proposed patch · ` +
      `**${report.counts.verified}** verified closed`
  );
  lines.push("");

  if (report.items.length === 0) {
    lines.push("No findings. Every attack was refused.");
    return lines.join("\n");
  }

  for (const item of report.items) {
    const f = item.finding;
    lines.push(`### ${f.owasp} · ${f.title}`);
    lines.push("");
    lines.push(`- **Attack:** \`${f.id}\` (${f.severity})`);
    lines.push(`- **Request:** \`${f.request.method} ${f.request.url}\``);
    lines.push(`- **Observed:** HTTP ${f.status ?? "—"} (control did not hold)`);
    if (f.evidence?.bodyExcerpt) {
      lines.push(`- **Evidence:** \`${f.evidence.bodyExcerpt.slice(0, 120).replace(/\n/g, " ")}\``);
    }
    lines.push("");

    if (item.patch) {
      lines.push(`**Proposed patch** (${item.model ?? "model"}):`);
      lines.push("```diff");
      lines.push(item.patch.trim());
      lines.push("```");
      if (item.verified?.closed === true) {
        lines.push(`> ✅ Verified: attack re-run against the patched copy and refused (HTTP ${item.verified.status}).`);
      } else if (item.verified?.applied) {
        lines.push(`> ⚠️ Patch applies cleanly; no retarget hook configured to re-run the attack. Human verify before merge.`);
      } else if (item.verified) {
        lines.push(`> ❌ Not verified: ${item.verified.reason}`);
      }
    } else {
      lines.push(`_No patch proposed: ${item.note ?? "unknown"}_`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("_Proposed by redteam-loop. A human merges — nothing here was applied to the repository._");
  return lines.join("\n");
}
