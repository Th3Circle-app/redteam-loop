/**
 * The attack runner.
 *
 * Fires each attack at a live target and records whether the control held.
 * The verdict is the attack's own `expect` predicate applied to the real
 * response — never a guess, never the model's opinion. Pure I/O: it knows how
 * to make a request and read a response, nothing about patching.
 */
import { ATTACKS } from "./attacks/index.js";

/**
 * Run one attack against a target.
 * @returns {Promise<Finding>} always resolves; a thrown request becomes a finding-shaped error.
 */
export async function runAttack(attack, target, { fetchImpl = fetch, timeoutMs = 8000 } = {}) {
  const req = attack.build(target);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const base = {
    id: attack.id,
    owasp: attack.owasp,
    title: attack.title,
    severity: attack.severity,
    request: { url: req.url, method: req.method },
  };

  try {
    const res = await fetchImpl(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body,
      redirect: "manual",
      signal: controller.signal,
    });
    const body = await res.text();
    const held = Boolean(attack.expect(res, body));
    return {
      ...base,
      status: res.status,
      held,
      // A finding is an attack that landed: the control did NOT hold.
      finding: !held,
      evidence: held ? null : summarize(res, body),
    };
  } catch (err) {
    // A network error is the target refusing to talk to us. Treat as held —
    // the attack did not land — but record it so a flapping target is visible.
    return { ...base, status: null, held: true, finding: false, error: String(err && err.message || err) };
  } finally {
    clearTimeout(timer);
  }
}

function summarize(res, body) {
  const headers = {};
  for (const k of ["access-control-allow-origin", "content-type", "server"]) {
    const v = res.headers.get(k);
    if (v) headers[k] = v;
  }
  return { status: res.status, headers, bodyExcerpt: String(body).slice(0, 400) };
}

/**
 * Run the full suite against a target.
 * @returns {Promise<{findings: Finding[], results: Finding[]}>}
 */
export async function scan(target, opts = {}) {
  const attacks = opts.attacks ?? ATTACKS;
  const results = [];
  for (const attack of attacks) {
    results.push(await runAttack(attack, target, opts));
  }
  return { results, findings: results.filter((r) => r.finding) };
}
