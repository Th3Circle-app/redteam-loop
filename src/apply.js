/**
 * Apply a unified diff to a throwaway copy of a file.
 *
 * Uses `git apply` in a temp dir so the diff is validated the same way a
 * reviewer's `git apply` would validate it — no hand-rolled patch parser to
 * disagree with git about hunk offsets. The original file is never touched.
 */
import { mkdtemp, writeFile, readFile, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

/**
 * @param {{path: string, source: string}} file
 * @param {string} patch  unified diff
 * @returns {Promise<{ok: boolean, dir?: string, patchedSource?: string, cleanup?: ()=>Promise<void>, reason?: string}>}
 */
export async function applyToCopy(file, patch) {
  const dir = await mkdtemp(join(tmpdir(), "redteam-"));
  const cleanup = () => rm(dir, { recursive: true, force: true });
  try {
    const rel = file.path.replace(/^\/+/, "");
    const abs = join(dir, rel);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, file.source);

    await run("git", ["init", "-q"], { cwd: dir });
    await run("git", ["add", rel], { cwd: dir });

    // Models routinely emit hunk headers as a bare `@@` with no line numbers,
    // which git apply rejects outright. Recompute every header from the source
    // before applying, so a correct change isn't lost to a cosmetic defect.
    const normalized = normalizeHunkHeaders(file.source, patch);

    const patchFile = join(dir, "change.patch");
    await writeFile(patchFile, normalized.endsWith("\n") ? normalized : normalized + "\n");

    // --check first: validate without writing, so a bad diff is a clean "no".
    await run("git", ["apply", "--check", patchFile], { cwd: dir });
    await run("git", ["apply", patchFile], { cwd: dir });

    const patchedSource = await readFile(abs, "utf8");
    return { ok: true, dir, patchedSource, cleanup };
  } catch (err) {
    await cleanup();
    return { ok: false, reason: String(err && err.stderr || err.message || err).trim() };
  }
}

/**
 * Rewrite every hunk header to correct `@@ -start,count +start,count @@` form by
 * locating each hunk's leading context in the source. Handles the common model
 * output of a bare `@@`, and corrects wrong counts on numbered headers too.
 * Throws if a hunk's context can't be found — a diff that doesn't match the
 * source should fail loudly, not be massaged into applying somewhere wrong.
 */
export function normalizeHunkHeaders(source, patch) {
  const srcLines = source.split("\n");
  const lines = patch.split("\n");
  const out = [];
  let i = 0;

  // Pass through the file header (---/+++), untouched.
  while (i < lines.length && !lines[i].startsWith("@@")) {
    out.push(lines[i]);
    i++;
  }

  while (i < lines.length) {
    if (!lines[i].startsWith("@@")) { out.push(lines[i]); i++; continue; }

    // Collect this hunk's body: lines starting with space, -, or +, until the
    // next @@ or EOF.
    const body = [];
    i++;
    while (i < lines.length && !lines[i].startsWith("@@")) {
      const c = lines[i][0];
      if (c === " " || c === "-" || c === "+" || lines[i] === "") body.push(lines[i]);
      else break;
      i++;
    }

    const oldLines = body.filter((l) => l.startsWith(" ") || l.startsWith("-")).map((l) => l.slice(1));
    const newCount = body.filter((l) => l.startsWith(" ") || l.startsWith("+")).length;
    const oldCount = oldLines.length;

    const start = locate(srcLines, oldLines);
    if (start < 0) throw new Error("hunk context not found in source");

    out.push(`@@ -${start + 1},${oldCount} +${start + 1},${newCount} @@`);
    out.push(...body);
  }

  return out.join("\n");
}

/** Find the 0-based index where `block` matches consecutively in `lines`. */
function locate(lines, block) {
  if (block.length === 0) return -1;
  for (let s = 0; s + block.length <= lines.length; s++) {
    let ok = true;
    for (let k = 0; k < block.length; k++) {
      if (lines[s + k] !== block[k]) { ok = false; break; }
    }
    if (ok) return s;
  }
  return -1;
}
