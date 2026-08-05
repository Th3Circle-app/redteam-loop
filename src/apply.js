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

    const patchFile = join(dir, "change.patch");
    await writeFile(patchFile, patch.endsWith("\n") ? patch : patch + "\n");

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
