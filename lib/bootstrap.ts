/**
 * gh-identity-guard — interactive bootstrap helpers (ADR-0025).
 *
 * When NEITHER identity source is configured, the extension may offer to
 * create `<cwd>/.pi/expected-identity` in an interactive (`ctx.hasUI`)
 * session. This module holds the side-effecting + parsing primitives so they
 * can be unit-tested without a live `ctx.ui`; the prompt orchestration itself
 * lives in `index.ts` (it needs `ctx.ui`).
 *
 * Decisions (ADR-0025): per-repo file is the only write target; the suggested
 * login is reference-only (the operator re-types it) and is suppressed on a
 * personal fork; the triggering call STILL fails closed after the write
 * (A1 commit-gate) so the operator commits the trust anchor and re-runs.
 */

import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Executor } from "./identity.ts";
import { isValidGhLogin } from "./identity.ts";

const GIT_HARDENING: readonly string[] = [
  "-c",
  "core.fsmonitor=",
  "-c",
  "core.hooksPath=/dev/null",
];

/**
 * Parse `{owner, repo}` from a git remote URL. Mirrors `extract_owner` in
 * hooks/gh-identity-guard.sh and the hardened host parsing in lib/remote.ts.
 * Returns empty strings on shapes we do not recognize; callers gate the
 * result behind an active-login equality check, so a bad guess is never
 * offered as a suggestion.
 */
export function parseOwnerRepo(url: string): { owner: string; repo: string } {
  const trimmed = url.trim();
  let path: string;
  if (trimmed.includes("://")) {
    // scheme://[userinfo@]host[:port]/owner/repo[.git]
    const afterScheme = trimmed.slice(trimmed.indexOf("://") + 3);
    const slash = afterScheme.indexOf("/");
    path = slash >= 0 ? afterScheme.slice(slash + 1) : "";
  } else if (/^[^/]+@[^/]+:/.test(trimmed)) {
    // scp-style: user@host:owner/repo[.git]
    path = trimmed.slice(trimmed.indexOf(":") + 1);
  } else {
    path = trimmed;
  }
  const parts = path.split("/").filter((p) => p.length > 0);
  const owner = parts[0] ?? "";
  const repo = (parts[1] ?? "").replace(/\.git$/, "");
  return { owner, repo };
}

/**
 * Best-effort owner of the `origin` remote, parsed from
 * `git -C <cwd> remote get-url origin`. Returns `{owner:"",repo:""}` on any
 * failure (no remote, not a repo, exec error).
 */
export async function originOwnerRepo(
  exec: Executor,
  cwd: string,
): Promise<{ owner: string; repo: string }> {
  try {
    const r = await exec.exec("git", [
      "-C",
      cwd,
      ...GIT_HARDENING,
      "remote",
      "get-url",
      "origin",
    ]);
    if (r.exitCode !== 0) return { owner: "", repo: "" };
    return parseOwnerRepo(r.stdout.trim());
  } catch {
    return { owner: "", repo: "" };
  }
}

/**
 * Is `<owner>/<repo>` a personal fork (has a non-null parent)? Best-effort via
 * `gh repo view <owner>/<repo> --json parent`. An explicit `owner/repo` arg is
 * passed so the result does not depend on the executor's working directory
 * (the `Executor` interface carries no cwd). Returns `false` on any failure —
 * parity with the hook, which treats an empty/failed probe as "not a fork".
 * The re-type requirement is the real safety net (ADR-0025 B1).
 */
export async function isPersonalFork(
  exec: Executor,
  owner: string,
  repo: string,
): Promise<boolean> {
  if (!owner || !repo) return false;
  try {
    const r = await exec.exec("gh", [
      "repo",
      "view",
      `${owner}/${repo}`,
      "--json",
      "parent",
      "--jq",
      'if .parent then "fork" else empty end',
    ]);
    if (r.exitCode !== 0) return false;
    return r.stdout.trim().length > 0;
  } catch {
    return false;
  }
}

/**
 * Compute a reference-only suggested login (ADR-0025 B1): the active login,
 * but only when it equals the `origin` owner, validates, and the repo is not
 * a personal fork. Returns `""` when no suggestion should be offered.
 */
export async function computeSuggestion(
  exec: Executor,
  cwd: string,
  activeLogin: string,
): Promise<{ suggestion: string; owner: string }> {
  const { owner, repo } = await originOwnerRepo(exec, cwd);
  if (
    activeLogin &&
    activeLogin === owner &&
    isValidGhLogin(activeLogin) &&
    !(await isPersonalFork(exec, owner, repo))
  ) {
    return { suggestion: activeLogin, owner };
  }
  return { suggestion: "", owner };
}

/**
 * Atomically write `<cwd>/.pi/expected-identity` with a single login line.
 * Writes to a temp file in the same directory then renames, so a crash mid-
 * write never leaves an empty/partial trust anchor. Mode 0644: the file is a
 * committed, world-readable trust anchor (logins are public), matching its
 * tracked state. Throws on failure (caller surfaces it).
 */
export function writeExpectedIdentity(cwd: string, login: string): string {
  const dir = join(cwd, ".pi");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "expected-identity");
  const tmp = `${path}.tmp.${process.pid}`;
  try {
    writeFileSync(tmp, `${login}\n`, { mode: 0o644 });
    renameSync(tmp, path);
  } catch (err) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      /* best-effort cleanup */
    }
    throw err;
  }
  return path;
}

/** Strip control bytes before echoing operator-typed input to the UI. */
export function sanitizeForDisplay(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f]/g, "");
}
