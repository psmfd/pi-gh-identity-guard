/**
 * gh-identity-guard — `git push` remote-host resolution.
 *
 * Source: ADR-0023 (host-scoping the in-session `git push` classification).
 *
 * The classifier flags every `git push` as identity-relevant because it sees
 * only the command STRING — it cannot know which remote the push targets.
 * This module performs the runtime resolution the classifier cannot:
 * it determines the EFFECTIVE push host and answers whether the operation
 * is in scope for the identity guard (`github.com`) or not (ADO, GitLab,
 * self-hosted, …).
 *
 * The pre-push hook (`hooks/gh-identity-guard.sh`) already does this for the
 * raw-shell vector — git's pre-push contract hands it the resolved remote URL
 * directly. The in-session layer has no such gift, so it shells out to git.
 *
 * Fail posture: **fail closed**. Any state where the effective host cannot be
 * positively confirmed non-`github.com` returns `"indeterminate"`, and the
 * caller keeps gating. A false block costs one `gh auth switch`/override; a
 * false allow is a wrong-account push, which is hard to reverse (ADR-0022
 * cost model). Positively-confirmed non-`github.com` is the ONLY pass-through.
 *
 * Security notes (security-review, #265):
 *   - `git remote get-url --push --all` is the authoritative post-rewrite URL:
 *     it applies `url.<base>.insteadOf` AND `url.<base>.pushInsteadOf`. An
 *     inline `-c url.*.(push)insteadOf=` on the push command is NOT reflected
 *     by a separate subprocess, so the classifier flags that shape and we
 *     fail closed on it here.
 *   - SSH host-aliases (`~/.ssh/config` `Host x` → `HostName github.com`) are
 *     invisible to the stored URL string, so any non-`github.com` SSH-form
 *     host is resolved via `ssh -G <host>` before classification.
 *   - git subprocesses run with `-c core.fsmonitor= -c core.hooksPath=/dev/null`
 *     so a hostile repo's config cannot execute code when we merely resolve a
 *     remote (CVE-2026-45033 class).
 */

import { isAbsolute, resolve } from "node:path";

import type { GitPushInvocation } from "./classifier.ts";
import type { Executor } from "./identity.ts";

export type { GitPushInvocation };

/** In-scope (`github.com`), out-of-scope, or could-not-determine. */
export type HostVerdict = "github" | "non-github" | "indeterminate";

/**
 * Flags prepended to every git subprocess to neutralise local-config code
 * execution in a possibly-hostile working directory. `git remote get-url`
 * and `git rev-parse` can trigger `core.fsmonitor` / hook execution; pinning
 * both to inert values closes that vector. Source: security-review #265.
 */
const GIT_HARDENING: readonly string[] = [
  "-c",
  "core.fsmonitor=",
  "-c",
  "core.hooksPath=/dev/null",
];

/**
 * Extract the host component of a git remote URL. Mirrors the hardened
 * `extract_host()` in `hooks/gh-identity-guard.sh` so both layers classify
 * identically.
 *
 * Handles: `scheme://[user[:pw]@]host[:port]/path`, SCP-style
 * `user@host:path`, double-`@` userinfo, trailing-dot FQDN, case folding.
 * Returns lowercase host, or "" when none can be extracted (caller treats
 * "" as indeterminate). An IPv6-literal authority yields `"["` — acceptable:
 * github.com is never served over an IPv6 literal, so it classifies as
 * non-github, the safe direction.
 */
export function extractHost(url: string): string {
  let u = url.trim();
  // Strip scheme (`anything://`).
  const scheme = u.indexOf("://");
  if (scheme >= 0) u = u.slice(scheme + 3);
  // Host portion is everything before the first `/`. Splitting path off FIRST
  // means a `@` or `:` inside the path can never be mistaken for userinfo/port.
  let hostPart = u.split("/", 1)[0] ?? "";
  // Take everything after the LAST `@` — handles `user:pa@ss@host` (the
  // rightmost `@` separates userinfo from authority).
  const at = hostPart.lastIndexOf("@");
  if (at >= 0) hostPart = hostPart.slice(at + 1);
  // Strip `:port` (HTTPS) or `:path` (SCP-style) — everything from the first
  // colon onward.
  const colon = hostPart.indexOf(":");
  let host = colon >= 0 ? hostPart.slice(0, colon) : hostPart;
  // Strip trailing `.` (absolute-DNS form: `github.com.` ≡ `github.com`).
  host = host.replace(/\.+$/, "");
  return host.toLowerCase();
}

/** Exact, case-insensitive `github.com` membership. Substring matching is
 * forbidden — it would admit `github.com.attacker.tld`, `notgithub.com`, etc. */
export function isGithubHost(host: string): boolean {
  return host === "github.com";
}

/**
 * Does the `git push <repository>` positional look like a URL (vs a named
 * remote like `origin`)? Per git-push(1) GIT URLS: a scheme prefix, a local
 * path, or SCP-style `[user@]host:path` (a colon with no `/` before it).
 */
export function looksLikeUrl(arg: string): boolean {
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(arg)) return true; // scheme://
  if (arg.startsWith("/") || arg.startsWith("./") || arg.startsWith("../")) {
    return true; // local filesystem path
  }
  // SCP-style: a colon appears before any slash.
  const colon = arg.indexOf(":");
  if (colon > 0) {
    const slash = arg.indexOf("/");
    if (slash === -1 || slash > colon) return true;
  }
  return false;
}

/**
 * Is this URL an SSH-transport form whose host may be a `~/.ssh/config` alias?
 * `ssh://…` and SCP-style `[user@]host:path` qualify; `https://`, `git://`,
 * `ftp(s)://`, and local paths do not.
 */
export function isSshForm(url: string): boolean {
  if (/^ssh:\/\//i.test(url)) return true;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(url)) return false; // other scheme
  if (url.startsWith("/") || url.startsWith("./") || url.startsWith("../")) {
    return false; // local path
  }
  const colon = url.indexOf(":");
  if (colon > 0) {
    const slash = url.indexOf("/");
    if (slash === -1 || slash > colon) return true; // SCP-style
  }
  return false;
}

/** Resolve the effective git working directory: each `-C` chains against the
 * previous (git applies them sequentially), starting from `cwd`. */
function effectiveDir(cwd: string, cDirs: readonly string[]): string {
  let dir = cwd;
  for (const c of cDirs) dir = isAbsolute(c) ? c : resolve(dir, c);
  return dir;
}

async function runGit(
  exec: Executor,
  dir: string,
  args: readonly string[],
): Promise<{ exitCode: number; stdout: string }> {
  try {
    const r = await exec.exec("git", [
      "-C",
      dir,
      ...GIT_HARDENING,
      ...args,
    ]);
    return { exitCode: r.exitCode, stdout: r.stdout };
  } catch {
    // Spawn failure (git missing, etc.) → indeterminate, fail closed.
    return { exitCode: -1, stdout: "" };
  }
}

/**
 * Resolve an SSH-form host's real `HostName` via `ssh -G <host>`, returning
 * the lowercased canonical host, or null when ssh is unavailable/errors
 * (caller treats null as indeterminate). `ssh -G` only prints resolved
 * config — it does not connect — so it is safe and fast.
 */
async function resolveSshHost(
  exec: Executor,
  host: string,
): Promise<string | null> {
  let stdout: string;
  let exitCode: number;
  try {
    const r = await exec.exec("ssh", ["-G", host]);
    stdout = r.stdout;
    exitCode = r.exitCode;
  } catch {
    return null;
  }
  if (exitCode !== 0) return null;
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^hostname\s+(\S+)/i.exec(line.trim());
    if (m && m[1]) return m[1].toLowerCase().replace(/\.+$/, "");
  }
  return null;
}

/** Classify a single resolved URL's effective host, resolving SSH aliases. */
async function classifyUrlHost(
  exec: Executor,
  url: string,
): Promise<HostVerdict> {
  const host = extractHost(url);
  if (host === "") return "indeterminate";
  if (isGithubHost(host)) return "github";
  if (isSshForm(url)) {
    // The stored host may be a `~/.ssh/config` alias for github.com.
    const real = await resolveSshHost(exec, host);
    if (real === null) return "indeterminate"; // can't confirm → fail closed
    return isGithubHost(real) ? "github" : "non-github";
  }
  return "non-github";
}

/**
 * Resolve the effective push host for one `git push` invocation.
 * `"github"` or `"indeterminate"` → caller gates; `"non-github"` → pass.
 */
export async function resolvePushHost(
  exec: Executor,
  cwd: string,
  inv: GitPushInvocation,
): Promise<HostVerdict> {
  // An inline `-c …insteadOf=` rewrites the effective URL, and a
  // `--git-dir`/`--work-tree` override points the push at a repo whose config
  // differs from cwd — both make a cwd-based resolution untrustworthy, so we
  // cannot positively confirm the host. Fail closed.
  if (inv.inlineConfigRewrite || inv.repoDirOverride) return "indeterminate";

  const dir = effectiveDir(cwd, inv.cDirs);

  // Collect the candidate push URL(s).
  let urls: string[];
  if (inv.remoteArg !== null && looksLikeUrl(inv.remoteArg)) {
    urls = [inv.remoteArg];
  } else {
    let remoteName = inv.remoteArg;
    if (remoteName === null) {
      // No explicit remote → resolve the branch's effective push remote.
      const rp = await runGit(exec, dir, [
        "rev-parse",
        "--abbrev-ref",
        "@{push}",
      ]);
      if (rp.exitCode !== 0) return "indeterminate"; // detached/no upstream
      const ref = rp.stdout.trim();
      if (ref === "") return "indeterminate";
      remoteName = ref.split("/", 1)[0] ?? "";
      if (remoteName === "") return "indeterminate";
    }
    // `--all` because a remote may carry multiple `pushurl` entries; git
    // pushes to all of them, so any github.com among them is in scope.
    const gu = await runGit(exec, dir, [
      "remote",
      "get-url",
      "--push",
      "--all",
      remoteName,
    ]);
    if (gu.exitCode !== 0) return "indeterminate";
    urls = gu.stdout
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (urls.length === 0) return "indeterminate";
  }

  // Gate if ANY url is github or cannot be confirmed; pass only if ALL are
  // positively non-github.
  let verdict: HostVerdict = "non-github";
  for (const url of urls) {
    const v = await classifyUrlHost(exec, url);
    if (v === "github") return "github";
    if (v === "indeterminate") verdict = "indeterminate";
  }
  return verdict;
}

/**
 * Reduce a set of `git push` invocations (a compound command may contain
 * several) to one verdict. Gate if ANY push is `github`/`indeterminate`;
 * pass only when EVERY push is positively `non-github`.
 */
export async function scopeGitPushes(
  exec: Executor,
  cwd: string,
  pushes: readonly GitPushInvocation[],
): Promise<HostVerdict> {
  let verdict: HostVerdict = "non-github";
  for (const inv of pushes) {
    const v = await resolvePushHost(exec, cwd, inv);
    if (v === "github") return "github";
    if (v === "indeterminate") verdict = "indeterminate";
  }
  return verdict;
}
