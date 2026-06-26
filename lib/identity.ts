/**
 * gh-identity-guard — expected-identity resolution.
 *
 * Precedence (ADR-0022 § Q1):
 *   1. <cwd>/.pi/expected-identity           (committed per-repo file; primary)
 *   2. ~/.pi/agent/settings.json             (user-layer fallback at
 *                                             extensionSettings.ghIdentityGuard.expectedIdentity)
 *   3. neither set → null  (caller must fail-closed)
 *
 * Returns `string[] | null`. Multiple logins are allowed in both surfaces
 * (some repos legitimately accept either a bot or a human maintainer).
 *
 * Project-layer settings.json (<cwd>/.pi/settings.json) is NEVER consulted.
 * Per ADR-0019 the project layer is untrusted input; a hostile project
 * setting `expectedIdentity: attacker-login` would silently spoof the guard.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Strip line comments (`# ...`) and trim. Empty lines become "". */
function cleanLine(raw: string): string {
  const hashIdx = raw.indexOf("#");
  const noComment = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;
  return noComment.trim();
}

/**
 * GitHub username regex per first-party docs.
 *
 * Standard accounts: alnum + single internal hyphens (no leading/trailing
 * dash, no consecutive dashes), ≤39 chars.
 *
 * Enterprise Managed Users (EMU): same idp-username shape plus a mandatory
 * `_<shortcode>` suffix, where shortcode is 3–8 alnum chars. Per first-party
 * docs the total length (idp-username + `_` + shortcode) is also capped at
 * 39 chars on github.com (30 on GHE.com data-residency). The regex below is
 * shape-only and over-permissive on length; the explicit `length <= 39`
 * precheck inside `isValidGhLogin` enforces the authoritative cap, mirroring
 * the parallel cap in hooks/gh-identity-guard.sh.
 *
 * Source: https://docs.github.com/en/enterprise-cloud@latest/admin/managing-iam/iam-configuration-reference/username-considerations-for-external-authentication
 */
const GH_LOGIN_RE =
  /^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}(?:_[a-zA-Z0-9]{3,8})?$/;

export function isValidGhLogin(login: string): boolean {
  if (login.length > 39) return false;
  return GH_LOGIN_RE.test(login);
}

/**
 * Read `<cwd>/.pi/expected-identity` with diagnostics.
 *
 * `presentButEmpty` is true iff the file EXISTS and parsed to zero valid
 * logins (the operator-typo case, #259 item 2) — used to surface a WARN
 * before falling through to the user layer.
 *
 * `presentButUnreadable` is true iff the file EXISTS but `readFileSync` throws
 * (e.g. a permission error) — a distinct condition from "absent" that
 * deserves its own operator signal (#268). The two diagnostic flags are
 * mutually exclusive: a read failure short-circuits before parsing.
 */
type TrackingStatus = "tracked" | "untracked" | "indeterminate";

const GIT_HARDENING: readonly string[] = [
  "-c",
  "core.fsmonitor=",
  "-c",
  "core.hooksPath=/dev/null",
];

const EMPTY_PER_REPO_RESULT = {
  logins: null,
  presentButEmpty: false,
  presentButUnreadable: false,
  presentButUntracked: false,
  trackingIndeterminate: false,
} as const;

async function isExpectedIdentityTracked(
  cwd: string,
  exec: Executor,
  signal?: AbortSignal,
): Promise<TrackingStatus> {
  try {
    const result = await exec.exec(
      "git",
      [
        "-C",
        cwd,
        ...GIT_HARDENING,
        "ls-files",
        "--error-unmatch",
        "--",
        ".pi/expected-identity",
      ],
      signal,
    );
    if (result.exitCode === 0) return "tracked";
    if (result.exitCode === 1) return "untracked";
    return "indeterminate";
  } catch {
    return "indeterminate";
  }
}

async function readPerRepoFileDetailed(
  cwd: string,
  exec: Executor,
  signal?: AbortSignal,
): Promise<{
  logins: string[] | null;
  presentButEmpty: boolean;
  presentButUnreadable: boolean;
  presentButUntracked: boolean;
  trackingIndeterminate: boolean;
}> {
  const path = join(cwd, ".pi", "expected-identity");
  if (!existsSync(path)) {
    return { ...EMPTY_PER_REPO_RESULT };
  }
  try {
    if (!statSync(path).isFile()) {
      return {
        ...EMPTY_PER_REPO_RESULT,
        presentButUnreadable: true,
      };
    }
  } catch {
    return {
      ...EMPTY_PER_REPO_RESULT,
      presentButUnreadable: true,
    };
  }
  const tracking = await isExpectedIdentityTracked(cwd, exec, signal);
  if (tracking !== "tracked") {
    return {
      ...EMPTY_PER_REPO_RESULT,
      presentButUntracked: tracking === "untracked",
      trackingIndeterminate: tracking === "indeterminate",
    };
  }
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    // existsSync passed but the read failed — a permission error, or the rare
    // race where the file was removed between the two calls. Either way,
    // surface it rather than silently demoting to "absent" (#268); the
    // behavior (warn, fall through, fail-closed floor) is safe for both.
    return {
      ...EMPTY_PER_REPO_RESULT,
      presentButUnreadable: true,
    };
  }
  const logins = raw
    .split(/\r?\n/)
    .map(cleanLine)
    .filter((l) => l.length > 0)
    .filter(isValidGhLogin);
  if (logins.length > 0) {
    return { ...EMPTY_PER_REPO_RESULT, logins };
  }
  return { ...EMPTY_PER_REPO_RESULT, presentButEmpty: true };
}

/** Read `~/.pi/agent/settings.json` user-layer fallback. */
function readUserLayer(): string[] | null {
  const path = join(homedir(), ".pi", "agent", "settings.json");
  if (!existsSync(path)) return null;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const ext = (parsed as { extensionSettings?: Record<string, unknown> })
    ?.extensionSettings;
  if (!ext || typeof ext !== "object") return null;
  const ours = ext.ghIdentityGuard;
  if (!ours || typeof ours !== "object") return null;
  const value = (ours as { expectedIdentity?: unknown }).expectedIdentity;
  if (typeof value === "string") {
    return isValidGhLogin(value) ? [value] : null;
  }
  if (Array.isArray(value)) {
    const logins = value.filter(
      (v): v is string => typeof v === "string" && isValidGhLogin(v),
    );
    return logins.length > 0 ? logins : null;
  }
  return null;
}

/** Resolution result with per-repo pin-file diagnostics (#259 item 2, #268). */
export interface IdentityResolution {
  /** Resolved logins (per-repo, then user-layer), or null if none. */
  logins: string[] | null;
  /** True iff `<cwd>/.pi/expected-identity` exists but yielded zero valid
   * logins — the caller should WARN, then still fall through (ADR-0022 §Q1). */
  perRepoFilePresentButEmpty: boolean;
  /** True iff `<cwd>/.pi/expected-identity` exists but could not be read
   * (e.g. a permission error) — distinct from absent; the caller should WARN,
   * then fall through to the user layer (#268). */
  perRepoFilePresentButUnreadable: boolean;
  /** True iff `<cwd>/.pi/expected-identity` exists but is not tracked by Git;
   * the caller should WARN, then fall through to the user layer (#306). */
  perRepoFilePresentButUntracked: boolean;
  /** True iff `<cwd>/.pi/expected-identity` exists but Git tracking could not
   * be verified; the caller should WARN, then fall through to the user layer. */
  perRepoFileTrackingIndeterminate: boolean;
}

export async function resolveIdentity(
  cwd: string,
  exec: Executor,
  opts: { signal?: AbortSignal } = {},
): Promise<IdentityResolution> {
  const perRepo = await readPerRepoFileDetailed(cwd, exec, opts.signal);
  if (perRepo.logins) {
    return {
      logins: perRepo.logins,
      perRepoFilePresentButEmpty: false,
      perRepoFilePresentButUnreadable: false,
      perRepoFilePresentButUntracked: false,
      perRepoFileTrackingIndeterminate: false,
    };
  }
  return {
    logins: readUserLayer(),
    perRepoFilePresentButEmpty: perRepo.presentButEmpty,
    perRepoFilePresentButUnreadable: perRepo.presentButUnreadable,
    perRepoFilePresentButUntracked: perRepo.presentButUntracked,
    perRepoFileTrackingIndeterminate: perRepo.trackingIndeterminate,
  };
}

/** Back-compat accessor: logins only. Retained for external/legacy callers
 * and the lib unit tests; `index.ts` uses `resolveIdentity` for the WARN. */
export async function resolveExpectedIdentity(
  cwd: string,
  exec: Executor,
  opts: { signal?: AbortSignal } = {},
): Promise<string[] | null> {
  return (await resolveIdentity(cwd, exec, opts)).logins;
}

/**
 * Active-identity probe. Shells out to `gh api /user --jq .login`.
 *
 * Per ADR-0022 § Q3 there is NO cross-call cache: any TTL window reintroduces
 * the originating defect class (#217) — an out-of-band `gh auth switch` in
 * another shell within the window is exactly the bug this guard exists to
 * close. ~80-150ms per mutation is acceptable.
 *
 * Throws ProbeError on any failure (non-zero exit, missing `gh`, empty
 * stdout, malformed login). Callers fail-closed.
 */
export class ProbeError extends Error {
  readonly kind:
    | "gh-not-found"
    | "exec-failed"
    | "empty-login"
    | "malformed-login";
  constructor(
    kind:
      | "gh-not-found"
      | "exec-failed"
      | "empty-login"
      | "malformed-login",
    message: string,
  ) {
    super(message);
    this.kind = kind;
  }
}

/**
 * Minimal interface for the subprocess runner; mirrors pi's `pi.exec`.
 *
 * The optional `signal` lets `probeActiveIdentity` abort a slow child on
 * timeout. Implementations MAY honor it (the real `spawn`-backed executor
 * forwards it so a hung `gh` is killed and not leaked); test fakes MAY
 * ignore it — the timeout is enforced by `Promise.race` regardless.
 */
export interface Executor {
  exec(
    cmd: string,
    args: readonly string[],
    signal?: AbortSignal,
  ): Promise<{ exitCode: number; stdout: string; stderr: string }>;
}

/** Default probe timeout. A captive-portal/slowloris stall must not hang
 * every mutating tool call indefinitely (#259 item 1). On timeout we throw
 * ProbeError("exec-failed") so callers fail closed. */
const DEFAULT_PROBE_TIMEOUT_MS = 10_000;

export async function probeActiveIdentity(
  exec: Executor,
  opts: { timeoutMs?: number } = {},
): Promise<string> {
  const timeoutMs = Math.max(1, opts.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS);
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The timeout arm MUST reject with a ProbeError (never a bare Error): the
  // call sites re-throw any non-ProbeError, and pi's handling of an unhandled
  // rejection from a tool_call handler is undocumented — a bare Error could
  // fail OPEN. (security-review + code-review, #259.)
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(
        new ProbeError(
          "exec-failed",
          `gh api /user timed out after ${timeoutMs}ms — network stall, captive portal, or API outage.`,
        ),
      );
    }, timeoutMs);
  });

  let result: { exitCode: number; stdout: string; stderr: string };
  try {
    const execPromise = exec.exec(
      "gh",
      ["api", "/user", "--jq", ".login"],
      controller.signal,
    );
    // Swallow a late rejection on the losing branch (e.g. the abort-triggered
    // child error that arrives after the timeout already won the race) so it
    // never surfaces as an unhandledRejection.
    execPromise.catch(() => {});
    result = await Promise.race([execPromise, timeout]);
  } catch (err) {
    // A ProbeError here is the timeout arm — re-throw as-is, never double-wrap.
    if (err instanceof ProbeError) throw err;
    // The timer calls controller.abort() before it rejects, so the spawn's
    // AbortError can win the race ahead of the timer's ProbeError. Normalize
    // any aborted-probe failure to the timeout message so operators see
    // "timed out", not "operation was aborted". (Fail-closed either way.)
    if (controller.signal.aborted) {
      throw new ProbeError(
        "exec-failed",
        `gh api /user timed out after ${timeoutMs}ms — network stall, captive portal, or API outage.`,
      );
    }
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    const msg = err instanceof Error ? err.message : String(err);
    if (code === "ENOENT" || /ENOENT|not found|spawn gh/i.test(msg)) {
      throw new ProbeError(
        "gh-not-found",
        "`gh` is not on PATH — cannot probe active identity.",
      );
    }
    throw new ProbeError("exec-failed", `gh exec failed: ${msg}`);
  } finally {
    clearTimeout(timer);
  }
  if (result.exitCode !== 0) {
    // Strip ANSI escapes from stderr tail before interpolation — defense in
    // depth against future `gh` versions emitting colored error output that
    // could pass control sequences into model-visible text.
    const ansiRe = /\x1b\[[0-9;]*[A-Za-z]/g;
    const cleaned = result.stderr.replace(ansiRe, "");
    const tail = cleaned.trim().split("\n").slice(-3).join(" | ");
    throw new ProbeError(
      "exec-failed",
      `gh api /user exited ${result.exitCode}: ${tail || "(no stderr)"}`,
    );
  }
  const login = result.stdout.trim();
  if (login === "") {
    throw new ProbeError(
      "empty-login",
      "gh api /user returned an empty login — token may be expired or revoked.",
    );
  }
  if (!isValidGhLogin(login)) {
    throw new ProbeError(
      "malformed-login",
      `gh api /user returned a value that is not a valid GitHub login: ${JSON.stringify(login)}`,
    );
  }
  return login;
}
