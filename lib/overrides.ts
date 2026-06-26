/**
 * gh-identity-guard — override surfaces.
 *
 * Three surfaces per ADR-0022 § Q5, all of which must announce themselves
 * via `ctx.ui.notify` on use (the "override cannot be silent" contract):
 *
 *   1. SKIP_GH_IDENTITY_GUARD=1  — session-wide env var. Extension installs
 *      no handler at init. Announced once via ctx.ui.notify at init time.
 *      (Checked in index.ts, not here.)
 *
 *   2. .gh-identity-allowlist    — per-repo file at <cwd>/.gh-identity-allowlist.
 *      One pattern per line; `#` comments; blank lines ignored.
 *      MVP semantic: exact substring match against the bash command string.
 *      Glob/regex deferred to Phase 2.
 *
 *   3. GH_IDENTITY_OVERRIDE=<login>  — per-invocation env-var prefix on the
 *      bash command. CHANGES the expected identity for that one call (does
 *      NOT skip the check). The active gh identity must equal <login> or
 *      the call hard-blocks. No fallback to the allowlist on override
 *      mismatch (failed assertions block).
 *
 * Precedence (per ADR-0022 § Q5 and security-review validation):
 *   1. If GH_IDENTITY_OVERRIDE=<login> prefix present → override evaluation
 *      path (active must equal <login>; allowlist never consulted).
 *   2. Otherwise: classify, probe, compare active vs expected.
 *   3. On mismatch → consult allowlist; matching pattern allows-with-notify.
 *   4. Otherwise block.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { isValidGhLogin } from "./identity.ts";

/* --- allowlist ----------------------------------------------------------- */

export function loadAllowlist(cwd: string): string[] {
  const file = join(cwd, ".gh-identity-allowlist");
  if (!existsSync(file)) return [];
  try {
    return readFileSync(file, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));
  } catch {
    return [];
  }
}

export function matchesAllowlist(
  command: string,
  patterns: readonly string[],
): string | null {
  for (const pat of patterns) {
    if (command.includes(pat)) return pat;
  }
  return null;
}

/* --- GH_IDENTITY_OVERRIDE prefix ----------------------------------------- */

export type OverrideParse =
  | { kind: "none" }
  | { kind: "valid"; login: string }
  | { kind: "invalid"; reason: string };

/**
 * Parse `GH_IDENTITY_OVERRIDE=<login>` from the leading env-var-assignment
 * run of a bash command string. POSIX permits any number of leading
 * `NAME=value` assignments before the command word; the override may appear
 * anywhere in that run.
 *
 * Sharpened per security-review validation 2026-05-26:
 *   - Strip a single run of leading whitespace before matching.
 *   - Recognize only at the outer level — NOT inside `bash -c '...'`,
 *     `eval '...'`, command substitution, or heredoc bodies. (Those shapes
 *     are handled by the bypass-DENY net in the classifier; the override
 *     would have no legitimate use there and would be an injection surface.)
 *   - Accept multiple env-var assignments in the leading run (e.g.,
 *     `A=1 B=2 GH_IDENTITY_OVERRIDE=x gh ...`).
 *   - Reject duplicate `GH_IDENTITY_OVERRIDE=` keys in the leading run
 *     (shell-legal but operator-ambiguous).
 *   - Validate <login> against the GitHub username regex before returning
 *     `valid`. Defense-in-depth against prompt-injected newlines/ANSI in
 *     downstream notify text.
 */
export function parseOverride(command: string): OverrideParse {
  // Strip a single leading whitespace run.
  let i = 0;
  while (i < command.length && (command[i] === " " || command[i] === "\t")) i++;
  const rest = command.slice(i);

  // Walk leading NAME=value tokens. Stop at the first token that does not
  // match the assignment shape. Tokens are whitespace-separated; quoted
  // assignment values are accepted but not parsed (we only need to detect
  // the GH_IDENTITY_OVERRIDE key reliably).
  const assignRe = /^([A-Za-z_][A-Za-z0-9_]*)=([^\s]*)/;
  let pos = 0;
  let foundLogin: string | null = null;
  let foundCount = 0;
  while (pos < rest.length) {
    const slice = rest.slice(pos);
    const m = assignRe.exec(slice);
    if (!m) break;
    const name = m[1] ?? "";
    const value = m[2] ?? "";
    if (name === "GH_IDENTITY_OVERRIDE") {
      foundCount++;
      // Strip a single matching wrapping quote pair (operators routinely
      // quote values out of habit: `GH_IDENTITY_OVERRIDE="bot-foo"`).
      let unquoted = value;
      if (
        unquoted.length >= 2 &&
        ((unquoted.startsWith('"') && unquoted.endsWith('"')) ||
          (unquoted.startsWith("'") && unquoted.endsWith("'")))
      ) {
        unquoted = unquoted.slice(1, -1);
      }
      foundLogin = unquoted;
    }
    pos += m[0].length;
    // Skip trailing whitespace before the next token.
    while (pos < rest.length && (rest[pos] === " " || rest[pos] === "\t")) pos++;
  }

  if (foundCount === 0) return { kind: "none" };
  if (foundCount > 1) {
    return {
      kind: "invalid",
      reason:
        "duplicate GH_IDENTITY_OVERRIDE= in leading env-var run is ambiguous",
    };
  }
  if (foundLogin === null || foundLogin === "") {
    return { kind: "invalid", reason: "GH_IDENTITY_OVERRIDE= must name a login" };
  }
  if (!isValidGhLogin(foundLogin)) {
    return {
      kind: "invalid",
      reason: `GH_IDENTITY_OVERRIDE=${JSON.stringify(foundLogin)} is not a valid GitHub login (expected: alnum + single hyphens, optionally with EMU \`_<shortcode>\` suffix where shortcode is 3–8 alnum chars, ≤39 chars total)`,
    };
  }
  return { kind: "valid", login: foundLogin };
}
