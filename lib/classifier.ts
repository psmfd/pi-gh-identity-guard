/**
 * gh-identity-guard — bash command classifier.
 *
 * Source of truth: ADR-0022 § Q2 (mutation matcher scope).
 *
 * Pipeline per call:
 *   1. Strip heredoc bodies from the command string (they routinely contain
 *      documented commands; ADR-0022 § Q2.E).
 *   2. Detect the bypass-DENY net (`bash -c`, `eval`, command substitution,
 *      `xargs gh|git`). If any prefix is present AND the outer string mentions
 *      `gh` or `git push`, force identity verification (do not outright deny —
 *      ADR-0022 § Q2.D).
 *   3. Split the (heredoc-stripped) command on shell separators
 *      `&&`, `||`, `;`, `|`, newline. Tokenize each segment respecting
 *      single- and double-quoting.
 *   4. For each simple command, apply the classifier rules:
 *        - argv[0] skip-list short-circuit
 *        - --help / --dry-run short-circuit
 *        - `gh <noun> <verb>` table (noun-scoped verbs)
 *        - `gh api` mutating-method / implicit-POST-flag detection
 *        - `git push` blanket
 *
 * Return: { mutating: boolean, reason?: string }. A truthy `mutating` means
 * the call requires identity verification.
 */

import {
  ARGV0_SKIP_LIST,
  GH_API_IMPLICIT_POST_FLAGS,
  GH_API_MUTATING_METHODS,
  GH_API_NONMUTATING_METHODS,
  GIT_GLOBAL_FLAGS_BARE,
  GIT_GLOBAL_FLAGS_WITH_ARG,
  MUTATING_VERBS,
  SHORT_CIRCUIT_FLAGS,
  WRAPPER_BINARIES,
} from "./nouns.ts";

export interface ClassifyResult {
  mutating: boolean;
  /** Human-readable explanation; only set when `mutating === true`. */
  reason?: string;
  /**
   * True when the mutation MUST be gated regardless of any remote-host check:
   * a `gh` mutation (inherently github.com) or a bypass-DENY-net shape (whose
   * effective remote cannot be reliably resolved → fail closed). When false
   * and `mutating` is true, the mutation is `git push`-only and the caller
   * should host-scope it via `gitPushes` before gating. ADR-0023.
   */
  unconditional: boolean;
  /**
   * True ONLY for the bypass-DENY-net shape (a shell interpreter / `eval` /
   * `xargs` / command substitution wrapping `gh`/`git push`). Distinct from
   * `unconditional`, which is ALSO true for an ordinary `gh` mutation. Used by
   * the interactive bootstrap (ADR-0025) to refuse prompting on an abnormal
   * call — a trust anchor must be created from a clean, statically-reasoned
   * mutating command, not a shape where static reasoning already failed.
   */
  bypassNet: boolean;
  /**
   * Every `git push` simple-command found (a compound command may contain
   * several). Populated only for the host-scoped path; empty when
   * `unconditional` is true. The caller resolves each invocation's effective
   * host and gates if ANY is github.com or indeterminate.
   */
  gitPushes: GitPushInvocation[];
  /**
   * True iff at least one mutating segment was EXEMPTED from gating because a
   * `SKIP_GH_IDENTITY_GUARD=1` assignment leads that same segment (the
   * per-command inline skip, #276). Exempted segments are NOT added to
   * `gitPushes` and do NOT set `reason`/`unconditional`. The caller uses this
   * only to emit the mandatory "operator skip" announcement; it is an
   * operator-controlled disable, never an agent action. The skip is honored
   * per-segment so `SKIP_GH_IDENTITY_GUARD=1 true && git push` does NOT exempt
   * the push, and it is IGNORED for bypass-DENY-net shapes (those always gate).
   */
  inlineSkip: boolean;
}

/**
 * A single parsed `git push` invocation handed to the remote-host resolver.
 * Defined here (where it is produced from the command string) and consumed by
 * `lib/remote.ts`; keeping the type here lets the classifier stay free of any
 * subprocess/`Executor` dependency. ADR-0023.
 */
export interface GitPushInvocation {
  /** Wrapper- and assignment-stripped argv of the `git` command. */
  readonly argv: readonly string[];
  /** Values of `-C <dir>` global flags, in order (chained against cwd). */
  readonly cDirs: readonly string[];
  /** The parsed `<repository>` positional / `--repo=` value, or null (bare). */
  readonly remoteArg: string | null;
  /** True iff an inline `-c url.*.(push)insteadOf=` flag is present — an
   * out-of-band subprocess cannot observe it, so resolution is untrustworthy
   * and the caller must fail closed. */
  readonly inlineConfigRewrite: boolean;
  /** True iff `--git-dir`/`--work-tree` is present — the push targets a repo
   * whose config differs from `cwd`, so a `cwd`-based remote resolution could
   * misclassify it. The caller must fail closed (gate). ADR-0023. */
  readonly repoDirOverride: boolean;
}

/**
 * Strip heredoc bodies from a bash command string. Operators routinely embed
 * documented commands inside heredocs (e.g. `cat <<EOF\ngh pr create ...\nEOF`)
 * and they must not classify as mutating. ADR-0022 § Q2.E.
 *
 * Important: the heredoc OPERATOR and DELIMITER on the marker line are
 * removed, but the rest of the marker line is preserved. Bash treats
 * `cat <<EOF; gh pr merge 42` as `cat <<EOF` followed by `; gh pr merge 42`
 * — the suffix is still part of the live command list. The previous
 * implementation dropped the suffix and was bypassable
 * (code-review 2026-05-26 CRITICAL).
 *
 * Supports: `<<EOF`, `<<-EOF`, `<<'EOF'`, `<<"EOF"`, `<<-"EOF"`. Quoted
 * delimiters disable parameter expansion in real bash; for classification
 * we treat them identically (we just need to skip the body).
 */
export function stripHeredocs(command: string): string {
  const lines = command.split("\n");
  const out: string[] = [];
  let skipUntil: string | null = null;
  let skipStrip = false;
  const heredocRe = /<<(-)?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/;
  for (const line of lines) {
    if (skipUntil !== null) {
      const candidate = skipStrip ? line.replace(/^\t+/, "") : line;
      if (candidate === skipUntil) {
        skipUntil = null;
        skipStrip = false;
      }
      // Drop the heredoc body line entirely.
      continue;
    }
    const m = heredocRe.exec(line);
    if (m) {
      skipStrip = m[1] === "-";
      skipUntil = m[3] ?? "";
      // Strip ONLY the heredoc operator + delimiter, preserving both the
      // text before it (the command receiving the redirect) AND any suffix
      // after the delimiter (separator + further commands on the same line).
      out.push(line.slice(0, m.index) + line.slice(m.index + m[0].length));
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}

/**
 * Tokenize a single simple-command segment. Respects single- and double-quoting
 * (no interpolation; we only need correct delimiter handling). Backslash
 * outside quotes escapes the next character. Whitespace separates tokens.
 */
export function tokenize(segment: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  while (i < segment.length) {
    const ch = segment[i];
    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      } else {
        cur += ch;
      }
      i++;
      continue;
    }
    if (inDouble) {
      if (ch === "\\" && i + 1 < segment.length) {
        // In real bash, backslash inside double quotes is special only for
        // $, `, ", \, newline. For tokenization we accept either way.
        cur += segment[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') {
        inDouble = false;
      } else {
        cur += ch;
      }
      i++;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      i++;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < segment.length) {
      cur += segment[i + 1];
      i += 2;
      continue;
    }
    if (ch === " " || ch === "\t") {
      if (cur !== "") {
        tokens.push(cur);
        cur = "";
      }
      i++;
      continue;
    }
    cur += ch;
    i++;
  }
  if (cur !== "") tokens.push(cur);
  return tokens;
}

/**
 * Split a command string into simple-command segments on shell separators
 * `&&`, `||`, `;`, `|`, newline. Respects quoting (does not split on
 * separators inside `'...'` or `"..."`).
 */
export function splitSegments(command: string): string[] {
  const segments: string[] = [];
  let cur = "";
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  while (i < command.length) {
    const ch = command[i];
    const next = command[i + 1];
    if (!inSingle && !inDouble) {
      if (ch === "&" && next === "&") {
        segments.push(cur);
        cur = "";
        i += 2;
        continue;
      }
      if (ch === "|" && next === "|") {
        segments.push(cur);
        cur = "";
        i += 2;
        continue;
      }
      if (ch === ";" || ch === "|" || ch === "\n") {
        segments.push(cur);
        cur = "";
        i++;
        continue;
      }
    }
    if (!inDouble && ch === "'") inSingle = !inSingle;
    else if (!inSingle && ch === '"') inDouble = !inDouble;
    cur += ch;
    i++;
  }
  if (cur !== "") segments.push(cur);
  return segments;
}

/** Path basename, mirrors POSIX `basename`. */
function basename(p: string): string {
  const slash = p.lastIndexOf("/");
  return slash >= 0 ? p.slice(slash + 1) : p;
}

/**
 * After tokenization, strip leading `NAME=value` env-var assignments so we
 * can correctly identify argv[0]. POSIX permits any number of leading
 * assignments before the command word (`A=1 B=2 gh pr create ...`).
 */
function stripLeadingAssignments(tokens: string[]): string[] {
  let i = 0;
  const re = /^[A-Za-z_][A-Za-z0-9_]*=/;
  while (i < tokens.length && re.test(tokens[i] ?? "")) i++;
  return tokens.slice(i);
}

/**
 * Detect a per-command inline `SKIP_GH_IDENTITY_GUARD=1` skip in the LEADING
 * `NAME=value` assignment run of a single (already-tokenized) segment (#276).
 *
 * Honored per-SEGMENT and only as a genuine command-prefix assignment, because
 * that is the only form the shell actually delivers to the executed command:
 *   - `SKIP_GH_IDENTITY_GUARD=1 git push`        → prefix on `git push` → honored
 *   - `SKIP_GH_IDENTITY_GUARD=1 true && git push`→ prefix on `true`; `git push`
 *     is a separate segment with no prefix → NOT honored for the push
 *   - `SKIP_GH_IDENTITY_GUARD=1; git push`       → bare assignment, never reaches
 *     `git push`'s environment → NOT honored
 * (Verified against bash assignment semantics; see ADR-0024.)
 *
 * The value must be exactly `1` (matching the session-wide `=== "1"` contract);
 * `tokenize()` has already removed any wrapping quotes, so `="1"`/`='1'` arrive
 * as `1`. `=0`/`=true`/`=` are not a skip. The `export VAR=1` builtin form is
 * deliberately NOT recognized (operators use the session-wide skip for that).
 */
function hasInlineSkip(tokens: readonly string[]): boolean {
  const re = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
  for (const tok of tokens) {
    const m = re.exec(tok);
    if (!m) break; // first non-assignment token is the command word
    if (m[1] === "SKIP_GH_IDENTITY_GUARD" && m[2] === "1") return true;
  }
  return false;
}

/**
 * Strip wrapper-binary prefixes from argv. Operators routinely run
 * `env GH_TOKEN=x gh pr create ...`, `nohup gh ...`, `timeout 60 gh ...`,
 * `sudo gh ...`. Without this pass the wrapper binary is argv[0] and
 * `gh`/`git` classification never fires. Source: security-review 2026-05-26
 * (HIGH wrapper-binary bypass).
 *
 * Strategy: peel known wrappers from the front, skipping the wrapper's own
 * options. Bounded recursion (max 3 wrappers deep) to handle
 * `sudo env gh ...` / `nohup timeout 60 gh ...`.
 */
function stripWrappers(argv: readonly string[], depth = 0): readonly string[] {
  if (depth >= 3 || argv.length === 0) return argv;
  const head = basename(argv[0] ?? "");
  if (!WRAPPER_BINARIES.has(head)) return argv;
  let i = 1;
  // Skip leading NAME=value assignments (env-style)
  const assignRe = /^[A-Za-z_][A-Za-z0-9_]*=/;
  while (i < argv.length && assignRe.test(argv[i] ?? "")) i++;
  // Skip option flags. The wrapper-options grammar varies (gnu-long
  // `--signal=KILL`, bsd-short `-oL`, short-with-value `nice -n 10`), so we
  // use a conservative heuristic: skip the flag token, then optionally
  // consume one non-flag value — BUT only if that value doesn't look like
  // a binary name we'd want to classify (gh, git, or another wrapper).
  // This avoids over-consumption on `stdbuf -oL gh ...` where `-oL` is a
  // glued flag and `gh` is the wrapped command.
  while (i < argv.length && (argv[i] ?? "").startsWith("-")) {
    const opt = argv[i] ?? "";
    i++;
    if (opt.includes("=")) continue; // --foo=bar self-contained
    const next = argv[i] ?? "";
    if (next === "" || next.startsWith("-")) continue;
    const nextBase = basename(next);
    if (nextBase === "gh" || nextBase === "git" || WRAPPER_BINARIES.has(nextBase)) {
      // The "value" is actually the wrapped command — do not consume.
      continue;
    }
    i++;
  }
  // `timeout` takes a positional duration; if the next token looks like a
  // duration (digits + optional unit) or pure digits, skip it.
  if (head === "timeout" && i < argv.length && /^\d+[smhd]?$/.test(argv[i] ?? "")) {
    i++;
  }
  const rest = argv.slice(i);
  if (rest.length === 0) return rest;
  return stripWrappers(rest, depth + 1);
}

/**
 * Parse a `git` argv (already wrapper- and assignment-stripped) into a
 * `GitPushInvocation`, or null when the command is not a `git push`.
 *
 * Walks global flags first — handling `-C <path>`, `-c <key=val>`,
 * `--git-dir=...`/`--git-dir <path>`, `--paginate`, `--no-pager`, etc. —
 * to locate the subcommand (security-review 2026-05-26 HIGH `git -C path push`
 * bypass). It additionally captures:
 *   - every `-C <dir>` (the effective working directory the resolver must use),
 *   - an inline `-c url.*.(push)insteadOf=` rewrite (direction-agnostic;
 *     forces fail-closed because a separate subprocess cannot see it),
 *   - the `<repository>` positional / `--repo=` value, parsed past push
 *     options that take a value (`-o`/`--push-option` are space-valued and
 *     would otherwise be mistaken for the remote). ADR-0023.
 */
function parseGitPush(argv: readonly string[]): GitPushInvocation | null {
  const cDirs: string[] = [];
  let inlineConfigRewrite = false;
  let repoDirOverride = false;
  let i = 1; // skip argv[0] === "git"
  let subIdx = -1;
  while (i < argv.length) {
    const tok = argv[i] ?? "";
    if (!tok.startsWith("-")) {
      subIdx = i;
      break;
    }
    if (tok === "-C") {
      const v = argv[i + 1] ?? "";
      if (v !== "") cDirs.push(v);
      i += 2;
      continue;
    }
    if (tok === "-c") {
      const v = argv[i + 1] ?? "";
      if (/^url\..*\.(push)?insteadof=/i.test(v)) inlineConfigRewrite = true;
      i += 2;
      continue;
    }
    // `--git-dir`/`--work-tree` (space or `=` form) repoint git at a repo
    // whose config differs from cwd; a cwd-based resolution would be wrong, so
    // flag it and fail closed downstream (ADR-0023).
    if (tok === "--git-dir" || tok === "--work-tree") {
      repoDirOverride = true;
      i += 2;
      continue;
    }
    if (tok.includes("=")) {
      if (/^--(git-dir|work-tree)=/.test(tok)) repoDirOverride = true;
      i++;
      continue;
    }
    if (GIT_GLOBAL_FLAGS_BARE.has(tok)) {
      i++;
      continue;
    }
    if (GIT_GLOBAL_FLAGS_WITH_ARG.has(tok)) {
      i += 2;
      continue;
    }
    // Unknown flag — conservative: assume bare.
    i++;
  }
  if (subIdx === -1 || (argv[subIdx] ?? "") !== "push") return null;

  // Parse `git push [options] [<repository> [<refspec>...]]` for the remote.
  let remoteArg: string | null = null;
  let j = subIdx + 1;
  while (j < argv.length) {
    const tok = argv[j] ?? "";
    if (tok.startsWith("--repo=")) {
      remoteArg = tok.slice("--repo=".length);
      break;
    }
    if (tok === "--repo") {
      remoteArg = argv[j + 1] ?? null;
      break;
    }
    // Push options whose value is a separate token — skip the value so it is
    // not mistaken for the <repository> positional. (`-o`/`--push-option`
    // repeat; `--receive-pack`/`--exec` are usually `=`-joined but accept a
    // space form too.)
    if (
      tok === "-o" ||
      tok === "--push-option" ||
      tok === "--receive-pack" ||
      tok === "--exec"
    ) {
      j += 2;
      continue;
    }
    if (tok.startsWith("-")) {
      j++; // any other flag (bare or `=`-joined) — self-contained
      continue;
    }
    remoteArg = tok; // first non-flag positional is the remote
    break;
  }
  return { argv: [...argv], cDirs, remoteArg, inlineConfigRewrite, repoDirOverride };
}

/**
 * Classify a single simple command (already tokenized + assignment-stripped).
 * Returns the classification kind and (optionally) a short reason fragment
 * naming the matched rule.
 */
function classifySimpleCommand(argvIn: readonly string[]): {
  kind: "skip" | "not-mutating" | "mutating";
  rule?: string;
  /** Present only for a `git push` match — the parsed invocation for the
   * caller to host-scope. Absent for `gh` mutations. ADR-0023. */
  gitPush?: GitPushInvocation;
} {
  if (argvIn.length === 0) return { kind: "not-mutating" };
  // Peel wrapper binaries (env, nohup, timeout, sudo, ...).
  const argv = stripWrappers(argvIn);
  if (argv.length === 0) return { kind: "not-mutating" };
  const argv0 = basename(argv[0] ?? "");
  if (ARGV0_SKIP_LIST.has(argv0)) return { kind: "skip" };
  // --help / --dry-run anywhere → not mutating. (`-h` deliberately not in
  // the set: too easily defused by `--title "fix -h bug"`. `gh`/`git` handle
  // `-h` themselves — they print help and make no API call — so the worst
  // case of letting it through is one probe + an allow.)
  for (const tok of argv) {
    if (SHORT_CIRCUIT_FLAGS.has(tok)) return { kind: "not-mutating" };
  }

  // `gh <noun> <verb>` table
  if (argv0 === "gh" && argv.length >= 3) {
    const noun = argv[1] ?? "";
    const verb = argv[2] ?? "";
    if (noun === "api") {
      return classifyGhApi(argv) ?? { kind: "not-mutating" };
    }
    const verbs = MUTATING_VERBS[noun];
    if (verbs && verbs.has(verb)) {
      return { kind: "mutating", rule: `gh ${noun} ${verb}` };
    }
    return { kind: "not-mutating" };
  }

  // `gh api ...` (also reachable via argv.length === 2 — bare `gh api PATH`)
  if (argv0 === "gh" && argv.length >= 2 && argv[1] === "api") {
    return classifyGhApi(argv) ?? { kind: "not-mutating" };
  }

  // `git push` — handle global flags. `git -C path push origin main`,
  // `git -c user.name=foo push`, `git --git-dir=... push` all evade a naive
  // `argv[1] === 'push'` rule (security-review 2026-05-26 HIGH). The parsed
  // invocation is host-scoped by the caller before gating (ADR-0023).
  if (argv0 === "git") {
    const gitPush = parseGitPush(argv);
    if (gitPush) {
      return { kind: "mutating", rule: "git push", gitPush };
    }
  }

  return { kind: "not-mutating" };
}

/**
 * Detect mutating `gh api` invocations: explicit method or implicit-POST flag.
 *
 * Precedence (ADR-0022 § Q2.B/Q2.F):
 *   1. An explicit mutating method (`-X POST`/`--method PATCH`/…) → mutating.
 *   2. An explicit read method (`-X GET`/`-X HEAD`) → NOT mutating, even when
 *      implicit-POST flags (`-f`/`-F`/…) are also present — real `gh` honors
 *      the explicit method (`-X GET -f q=x` is a GET with query params).
 *   3. No explicit (recognized) method, but an implicit-POST flag → mutating.
 *
 * The LAST `-X`/`--method` wins (mirrors `gh`/curl). An unrecognized or
 * malformed `-X` value (empty, another flag, garbage) is ignored as a method
 * override and falls through to implicit-POST detection — fail closed.
 */
function classifyGhApi(
  argv: readonly string[],
): { kind: "mutating"; rule: string } | null {
  let explicitMethod: string | null = null;
  let implicitFlag: string | null = null;
  for (let i = 1; i < argv.length; i++) {
    const tok = argv[i] ?? "";
    if (tok === "-X" || tok === "--method") {
      explicitMethod = (argv[i + 1] ?? "").toUpperCase();
    } else if (tok.startsWith("-X") && tok.length > 2) {
      explicitMethod = tok.slice(2).toUpperCase(); // `-XPOST`
    } else if (tok.startsWith("--method=")) {
      explicitMethod = tok.slice("--method=".length).toUpperCase();
    } else if (GH_API_IMPLICIT_POST_FLAGS.has(tok) && implicitFlag === null) {
      implicitFlag = tok;
    }
    // NB: we intentionally do NOT `i++` past an `-X`/`--method` VALUE token.
    // Re-scanning it is a no-op for real method names (GET/POST/… are not
    // implicit-POST flags), and for the malformed `gh api -X -f x=1` it makes
    // the stray `-f` set implicitFlag → classified mutating (fail-closed),
    // which the security review relies on. Skipping the value would flip that
    // edge to non-mutating.
  }

  if (explicitMethod !== null) {
    if (GH_API_MUTATING_METHODS.has(explicitMethod)) {
      return { kind: "mutating", rule: `gh api -X ${explicitMethod}` };
    }
    // An explicit READ method overrides any implicit-POST flag.
    if (GH_API_NONMUTATING_METHODS.has(explicitMethod)) {
      return null;
    }
    // Unrecognized/malformed `-X` value: ignore it, fall through.
  }

  if (implicitFlag !== null) {
    return { kind: "mutating", rule: `gh api ${implicitFlag} (implicit POST)` };
  }
  return null;
}

/**
 * Extract the inner text of every top-level `$(...)` command substitution,
 * matching parentheses with depth tracking so a nested `$(...)` is captured
 * whole. The previous `/\$\(([^)]*)\)/g` regex stopped at the FIRST `)`, so a
 * mention sitting after a nested close — `$(foo $(bar) gh push)` — was missed
 * and the bypass-DENY net could be evaded. ADR-0022 § Q2 (accepted-limitation
 * hardening, #259 item 5).
 *
 * An unterminated `$(` (no matching close) yields the remainder of the string
 * as its inner — conservative / fail-closed: an unbalanced substitution that
 * mentions `gh` still forces identity verification. Parens are counted
 * regardless of quoting; over-detection is the safe direction for a guard.
 */
export function extractDollarParenInners(command: string): string[] {
  const inners: string[] = [];
  let i = 0;
  while (i < command.length) {
    if (command[i] === "$" && command[i + 1] === "(") {
      let depth = 1;
      let j = i + 2;
      while (j < command.length && depth > 0) {
        const ch = command[j];
        if (ch === "(") depth++;
        else if (ch === ")") depth--;
        if (depth === 0) break;
        j++;
      }
      // Inner is the content between `$(` and its matching `)` (or end of
      // string when unbalanced). A nested `$(...)` is included verbatim, so
      // testing the outer inner already covers any nested mention.
      inners.push(command.slice(i + 2, j));
      i = depth === 0 ? j + 1 : j;
    } else {
      i++;
    }
  }
  return inners;
}

/**
 * Bypass-DENY net per ADR-0022 § Q2.D. Returns true when the command
 * contains a shell-interpreter prefix, `eval`, `xargs gh|git`, or command
 * substitution that mentions `gh` or `git push`. In that case the caller
 * should force identity verification regardless of segment classification.
 */
export function detectBypass(command: string): boolean {
  const ghWordRe = /(^|[^a-zA-Z0-9_])gh($|[^a-zA-Z0-9_])/;
  const mentionsGh = ghWordRe.test(command) || /git\s+push/.test(command);
  if (!mentionsGh) return false;

  const bypassPatterns: RegExp[] = [
    /\b(bash|sh|dash|zsh|ksh)\s+-c\b/,
    /\bbusybox\s+sh\s+-c\b/,
    /\beval\s/,
    // xargs followed eventually by gh/git, allowing any option flags or
    // option-values in between. Source: code-review 2026-05-26 ERROR
    // (`xargs -I {} gh ...`, `xargs -L 5 gh ...`).
    /\bxargs\b[^\n]*?\b(gh|git)\b/,
  ];
  for (const re of bypassPatterns) {
    if (re.test(command)) return true;
  }
  // Command substitution containing `gh ` or `git push`
  // `$(...)` form — balanced-paren extraction handles nesting.
  for (const inner of extractDollarParenInners(command)) {
    if (ghWordRe.test(inner) || /git\s+push/.test(inner)) {
      return true;
    }
  }
  // Backtick form (backticks do not nest in shell)
  const backtickRe = /`([^`]*)`/g;
  let m: RegExpExecArray | null;
  while ((m = backtickRe.exec(command)) !== null) {
    const inner = m[1] ?? "";
    if (ghWordRe.test(inner) || /git\s+push/.test(inner)) {
      return true;
    }
  }
  return false;
}

/**
 * Top-level classifier. Returns `{ mutating: true, reason }` when the call
 * requires identity verification, otherwise `{ mutating: false }`.
 */
export function classify(command: string): ClassifyResult {
  const notMutating: ClassifyResult = {
    mutating: false,
    unconditional: false,
    bypassNet: false,
    gitPushes: [],
    inlineSkip: false,
  };
  if (command.trim() === "") return notMutating;
  const stripped = stripHeredocs(command);

  // Bypass-DENY net: force identity verification on suspect shapes. The
  // effective remote of a `git push` hidden inside `bash -c`/`eval`/`$(...)`
  // cannot be reliably resolved, so this is an UNCONDITIONAL gate — no
  // host-scoping (ADR-0023; fail closed). A per-command inline skip is
  // deliberately NOT honored here: the bypass-net exists precisely for shapes
  // where static reasoning fails, so it always gates (ADR-0024; #276).
  if (detectBypass(stripped)) {
    return {
      mutating: true,
      reason:
        "shell-interpreter, eval, xargs, or command substitution alongside `gh`/`git push` (bypass-DENY net forces identity verification)",
      unconditional: true,
      bypassNet: true,
      gitPushes: [],
      inlineSkip: false,
    };
  }

  // Scan every segment. A `gh` mutation gates unconditionally (inherently
  // github.com); `git push` segments are collected for host-scoping. A
  // mutating segment whose OWN leading run carries `SKIP_GH_IDENTITY_GUARD=1`
  // is EXEMPTED (per-segment, #276) — it is not gated, but its presence is
  // recorded in `inlineSkip` so the caller can announce the operator skip.
  let ghReason: string | undefined;
  const gitPushes: GitPushInvocation[] = [];
  let inlineSkip = false;
  for (const segment of splitSegments(stripped)) {
    const tokens = tokenize(segment);
    const argv = stripLeadingAssignments(tokens);
    const result = classifySimpleCommand(argv);
    if (result.kind !== "mutating") continue;
    if (hasInlineSkip(tokens)) {
      // Operator disabled the guard for THIS segment only.
      inlineSkip = true;
      continue;
    }
    if (result.gitPush) {
      gitPushes.push(result.gitPush);
    } else if (ghReason === undefined) {
      ghReason = result.rule ?? "matched mutating rule";
    }
  }

  if (ghReason !== undefined) {
    // A non-exempt gh mutation present → always gate.
    return {
      mutating: true,
      reason: ghReason,
      unconditional: true,
      bypassNet: false,
      gitPushes,
      inlineSkip,
    };
  }
  if (gitPushes.length > 0) {
    return {
      mutating: true,
      reason: "git push",
      unconditional: false,
      bypassNet: false,
      gitPushes,
      inlineSkip,
    };
  }
  // No NON-exempt mutation. `inlineSkip` may still be true (every mutating
  // segment was skip-exempted) — the caller allows the call but announces.
  return { ...notMutating, inlineSkip };
}
