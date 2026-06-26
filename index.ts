/**
 * gh-identity-guard — pi extension
 *
 * Tool-boundary guard that intercepts mutating GitHub invocations from the
 * `bash` tool, verifies the active gh CLI identity matches an expected
 * identity declared per-repo, and blocks on drift.
 *
 * Structural answer to the silent `gh auth status` drift defect (pi_config
 * #217). Supersedes the procedural skill-text fix from PR #251 as the
 * primary enforcement layer; the procedural text and
 * `scripts/lib/gh-verify-user.sh` survive as belt-and-suspenders.
 *
 * What it blocks:
 *   - `gh <noun> <verb>` mutations (noun-scoped verb table)
 *   - `gh api -X POST|PATCH|PUT|DELETE` (and `--method`, `-XPOST` forms)
 *   - `gh api` with `-f|--field|-F|--raw-field|--input` (implicit POST)
 *   - `git push` in any form
 *   - Compound/bypass shapes (`bash -c`, `eval`, `xargs gh|git`, command
 *     substitution) that mention `gh`/`git push` — force identity check
 *
 * Override mechanisms (announced via ctx.ui.notify on use):
 *   - SKIP_GH_IDENTITY_GUARD=1                 (session-wide env var)
 *   - .gh-identity-allowlist at repo root      (per-pattern exact substring)
 *   - GH_IDENTITY_OVERRIDE=<login> prefix      (per-invocation; changes the
 *                                              expected identity for a
 *                                              MUTATING call. Non-mutating
 *                                              commands are allowed without a
 *                                              probe, as on the standard path.)
 *
 * Interactive bootstrap (ADR-0025): when neither identity source is
 * configured, an interactive session (ctx.hasUI) on a clean mutating call
 * (not a bypass-DENY-net shape) is offered an in-place create of
 * <cwd>/.pi/expected-identity via ctx.ui.confirm/input. The operator re-types
 * the login (suggestion is reference-only, suppressed on personal forks); the
 * file is written but the triggering call STILL fails closed (commit + re-run).
 *
 * Source ADR: adrs/0022-gh-identity-guard-extension.md
 */

import { spawn } from "node:child_process";
import type {
  BashToolCallEvent,
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
} from "@earendil-works/pi-coding-agent";

import { classify, type ClassifyResult } from "./lib/classifier.ts";
import {
  type Executor,
  isValidGhLogin,
  ProbeError,
  probeActiveIdentity,
  resolveIdentity,
} from "./lib/identity.ts";
import { scopeGitPushes } from "./lib/remote.ts";
import {
  loadAllowlist,
  matchesAllowlist,
  parseOverride,
} from "./lib/overrides.ts";
import {
  computeSuggestion,
  sanitizeForDisplay,
  writeExpectedIdentity,
} from "./lib/bootstrap.ts";

// --- Subprocess executor (mirrors pi.exec shape) ---------------------------

const defaultExecutor: Executor = {
  exec(cmd, args, signal) {
    return new Promise((resolve, reject) => {
      // `signal` lets probeActiveIdentity kill a timed-out child (SIGTERM)
      // instead of leaking it; spawn ignores an undefined signal.
      const child = spawn(cmd, [...args], {
        stdio: ["ignore", "pipe", "pipe"],
        signal,
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => {
        stdout += String(d);
      });
      child.stderr.on("data", (d) => {
        stderr += String(d);
      });
      child.on("error", reject);
      child.on("close", (code) => {
        resolve({ exitCode: code ?? -1, stdout, stderr });
      });
    });
  },
};

// --- Error-message helpers -------------------------------------------------

function probeErrorReason(err: ProbeError): string {
  // The hint must NOT coach a blocked agent into disabling the guard — that
  // would defeat its entire purpose. List only the identity-CORRECTING paths
  // (which still verify identity) as the way forward; disabling the guard is
  // an out-of-band OPERATOR action, named last and explicitly not an agent
  // step. (code-review loophole-text finding; ADR-0024.)
  const overrideHint =
    "\n\nThe way forward is to use the CORRECT identity:\n" +
    "  - `gh auth switch --user <login>` then retry, or\n" +
    "  - prefix the call with `GH_IDENTITY_OVERRIDE=<login>` after switching\n" +
    "    (asserts <login> for this one call; the identity is still verified).\n" +
    "Disabling the guard is an operator action, not an agent one: a human who\n" +
    "has reviewed the session may set SKIP_GH_IDENTITY_GUARD=1 or add a pattern\n" +
    "to .gh-identity-allowlist. Do not disable the guard to clear a block.";
  switch (err.kind) {
    case "gh-not-found":
      return (
        "gh-identity-guard: `gh` is not on PATH.\n\n" +
        "Suggested alternatives:\n" +
        "  - Install GitHub CLI (https://cli.github.com/)." +
        // NB: a sandboxed/no-GitHub environment is a legitimate reason to
        // disable the guard, but that is an operator decision — it is covered
        // by the operator-only framing in `overrideHint` below, NOT presented
        // here as a self-service "alternative" the agent should reach for.
        overrideHint
      );
    case "exec-failed":
      return (
        `gh-identity-guard: identity probe failed (${err.message}).\n\n` +
        "Suggested alternatives:\n" +
        "  - Run `gh auth status` and `gh api /user --jq .login` in your\n" +
        "    own shell to diagnose. Common causes: expired token, network\n" +
        "    failure, GitHub API outage." +
        overrideHint
      );
    case "empty-login":
      return (
        "gh-identity-guard: gh returned an empty login — token is likely\n" +
        "expired or revoked.\n\n" +
        "Suggested alternatives:\n" +
        "  - Run `gh auth refresh` (or `gh auth login`) and retry." +
        overrideHint
      );
    case "malformed-login":
      return (
        `gh-identity-guard: gh returned an unexpected value: ${err.message}\n\n` +
        "This is a hard refusal — retrying is unlikely to help. Inspect\n" +
        "`gh api /user` output manually." +
        overrideHint
      );
  }
}

function noExpectedReason(): string {
  return (
    "gh-identity-guard: no expected identity configured for this repo.\n\n" +
    "Declare one of the following before running mutating GitHub commands:\n" +
    "  - git-tracked `.pi/expected-identity` at the repo root: one GitHub\n" +
    "    login per line (multiple logins allowed). This file must be tracked\n" +
    "    by Git; it is itself the code-review artifact for who may write to\n" +
    "    this repo via pi.\n" +
    "  - `extensionSettings.ghIdentityGuard.expectedIdentity` in\n" +
    "    ~/.pi/agent/settings.json (string or array of strings) as a\n" +
    "    user-layer fallback.\n\n" +
    "Project-layer ./.pi/settings.json is NOT honored as a source-of-truth\n" +
    "(project layer is untrusted input per ADR-0019). See ADR-0022 § Q1."
  );
}

/**
 * Block reason after a successful interactive bootstrap write (ADR-0025 A1).
 * Deliberately DISTINCT from `noExpectedReason()` so the model does not read
 * it as the same unconfigured state and re-issue the call (which would
 * re-trigger the operator prompt). It names a completed HUMAN action and that
 * a re-run is required after committing the new trust anchor.
 */
function bootstrapWroteReason(login: string, path: string): string {
  return (
    `gh-identity-guard: created ${path} pinning \`${login}\` (operator action).\n\n` +
    "This call is still blocked on purpose: the new trust anchor is not yet\n" +
    "tracked/committed and the active identity has not been verified against\n" +
    "it. A human must:\n" +
    "  1. track and commit the file:  git add .pi/expected-identity && git commit\n" +
    "  2. re-run this command (it will then verify the active gh identity).\n\n" +
    "Do not retry automatically \u2014 a human action (commit) is required first."
  );
}

function driftReason(actual: string, expected: readonly string[]): string {
  const expectedList =
    expected.length === 1
      ? expected[0]
      : `one of ${expected.map((l) => `\`${l}\``).join(", ")}`;
  return (
    `gh-identity-guard: active gh identity is \`${actual}\` but this repo\n` +
    `expects ${expectedList}.\n\n` +
    "Suggested alternatives:\n" +
    `  - Switch the active identity: \`gh auth switch --user ${expected[0]}\`\n` +
    "    then retry.\n" +
    "  - If this call legitimately needs a different identity (e.g., a one-off\n" +
    "    bot comment), prefix the command with\n" +
    "    `GH_IDENTITY_OVERRIDE=<active-login>` after switching.\n" +
    "  - If this command pattern should always be allowed regardless of\n" +
    "    identity, add it as a substring to `.gh-identity-allowlist` at the\n" +
    "    repo root.\n" +
    "  - If the guard is misfiring on a non-mutating command, file an issue\n" +
    "    against the classifier."
  );
}

function overrideMismatchReason(declared: string, actual: string): string {
  return (
    `gh-identity-guard: GH_IDENTITY_OVERRIDE=${declared} was declared but the\n` +
    `active gh identity is \`${actual}\`.\n\n` +
    "The override CHANGES the expected identity for this call; it does NOT\n" +
    "skip the identity check. Active identity must equal the declared login.\n\n" +
    "Suggested alternatives:\n" +
    `  - Switch to the declared identity first: \`gh auth switch --user ${declared}\`\n` +
    "    then retry the prefixed command.\n" +
    `  - Or change the prefix to match the active identity: \`GH_IDENTITY_OVERRIDE=${actual}\`.\n` +
    "  - Or remove the prefix to use the repo's expected identity."
  );
}

// --- Remote-host scoping (ADR-0023) ----------------------------------------

/**
 * True when a mutating classification is a `git push` (or pushes) whose
 * effective remote is positively confirmed NON-`github.com` — the one case
 * where the guard passes through without an identity check. Everything else
 * (a `gh` mutation, a bypass-net shape, or a push whose host is github.com or
 * cannot be determined) returns false → the caller keeps gating. Fail closed.
 */
async function isNonGithubPush(
  classification: ClassifyResult,
  cwd: string,
  executor: Executor,
): Promise<boolean> {
  if (classification.unconditional) return false;
  if (classification.gitPushes.length === 0) return false;
  const verdict = await scopeGitPushes(executor, cwd, classification.gitPushes);
  return verdict === "non-github";
}

// --- Event guard -----------------------------------------------------------

/**
 * Runtime guard for the bash tool call. Equivalent to the library's
 * `isToolCallEventType("bash", event)` but implemented locally with a
 * type-only import, so this module carries NO runtime dependency on
 * `@earendil-works/pi-coding-agent` — keeping it importable where the
 * package is absent at runtime (e.g. the CI test runner). A user-defined
 * type guard still narrows correctly; the bare `event.toolName === "bash"`
 * does not, because `CustomToolCallEvent.toolName` is `string`.
 */
function isBashToolCall(event: ToolCallEvent): event is BashToolCallEvent {
  return event.toolName === "bash";
}

/**
 * Interactive bootstrap of `<cwd>/.pi/expected-identity` (ADR-0025).
 *
 * Returns the block reason on a successful write (the triggering call STILL
 * fails closed — A1 commit-gate), or `null` when the operator declined,
 * cancelled, or entered an invalid login (the caller then falls through to the
 * standard fail-closed block). The caller MUST gate on
 * `ctx.hasUI && !classification.unconditional` before invoking, so this never
 * prompts in print/json sessions or on bypass-DENY-net shapes.
 *
 * No dialog passes a `timeout` option: in RPC an unanswered timed dialog
 * auto-resolves silently (pi 0.78.1 docs/rpc.md), which would be an unintended
 * auto-decline/accept. A cancelled confirm returns false, a cancelled input
 * returns undefined — both map to "declined" here (fail closed).
 */
async function maybeBootstrap(
  ctx: ExtensionContext,
  exec: Executor,
): Promise<string | null> {
  // Reference-only suggestion (ADR-0025 B1): the active login, but only when it
  // equals the origin owner and the repo is not a personal fork. Best-effort;
  // a probe failure simply means no suggestion. NEVER pre-filled or
  // auto-accepted — the operator re-types the login below.
  let suggestion = "";
  try {
    const active = await probeActiveIdentity(exec);
    const r = await computeSuggestion(exec, ctx.cwd, active);
    suggestion = r.suggestion;
    ctx.ui.notify(
      `gh-identity-guard: no expected identity configured. active gh login: \`${active}\`; origin owner: \`${r.owner || "<none>"}\`.`,
      "info",
    );
  } catch {
    // Probe failed (gh missing / network / drift) — still allow manual entry.
  }

  const proceed = await ctx.ui.confirm(
    "gh-identity-guard: bootstrap .pi/expected-identity?",
    "No expected GitHub identity is configured for this repo. Create " +
      ".pi/expected-identity now? You will type the login explicitly" +
      (suggestion ? ` (suggested: ${suggestion}).` : ".") +
      " It is committed, tracked policy — you must commit it afterward, and" +
      " this command stays blocked until you do and re-run.",
  );
  if (!proceed) return null;

  const entered = await ctx.ui.input(
    suggestion
      ? `Enter the expected GitHub login (re-type "${suggestion}" to confirm):`
      : "Enter the expected GitHub login:",
    "", // no prefill — re-type required (ADR-0025 B1)
  );
  const login = (entered ?? "").trim();
  if (!login || !isValidGhLogin(login)) {
    if (login) {
      ctx.ui.notify(
        `gh-identity-guard: \`${sanitizeForDisplay(login)}\` is not a valid GitHub login (1–39 chars, alphanumeric with single internal hyphens) — nothing written.`,
        "error",
      );
    }
    return null;
  }
  try {
    const path = writeExpectedIdentity(ctx.cwd, login);
    const reason = bootstrapWroteReason(login, path);
    ctx.ui.notify(reason, "warning");
    return reason;
  } catch (err) {
    ctx.ui.notify(
      `gh-identity-guard: could not write .pi/expected-identity (${err instanceof Error ? err.message : String(err)}).`,
      "error",
    );
    return null;
  }
}

// --- Main ------------------------------------------------------------------

export default function (pi: ExtensionAPI, deps?: { executor?: Executor }) {
  const executor = deps?.executor ?? defaultExecutor;

  if (process.env.SKIP_GH_IDENTITY_GUARD === "1") {
    // Session-wide bypass. Announce via notify per ADR-0022 § Q5
    // "override cannot be silent" contract. Probe lazily so we can name the
    // active identity in the announcement — fire-and-forget; on probe
    // failure we still announce the bypass without the identity.
    pi.on("session_start", (_event, ctx) => {
      if (!ctx.hasUI) return;
      void (async () => {
        let suffix = "";
        try {
          const login = await probeActiveIdentity(executor);
          suffix = `; active identity is \`${login}\``;
        } catch {
          suffix = "; active identity could not be probed";
        }
        ctx.ui.notify(
          `gh-identity-guard: bypassed via SKIP_GH_IDENTITY_GUARD=1${suffix}`,
          "warning",
        );
      })();
    });
    return;
  }

  pi.on("tool_call", async (event, ctx) => {
    if (!isBashToolCall(event)) return undefined;
    const command = event.input.command;
    if (!command) return undefined;

    // Classified once and shared across the override and standard paths.
    const classification = classify(command);

    // --- Override-evaluation path (terminates; no allowlist fallback) ----
    const override = parseOverride(command);
    // Contradictory intent: an inline SKIP disables the guard for this call
    // while GH_IDENTITY_OVERRIDE asserts a specific identity for it. Refuse
    // explicitly rather than letting evaluation order silently pick one
    // (ADR-0024; #276).
    if (override.kind === "valid" && classification.inlineSkip) {
      const reason =
        "gh-identity-guard: contradictory overrides — both " +
        "SKIP_GH_IDENTITY_GUARD=1 (disable) and GH_IDENTITY_OVERRIDE= (assert " +
        "identity) prefix this call. Remove one and retry.";
      if (ctx.hasUI) ctx.ui.notify(reason, "error");
      return { block: true, reason };
    }
    if (override.kind === "invalid") {
      const reason = `gh-identity-guard: ${override.reason}.\n\nFix the GH_IDENTITY_OVERRIDE= prefix and retry.`;
      if (ctx.hasUI) ctx.ui.notify(reason, "error");
      return { block: true, reason };
    }
    if (override.kind === "valid") {
      // A read-only command carries no wrong-account-mutation risk, so the
      // override assertion (and its identity probe) is unnecessary — skip it
      // for non-mutating commands, matching the standard path which never
      // probes a read-only call (#259 item 3). classify() strips the leading
      // GH_IDENTITY_OVERRIDE= assignment, and its bypass-DENY net still forces
      // verification on shell-interpreter / eval / command-substitution shapes
      // even when an override prefix is present — no new bypass.
      if (!classification.mutating) return undefined;
      // A `git push` to a non-github.com remote (ADO, GitLab, …) carries no
      // wrong-gh-account risk — allow it without asserting the override
      // identity, matching the standard path (ADR-0023).
      if (await isNonGithubPush(classification, ctx.cwd, executor)) {
        return undefined;
      }

      let actual: string;
      try {
        actual = await probeActiveIdentity(executor);
      } catch (err) {
        if (err instanceof ProbeError) {
          const reason = probeErrorReason(err);
          if (ctx.hasUI) ctx.ui.notify(reason, "error");
          return { block: true, reason };
        }
        throw err;
      }
      if (actual !== override.login) {
        const reason = overrideMismatchReason(override.login, actual);
        if (ctx.hasUI) ctx.ui.notify(reason, "error");
        return { block: true, reason };
      }
      if (ctx.hasUI) {
        ctx.ui.notify(
          `gh-identity-guard: per-invocation override active — call runs as \`${actual}\` (declared via GH_IDENTITY_OVERRIDE=${override.login})`,
          "info",
        );
      }
      return undefined;
    }

    // --- Standard path: classify, then probe-and-compare -----------------
    // Announce any per-command operator skip (mandatory, never silent —
    // ADR-0022 §Q5 / ADR-0024). The skip was applied per-segment in
    // classify(); here we only surface it, worded as an OPERATOR override so
    // an agent does not read it as a self-service unblock. In a headless
    // (no-UI) session the skip is still honored but cannot be announced —
    // accepted gap, consistent with the session-wide bypass; the prefix is
    // visible in the tool-call stream.
    if (classification.inlineSkip && ctx.hasUI) {
      // `mutating` still true here means OTHER, non-exempt segments remain and
      // will be gated below — so the skip covered only part of the command.
      const scope = classification.mutating
        ? "one segment of this call (other segments are still checked)"
        : "this call";
      ctx.ui.notify(
        `gh-identity-guard: OPERATOR SKIP — identity check suppressed for ${scope} ` +
          "by a SKIP_GH_IDENTITY_GUARD=1 prefix. This is an operator override, " +
          "not an agent action.",
        "warning",
      );
    }
    if (!classification.mutating) return undefined;
    // Host-scope `git push`: a push to a non-github.com remote is out of
    // scope for the GitHub identity guard and passes through silently,
    // matching the pre-push hook (ADR-0023). github.com or an indeterminate
    // host falls through to the identity check (fail closed).
    if (await isNonGithubPush(classification, ctx.cwd, executor)) {
      return undefined;
    }

    const resolution = await resolveIdentity(ctx.cwd, executor, {
      signal: ctx.signal,
    });
    if (resolution.perRepoFilePresentButEmpty && ctx.hasUI) {
      // The per-repo pin file exists but parsed to zero valid logins (likely
      // a typo). WARN, then fall through to the user-layer per ADR-0022 §Q1
      // — the fail-closed floor below still applies if nothing resolves.
      ctx.ui.notify(
        "gh-identity-guard: .pi/expected-identity exists but contains no valid " +
          "GitHub logins (check for typos — logins are ≤39 chars, alphanumeric " +
          "with single internal hyphens). Falling back to user-layer settings.",
        "warning",
      );
    }
    if (resolution.perRepoFilePresentButUnreadable && ctx.hasUI) {
      // The per-repo pin file exists but could not be read (e.g. a permission
      // error). WARN, then fall through to the user-layer (#268) — the
      // fail-closed floor below still applies if nothing resolves.
      ctx.ui.notify(
        "gh-identity-guard: .pi/expected-identity exists but could not be read " +
          "(check file permissions). Falling back to user-layer settings.",
        "warning",
      );
    }
    if (resolution.perRepoFilePresentButUntracked && ctx.hasUI) {
      // The per-repo pin file exists but is not Git-tracked. Per #306 it is
      // local-only policy, not the PR-reviewed trust anchor ADR-0022 relies on.
      ctx.ui.notify(
        "gh-identity-guard: .pi/expected-identity exists but is not tracked " +
          "by git. Ignoring it and falling back to user-layer settings.",
        "warning",
      );
    }
    if (resolution.perRepoFileTrackingIndeterminate && ctx.hasUI) {
      ctx.ui.notify(
        "gh-identity-guard: .pi/expected-identity exists but git tracking " +
          "could not be verified. Ignoring it and falling back to user-layer settings.",
        "warning",
      );
    }
    const expected = resolution.logins;
    if (expected === null) {
      // ADR-0025: with an operator present (ctx.hasUI: TUI or RPC) and a CLEAN
      // mutating call (NOT a bypass-DENY-net shape), offer to bootstrap the
      // per-repo pin in place. Suppressed under classification.bypassNet
      // (security review MEDIUM-2 — a trust anchor must be created from a clean
      // call, not a shell-interpreter/eval/xargs/$() shape) and whenever
      // !ctx.hasUI (print/json) — both keep the fail-closed floor. Reached only
      // after the SKIP/OVERRIDE short-circuits and the non-github passthrough,
      // so no bypass surface ever prompts.
      if (ctx.hasUI && !classification.bypassNet) {
        const created = await maybeBootstrap(ctx, executor);
        // A1: even on a successful write we STILL block this call.
        if (created !== null) return { block: true, reason: created };
        // Declined / cancelled / invalid → fall through to the standard block.
      }
      const reason = noExpectedReason();
      if (ctx.hasUI) ctx.ui.notify(reason, "error");
      return { block: true, reason };
    }

    let actual: string;
    try {
      actual = await probeActiveIdentity(executor);
    } catch (err) {
      if (err instanceof ProbeError) {
        const reason = probeErrorReason(err);
        if (ctx.hasUI) ctx.ui.notify(reason, "error");
        return { block: true, reason };
      }
      throw err;
    }

    if (expected.includes(actual)) return undefined;

    // Drift detected. Consult allowlist as the final allow-path.
    const allowlist = loadAllowlist(ctx.cwd);
    const allowHit = matchesAllowlist(command, allowlist);
    if (allowHit !== null) {
      if (ctx.hasUI) {
        ctx.ui.notify(
          `gh-identity-guard: allowlist hit (\`${allowHit}\`) — call runs as \`${actual}\` instead of expected ${expected.map((l) => `\`${l}\``).join(", ")}`,
          "info",
        );
      }
      return undefined;
    }

    const reason = driftReason(actual, expected);
    if (ctx.hasUI) ctx.ui.notify(reason, "error");
    return { block: true, reason };
  });
}
