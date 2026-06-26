/**
 * gh-identity-guard — index.ts wiring tests.
 *
 * Covers:
 *   - the #259 item-2 empty-pin notify (mutating command with an empty pin
 *     file must WARN before falling through);
 *   - the GH_IDENTITY_OVERRIDE probe short-circuit (#259 item 3);
 *   - the ADR-0023 remote-host scoping: a `git push` to a non-github.com
 *     remote passes through, github.com / indeterminate hosts gate, SSH
 *     aliases are resolved via `ssh -G`, and the scope applies on both the
 *     standard and override paths.
 *
 * All subprocess interaction is stubbed via the injectable `executor` dep, so
 * no real `gh`/`git`/`ssh` runs and the tests are deterministic. The stub is
 * COMMAND-AWARE (dispatches on argv[0]) — a blanket stub would make the host
 * resolver `git rev-parse` "succeed" with a bogus remote and mask real
 * behaviour.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Executor } from "../lib/identity.ts";

const mod = await import("../index.ts");

type Handler = (event: unknown, ctx: unknown) => unknown;

interface FakePi {
  on(name: string, handler: Handler): void;
  handlers: Record<string, Handler[]>;
}

function makePi(): FakePi {
  const handlers: Record<string, Handler[]> = {};
  return {
    on(name, handler) {
      (handlers[name] ??= []).push(handler);
    },
    handlers,
  };
}

interface NotifyCall {
  message: string;
  level: string;
}

function makeCtx(
  cwd: string,
  hasUI = true,
): { ctx: unknown; calls: NotifyCall[] } {
  const calls: NotifyCall[] = [];
  const ctx = {
    cwd,
    hasUI,
    ui: {
      notify(message: string, level: string) {
        calls.push({ message, level });
      },
      // The interactive bootstrap (ADR-0025) may be reached when resolution is
      // null. These existing tests are not exercising it, so decline by
      // default — the call then falls through to the same fail-closed block,
      // and the WARN assertions below are unaffected. Bootstrap-specific
      // behavior is covered in bootstrap.test.ts.
      confirm(_title: string, _message: string) {
        return Promise.resolve(false);
      },
      input(_title: string, _placeholder?: string) {
        return Promise.resolve(undefined);
      },
    },
  };
  return { ctx, calls };
}

// --- Command-aware executor stub -------------------------------------------

interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr?: string;
}
interface ExecCall {
  cmd: string;
  args: string[];
}
interface MakeExecutorOpts {
  /** `gh api /user --jq .login` result login. Defaults to "TheSemicolon". */
  login?: string;
  /** When true, the gh probe throws (simulates a probe failure). */
  rejectProbe?: boolean;
  /** `git rev-parse --abbrev-ref @{push}` result. Default: exit 128 (no repo
   * / no upstream) → indeterminate → gate. */
  revParse?: ExecResult;
  /** `git remote get-url --push --all <remote>` result. Default: exit 128. */
  getUrl?: ExecResult;
  /** `ssh -G <host>` result. Default: exit 255 (unresolvable). */
  ssh?: ExecResult;
  /** Whether `.pi/expected-identity` is tracked. Default: true. */
  pinTracked?: boolean;
}

function makeExecutor(opts: MakeExecutorOpts = {}): {
  executor: Executor;
  calls: ExecCall[];
  probeCount: () => number;
} {
  const calls: ExecCall[] = [];
  let probeCount = 0;
  const executor: Executor = {
    exec(cmd, args) {
      calls.push({ cmd, args: [...args] });
      if (cmd === "gh") {
        probeCount++;
        if (opts.rejectProbe) throw new Error("forced probe failure");
        return Promise.resolve({
          exitCode: 0,
          stdout: `${opts.login ?? "TheSemicolon"}\n`,
          stderr: "",
        });
      }
      if (cmd === "git") {
        if (args.includes("rev-parse")) {
          return Promise.resolve({
            stderr: "",
            ...(opts.revParse ?? { exitCode: 128, stdout: "" }),
          });
        }
        if (args.includes("get-url")) {
          return Promise.resolve({
            stderr: "",
            ...(opts.getUrl ?? { exitCode: 128, stdout: "" }),
          });
        }
        if (args.includes("ls-files")) {
          const tracked = opts.pinTracked ?? true;
          return Promise.resolve({
            exitCode: tracked ? 0 : 1,
            stdout: tracked ? ".pi/expected-identity\n" : "",
            stderr: "",
          });
        }
        return Promise.resolve({ exitCode: 128, stdout: "", stderr: "" });
      }
      if (cmd === "ssh") {
        return Promise.resolve({
          stderr: "",
          ...(opts.ssh ?? { exitCode: 255, stdout: "" }),
        });
      }
      return Promise.resolve({ exitCode: 127, stdout: "", stderr: "" });
    },
  };
  return { executor, calls, probeCount: () => probeCount };
}

function bashEvent(command: string): unknown {
  return {
    type: "tool_call",
    toolCallId: "test-1",
    toolName: "bash",
    input: { command },
  };
}

async function withRepo(
  fileContent: string | null,
  run: (cwd: string) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ghig-index-"));
  await fs.mkdir(join(root, ".pi"), { recursive: true });
  if (fileContent !== null) {
    await fs.writeFile(join(root, ".pi", "expected-identity"), fileContent);
  }
  try {
    await run(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function getToolCallHandler(executor: Executor): Handler {
  const prev = process.env.SKIP_GH_IDENTITY_GUARD;
  delete process.env.SKIP_GH_IDENTITY_GUARD;
  try {
    const pi = makePi();
    mod.default(pi as never, { executor });
    assert.equal(pi.handlers.tool_call?.length, 1, "tool_call handler registered");
    return pi.handlers.tool_call[0];
  } finally {
    if (prev !== undefined) process.env.SKIP_GH_IDENTITY_GUARD = prev;
  }
}

const EMPTY_PIN_RE = /expected-identity exists but contains no valid/;
const UNREADABLE_PIN_RE = /expected-identity exists but could not be read/;
const UNTRACKED_PIN_RE = /expected-identity exists but is not tracked/;
// `chmod 000` does not block root, so the unreadable-pin path can't be
// exercised as root — skip there rather than emit a false failure.
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

// --- #259 item-2 empty-pin notify ------------------------------------------

test("empty .pi/expected-identity emits the warning notify on a mutating command (#259)", async () => {
  await withRepo("-invalid\nalso--invalid\n", async (cwd) => {
    // No git repo in cwd → rev-parse fails → indeterminate → gate → resolve.
    const { executor } = makeExecutor();
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    await handler(bashEvent("git push"), ctx);

    const warnings = calls.filter(
      (c) => c.level === "warning" && EMPTY_PIN_RE.test(c.message),
    );
    assert.equal(warnings.length, 1, "exactly one empty-pin warning fired");
  });
});

test("valid .pi/expected-identity does NOT emit the empty-pin warning", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor } = makeExecutor();
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    await handler(bashEvent("git push"), ctx);

    const warnings = calls.filter((c) => EMPTY_PIN_RE.test(c.message));
    assert.equal(warnings.length, 0, "no empty-pin warning for a valid pin file");
  });
});

test("untracked .pi/expected-identity emits warning and blocks without fallback (#306)", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor } = makeExecutor({ pinTracked: false });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = (await handler(bashEvent("git push"), ctx)) as
      | { block?: boolean; reason?: string }
      | undefined;

    assert.equal(result?.block, true, "untracked pin is not authoritative");
    assert.match(result?.reason ?? "", /no expected identity configured/);
    const warnings = calls.filter(
      (c) => c.level === "warning" && UNTRACKED_PIN_RE.test(c.message),
    );
    assert.equal(warnings.length, 1, "exactly one untracked-pin warning fired");
  });
});

test("non-mutating command does not emit the empty-pin warning even with empty pin", async () => {
  await withRepo("-invalid\n", async (cwd) => {
    const { executor } = makeExecutor();
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    await handler(bashEvent("gh pr list"), ctx);

    const warnings = calls.filter((c) => EMPTY_PIN_RE.test(c.message));
    assert.equal(warnings.length, 0, "non-mutating command short-circuits before resolve");
  });
});

test(
  "unreadable .pi/expected-identity emits the unreadable warning notify (#268)",
  { skip: isRoot ? "cannot make a file unreadable as root" : false },
  async () => {
    await withRepo("TheSemicolon\n", async (cwd) => {
      const pin = join(cwd, ".pi", "expected-identity");
      await fs.chmod(pin, 0o000);
      try {
        const { executor } = makeExecutor();
        const handler = getToolCallHandler(executor);
        const { ctx, calls } = makeCtx(cwd);
        await handler(bashEvent("git push"), ctx);
        const warnings = calls.filter(
          (c) => c.level === "warning" && UNREADABLE_PIN_RE.test(c.message),
        );
        assert.equal(warnings.length, 1, "exactly one unreadable-pin warning fired");
        const empty = calls.filter((c) => EMPTY_PIN_RE.test(c.message));
        assert.equal(empty.length, 0, "unreadable is not reported as empty");
      } finally {
        // Restore perms so withRepo's cleanup can remove the temp dir.
        await fs.chmod(pin, 0o644);
      }
    });
  },
);

test(
  "non-mutating command does not emit the unreadable-pin warning",
  { skip: isRoot ? "cannot make a file unreadable as root" : false },
  async () => {
    await withRepo("TheSemicolon\n", async (cwd) => {
      const pin = join(cwd, ".pi", "expected-identity");
      await fs.chmod(pin, 0o000);
      try {
        const { executor } = makeExecutor();
        const handler = getToolCallHandler(executor);
        const { ctx, calls } = makeCtx(cwd);
        // `gh pr list` is read-only → classifier short-circuits before
        // resolveIdentity, so no pin diagnostic fires.
        await handler(bashEvent("gh pr list"), ctx);
        assert.equal(
          calls.filter((c) => UNREADABLE_PIN_RE.test(c.message)).length,
          0,
          "non-mutating command short-circuits before resolve",
        );
      } finally {
        await fs.chmod(pin, 0o644);
      }
    });
  },
);

// --- GH_IDENTITY_OVERRIDE probe short-circuit (#259 item 3) -----------------

test("override prefix on a non-mutating command does NOT probe and is allowed", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor({ rejectProbe: true });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = await handler(
      bashEvent("GH_IDENTITY_OVERRIDE=someone-else gh pr list"),
      ctx,
    );
    assert.equal(result, undefined, "read-only override call is allowed");
    assert.equal(probeCount(), 0, "no identity probe ran");
    const errors = calls.filter((c) => c.level === "error");
    assert.equal(errors.length, 0, "no block/error notify");
  });
});

test("override prefix on a MUTATING gh command still probes and blocks on mismatch", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // probe resolves "TheSemicolon"; override declares "someone-else" → block.
    const { executor } = makeExecutor({ login: "TheSemicolon" });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("GH_IDENTITY_OVERRIDE=someone-else gh pr create --title x"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "mutating override mismatch blocks");
  });
});

test("override prefix matching the active identity allows a mutating git push", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // No repo → push host indeterminate → gate → probe matches override.
    const { executor } = makeExecutor({ login: "TheSemicolon" });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = await handler(
      bashEvent("GH_IDENTITY_OVERRIDE=TheSemicolon git push"),
      ctx,
    );
    assert.equal(result, undefined, "matching override allows the mutating call");
  });
});

test("mutating override works with NO .pi/expected-identity configured (item 4)", async () => {
  await withRepo(null, async (cwd) => {
    const { executor } = makeExecutor({ login: "TheSemicolon" });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = await handler(
      bashEvent("GH_IDENTITY_OVERRIDE=TheSemicolon git push"),
      ctx,
    );
    assert.equal(result, undefined, "matching override allows even with no pin file");
  });
});

test("bypass shape with override prefix still probes (no short-circuit escape)", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor({ rejectProbe: true });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("GH_IDENTITY_OVERRIDE=someone-else bash -c 'gh pr merge 42'"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(probeCount(), 1, "probe was attempted (bypass shape is mutating)");
    assert.equal(result?.block, true, "probe failure on a mutating call blocks");
  });
});

// --- ADR-0023 remote-host scoping ------------------------------------------

test("git push to a github.com remote gates and blocks on drift", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/main\n" },
      getUrl: { exitCode: 0, stdout: "https://github.com/psmfd/pi-config.git\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(bashEvent("git push"), ctx)) as
      | { block?: boolean }
      | undefined;
    assert.equal(result?.block, true, "github.com push with wrong identity blocks");
  });
});

test("git push to an Azure DevOps HTTPS remote passes through without a probe (#265)", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/dev\n" },
      getUrl: { exitCode: 0, stdout: "https://dev.azure.com/org/proj/_git/repo\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = await handler(bashEvent("git push origin dev"), ctx);
    assert.equal(result, undefined, "ADO push is allowed");
    assert.equal(probeCount(), 0, "no gh identity probe on a non-github push");
    assert.equal(calls.filter((c) => c.level === "error").length, 0, "no block");
  });
});

test("git push to an Azure DevOps SSH remote passes through via ssh -G resolution", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount, calls } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/dev\n" },
      getUrl: { exitCode: 0, stdout: "git@ssh.dev.azure.com:v3/org/proj/repo\n" },
      ssh: { exitCode: 0, stdout: "user git\nhostname ssh.dev.azure.com\nport 22\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = await handler(bashEvent("git push"), ctx);
    assert.equal(result, undefined, "ADO ssh push is allowed");
    assert.equal(probeCount(), 0, "no gh identity probe");
    assert.ok(
      calls.some((c) => c.cmd === "ssh" && c.args.includes("-G")),
      "ssh -G alias resolution was attempted",
    );
  });
});

test("SSH alias resolving to github.com gates (closes the alias bypass)", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // `git@gh-personal:...` where ~/.ssh/config maps gh-personal → github.com.
    const { executor } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/main\n" },
      getUrl: { exitCode: 0, stdout: "git@gh-personal:psmfd/pi-config.git\n" },
      ssh: { exitCode: 0, stdout: "hostname github.com\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(bashEvent("git push"), ctx)) as
      | { block?: boolean }
      | undefined;
    assert.equal(result?.block, true, "aliased github.com push must gate, not pass");
  });
});

test("indeterminate push host (no upstream) fails closed and gates", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 128, stdout: "" }, // no upstream / detached
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(bashEvent("git push"), ctx)) as
      | { block?: boolean }
      | undefined;
    assert.equal(result?.block, true, "indeterminate host fails closed (gates)");
  });
});

test("explicit github.com URL arg gates without a remote lookup", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, calls } = makeExecutor({ login: "intruder" });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("git push https://github.com/psmfd/pi-config.git HEAD"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "explicit github URL gates");
    assert.equal(
      calls.filter((c) => c.cmd === "git" && c.args.includes("get-url")).length,
      0,
      "no remote get-url needed for an explicit URL arg",
    );
  });
});

test("explicit Azure DevOps URL arg passes through", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor({ login: "intruder" });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = await handler(
      bashEvent("git push https://dev.azure.com/org/proj/_git/repo main"),
      ctx,
    );
    assert.equal(result, undefined, "explicit ADO URL passes through");
    assert.equal(probeCount(), 0, "no probe on a non-github explicit URL");
  });
});

test("inline -c url.*.insteadOf rewrite fails closed and gates", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // The inline rewrite could repoint origin at github.com; a separate
    // subprocess cannot see it, so we must gate regardless of the stored URL.
    const { executor } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/main\n" },
      getUrl: { exitCode: 0, stdout: "https://dev.azure.com/org/proj/_git/repo\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(
      bashEvent(
        "git -c url.https://github.com/.insteadOf=https://dev.azure.com/ push origin main",
      ),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "inline insteadOf rewrite fails closed");
  });
});

test("git -C <dir> push resolves the remote in that directory, with hardening", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, calls } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/dev\n" },
      getUrl: { exitCode: 0, stdout: "https://dev.azure.com/org/proj/_git/repo\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = await handler(bashEvent("git -C /some/abs/dir push"), ctx);
    assert.equal(result, undefined, "ADO remote in -C dir passes through");
    const gitCalls = calls.filter((c) => c.cmd === "git");
    assert.ok(gitCalls.length > 0, "git was invoked for resolution");
    for (const c of gitCalls) {
      assert.equal(c.args[0], "-C", "git invoked with -C");
      assert.equal(c.args[1], "/some/abs/dir", "git -C uses the command's -C dir");
      assert.ok(
        c.args.includes("core.fsmonitor=") &&
          c.args.includes("core.hooksPath=/dev/null"),
        "fsmonitor/hooksPath hardening present",
      );
    }
  });
});

test("git --git-dir push fails closed and gates (cwd-resolution unreliable)", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // cwd's origin would resolve to ADO, but the push targets a different
    // repo via --git-dir; we must not trust cwd resolution → gate.
    const { executor } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/main\n" },
      getUrl: { exitCode: 0, stdout: "https://dev.azure.com/org/proj/_git/repo\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("git --git-dir=/other/.git push origin main"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "--git-dir push fails closed (gates)");
  });
});

// --- ADR-0024: per-command inline SKIP_GH_IDENTITY_GUARD=1 (#276) ------------

const OPERATOR_SKIP_RE = /OPERATOR SKIP/;

test("inline skip on a git push allows the call and announces it, no probe", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor({ login: "intruder" });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = await handler(
      bashEvent("SKIP_GH_IDENTITY_GUARD=1 git push origin main"),
      ctx,
    );
    assert.equal(result, undefined, "skipped push is allowed");
    assert.equal(probeCount(), 0, "no identity probe on a skipped call");
    const skips = calls.filter(
      (c) => c.level === "warning" && OPERATOR_SKIP_RE.test(c.message),
    );
    assert.equal(skips.length, 1, "exactly one operator-skip announcement");
  });
});

test("partial compound: skip exempts the first push, the second still gates", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // Second push (backup) resolves to github.com with wrong identity → block,
    // even though the first push was skip-exempted.
    const { executor } = makeExecutor({
      login: "intruder",
      getUrl: { exitCode: 0, stdout: "https://github.com/psmfd/pi-config.git\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = (await handler(
      bashEvent(
        "SKIP_GH_IDENTITY_GUARD=1 git push origin main && git push backup main",
      ),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "non-exempt github push still gates");
    assert.ok(
      calls.some((c) => OPERATOR_SKIP_RE.test(c.message)),
      "the exempted segment is still announced",
    );
  });
});

test("SKIP + GH_IDENTITY_OVERRIDE together is blocked as contradictory", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor();
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("SKIP_GH_IDENTITY_GUARD=1 GH_IDENTITY_OVERRIDE=someone git push"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "contradictory overrides block");
    assert.equal(probeCount(), 0, "no probe — refused before evaluation");
    assert.ok(
      calls.some((c) => c.level === "error" && /contradictory/.test(c.message)),
      "names the contradiction",
    );
  });
});

test("non-mutating command with a skip prefix does not announce", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor } = makeExecutor();
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = await handler(
      bashEvent("SKIP_GH_IDENTITY_GUARD=1 gh pr list"),
      ctx,
    );
    assert.equal(result, undefined, "read-only command allowed");
    assert.equal(
      calls.filter((c) => OPERATOR_SKIP_RE.test(c.message)).length,
      0,
      "no skip announcement for a non-mutating command",
    );
  });
});

test("inline skip is honored in a headless (no-UI) session, announcement suppressed", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    const { executor, probeCount } = makeExecutor({ login: "intruder" });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd, /* hasUI */ false);
    const result = await handler(
      bashEvent("SKIP_GH_IDENTITY_GUARD=1 git push origin main"),
      ctx,
    );
    assert.equal(result, undefined, "skip honored without UI");
    assert.equal(probeCount(), 0, "no probe");
    assert.equal(calls.length, 0, "no notify possible without UI (accepted gap)");
  });
});

test("inline skip is IGNORED for a bypass-net shape (still gates)", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // `bash -c '...'` is bypass-net → unconditional gate; the outer skip must
    // not disable it. Probe runs (throwing executor) → block.
    const { executor, probeCount } = makeExecutor({ rejectProbe: true });
    const handler = getToolCallHandler(executor);
    const { ctx, calls } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("SKIP_GH_IDENTITY_GUARD=1 bash -c 'git push origin main'"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "bypass-net shape gates despite the skip");
    assert.equal(probeCount(), 1, "probe attempted (skip not honored)");
    assert.equal(
      calls.filter((c) => OPERATOR_SKIP_RE.test(c.message)).length,
      0,
      "no skip announcement for an un-honored skip",
    );
  });
});

test("compound push: github.com segment gates even when another is ADO", async () => {
  await withRepo("TheSemicolon\n", async (cwd) => {
    // First push (origin) resolves to github.com → must gate the whole call.
    const { executor } = makeExecutor({
      login: "intruder",
      revParse: { exitCode: 0, stdout: "origin/main\n" },
      getUrl: { exitCode: 0, stdout: "https://github.com/psmfd/pi-config.git\n" },
    });
    const handler = getToolCallHandler(executor);
    const { ctx } = makeCtx(cwd);
    const result = (await handler(
      bashEvent("git push https://dev.azure.com/o/p/_git/r main && git push origin main"),
      ctx,
    )) as { block?: boolean } | undefined;
    assert.equal(result?.block, true, "any github.com push in a compound command gates");
  });
});
