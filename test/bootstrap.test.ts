/**
 * gh-identity-guard — interactive bootstrap tests (ADR-0025).
 *
 * Covers lib/bootstrap.ts pure/executor helpers and the index.ts wiring that
 * offers to create <cwd>/.pi/expected-identity at the no-expected-identity
 * terminal state. The tool_call handler is exercised with a fake `pi`, a
 * scripted `ctx.ui` (confirm/input/notify), and a command-aware executor stub
 * (no real gh/git). HOME is redirected to an empty temp dir so the user-layer
 * fallback (~/.pi/agent/settings.json) never leaks a real identity in.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Executor } from "../lib/identity.ts";
import {
  computeSuggestion,
  originOwnerRepo,
  parseOwnerRepo,
  sanitizeForDisplay,
  writeExpectedIdentity,
} from "../lib/bootstrap.ts";
import { classify } from "../lib/classifier.ts";

const mod = await import("../index.ts");

type Handler = (event: unknown, ctx: unknown) => unknown;

function makePi(): { on(name: string, h: Handler): void; handlers: Record<string, Handler[]> } {
  const handlers: Record<string, Handler[]> = {};
  return {
    on(name, h) {
      (handlers[name] ??= []).push(h);
    },
    handlers,
  };
}

interface ExecCall {
  cmd: string;
  args: string[];
}
interface ExecOpts {
  login?: string;
  rejectProbe?: boolean;
  originUrl?: string;
  isFork?: boolean;
}
function makeExec(opts: ExecOpts = {}): { executor: Executor; calls: ExecCall[] } {
  const calls: ExecCall[] = [];
  const executor: Executor = {
    exec(cmd, args) {
      calls.push({ cmd, args: [...args] });
      if (cmd === "gh" && args[0] === "api") {
        if (opts.rejectProbe) return Promise.reject(new Error("forced probe failure"));
        return Promise.resolve({ exitCode: 0, stdout: `${opts.login ?? "TheSemicolon"}\n`, stderr: "" });
      }
      if (cmd === "gh" && args[0] === "repo" && args[1] === "view") {
        return Promise.resolve({ exitCode: 0, stdout: opts.isFork ? "fork\n" : "", stderr: "" });
      }
      if (cmd === "git" && args.includes("get-url") && args.includes("origin")) {
        return opts.originUrl
          ? Promise.resolve({ exitCode: 0, stdout: `${opts.originUrl}\n`, stderr: "" })
          : Promise.resolve({ exitCode: 128, stdout: "", stderr: "" });
      }
      if (cmd === "git") return Promise.resolve({ exitCode: 128, stdout: "", stderr: "" });
      return Promise.resolve({ exitCode: 127, stdout: "", stderr: "" });
    },
  };
  return { executor, calls };
}

interface CtxCalls {
  notify: { message: string; level: string }[];
  confirm: { title: string; message: string }[];
  input: { title: string; placeholder?: string }[];
}
function makeCtx(
  cwd: string,
  opts: { hasUI?: boolean; confirm?: boolean; input?: string | undefined } = {},
): { ctx: unknown; calls: CtxCalls } {
  const calls: CtxCalls = { notify: [], confirm: [], input: [] };
  const ctx = {
    cwd,
    hasUI: opts.hasUI ?? true,
    ui: {
      notify(message: string, level: string) {
        calls.notify.push({ message, level });
      },
      confirm(title: string, message: string) {
        calls.confirm.push({ title, message });
        return Promise.resolve(opts.confirm ?? false);
      },
      input(title: string, placeholder?: string) {
        calls.input.push({ title, placeholder });
        return Promise.resolve(opts.input);
      },
    },
  };
  return { ctx, calls };
}

function bashEvent(command: string): unknown {
  return { type: "tool_call", toolCallId: "t1", toolName: "bash", input: { command } };
}

/** Temp repo (no pin) + isolated empty HOME, restored afterward. */
async function withRepo(run: (cwd: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "ghig-boot-"));
  const home = await mkdtemp(join(tmpdir(), "ghig-home-"));
  const origHome = process.env.HOME;
  process.env.HOME = home;
  try {
    await run(root);
  } finally {
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    await rm(root, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
}

function getHandler(executor: Executor): Handler {
  const pi = makePi();
  (mod.default as (pi: unknown, deps?: unknown) => void)(pi, { executor });
  const h = pi.handlers.tool_call?.[0];
  assert.ok(h, "tool_call handler registered");
  return h;
}

async function pinExists(cwd: string): Promise<string | null> {
  try {
    return await fs.readFile(join(cwd, ".pi", "expected-identity"), "utf8");
  } catch {
    return null;
  }
}

// --- lib/bootstrap.ts unit tests -------------------------------------------

test("parseOwnerRepo handles the common remote URL shapes", () => {
  assert.deepEqual(parseOwnerRepo("https://github.com/owner/repo.git"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseOwnerRepo("git@github.com:owner/repo.git"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseOwnerRepo("ssh://git@github.com/owner/repo"), { owner: "owner", repo: "repo" });
  assert.deepEqual(parseOwnerRepo("https://x-access-token:tok@github.com/owner/repo.git"), {
    owner: "owner",
    repo: "repo",
  });
  assert.deepEqual(parseOwnerRepo("not a url"), { owner: "not a url", repo: "" });
});

test("originOwnerRepo invokes git with hardening flags before the subcommand", async () => {
  const { executor, calls } = makeExec({ originUrl: "https://github.com/alice/repo.git" });
  assert.deepEqual(await originOwnerRepo(executor, "/repo"), { owner: "alice", repo: "repo" });

  const gitCall = calls.find((c) => c.cmd === "git");
  assert.ok(gitCall, "git remote lookup was invoked");
  assert.deepEqual(gitCall.args, [
    "-C",
    "/repo",
    "-c",
    "core.fsmonitor=",
    "-c",
    "core.hooksPath=/dev/null",
    "remote",
    "get-url",
    "origin",
  ]);
});

test("computeSuggestion offers the active login only when it equals the origin owner and not a fork", async () => {
  const base = { login: "alice", originUrl: "https://github.com/alice/repo.git" };
  const eq = makeExec({ ...base, isFork: false });
  assert.deepEqual(await computeSuggestion(eq.executor, "/x", "alice"), { suggestion: "alice", owner: "alice" });

  const fork = makeExec({ ...base, isFork: true });
  assert.deepEqual(await computeSuggestion(fork.executor, "/x", "alice"), { suggestion: "", owner: "alice" });

  const mismatch = makeExec({ login: "alice", originUrl: "https://github.com/org/repo.git" });
  assert.deepEqual(await computeSuggestion(mismatch.executor, "/x", "alice"), { suggestion: "", owner: "org" });
});

test("writeExpectedIdentity writes a single trailing-newline line atomically", async () => {
  await withRepo(async (cwd) => {
    const path = writeExpectedIdentity(cwd, "mona-cat");
    assert.equal(await fs.readFile(path, "utf8"), "mona-cat\n");
  });
});

test("sanitizeForDisplay strips control bytes", () => {
  assert.equal(sanitizeForDisplay("a\u0000b\u001bc\u007fd\n"), "abcd");
});

test("classify exposes bypassNet only for the bypass-DENY-net shape", () => {
  assert.equal(classify("gh pr create --title x").bypassNet, false);
  assert.equal(classify("git push origin main").bypassNet, false);
  assert.equal(classify("bash -c 'gh pr create'").bypassNet, true);
});

// --- index.ts bootstrap wiring tests ---------------------------------------

test("accept + re-type a valid login: writes the file but STILL blocks (A1)", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({ login: "TheSemicolon", originUrl: "https://github.com/TheSemicolon/repo.git" });
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: true, input: "TheSemicolon" });
    const res = (await handler(bashEvent("gh pr create --title x"), ctx)) as { block: boolean; reason: string };
    assert.equal(res.block, true);
    assert.match(res.reason, /created .*expected-identity/);
    assert.match(res.reason, /human action \(commit\) is required|commit/);
    assert.equal(await pinExists(cwd), "TheSemicolon\n");
    assert.equal(calls.confirm.length, 1);
    assert.equal(calls.input.length, 1);
  });
});

test("decline: no file, falls through to the standard fail-closed block", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({});
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: false });
    const res = (await handler(bashEvent("gh pr create --title x"), ctx)) as { block: boolean; reason: string };
    assert.equal(res.block, true);
    assert.match(res.reason, /no expected identity configured/);
    assert.equal(await pinExists(cwd), null);
    assert.equal(calls.confirm.length, 1);
    assert.equal(calls.input.length, 0);
  });
});

test("invalid login: nothing written, error notify, fail-closed block", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({});
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: true, input: "not a valid login!" });
    const res = (await handler(bashEvent("gh pr create --title x"), ctx)) as { block: boolean; reason: string };
    assert.equal(res.block, true);
    assert.match(res.reason, /no expected identity configured/);
    assert.equal(await pinExists(cwd), null);
    assert.ok(calls.notify.some((n) => /not a valid GitHub login/.test(n.message) && n.level === "error"));
  });
});

test("no UI (print/json): never prompts, plain fail-closed block", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({});
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { hasUI: false, confirm: true, input: "TheSemicolon" });
    const res = (await handler(bashEvent("gh pr create --title x"), ctx)) as { block: boolean; reason: string };
    assert.equal(res.block, true);
    assert.match(res.reason, /no expected identity configured/);
    assert.equal(await pinExists(cwd), null);
    assert.equal(calls.confirm.length, 0);
  });
});

test("bypass-DENY-net shape: never prompts even with a UI (security MEDIUM-2)", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({});
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: true, input: "TheSemicolon" });
    const res = (await handler(bashEvent("bash -c 'gh pr create'"), ctx)) as { block: boolean };
    assert.equal(res.block, true);
    assert.equal(calls.confirm.length, 0);
    assert.equal(await pinExists(cwd), null);
  });
});

test("suggestion shown when active login == origin owner and not a fork", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({ login: "TheSemicolon", originUrl: "https://github.com/TheSemicolon/repo.git", isFork: false });
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: true, input: "TheSemicolon" });
    await handler(bashEvent("gh pr create --title x"), ctx);
    assert.match(calls.confirm[0].message, /suggested: TheSemicolon/);
    assert.match(calls.input[0].title, /re-type "TheSemicolon"/);
    // Never pre-filled — placeholder is empty (B1).
    assert.equal(calls.input[0].placeholder, "");
  });
});

test("suggestion suppressed on a personal fork (confused-deputy mitigation B1)", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({ login: "TheSemicolon", originUrl: "https://github.com/TheSemicolon/repo.git", isFork: true });
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: true, input: "TheSemicolon" });
    await handler(bashEvent("gh pr create --title x"), ctx);
    assert.doesNotMatch(calls.confirm[0].message, /suggested/);
    assert.doesNotMatch(calls.input[0].title, /re-type/);
  });
});

test("bootstrap writes only the per-repo file, never the user-layer settings.json", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({ login: "TheSemicolon", originUrl: "https://github.com/TheSemicolon/repo.git" });
    const handler = getHandler(executor);
    const { ctx } = makeCtx(cwd, { confirm: true, input: "TheSemicolon" });
    await handler(bashEvent("gh pr create --title x"), ctx);
    // HOME is the isolated temp dir; the user-layer file must not have been created.
    const home = process.env.HOME as string;
    assert.equal(await pinExists(cwd), "TheSemicolon\n");
    let userLayer: string | null = null;
    try {
      userLayer = await fs.readFile(join(home, ".pi", "agent", "settings.json"), "utf8");
    } catch {
      userLayer = null;
    }
    assert.equal(userLayer, null);
  });
});

test("probe failure still allows manual entry (no suggestion)", async () => {
  await withRepo(async (cwd) => {
    const { executor } = makeExec({ rejectProbe: true });
    const handler = getHandler(executor);
    const { ctx, calls } = makeCtx(cwd, { confirm: true, input: "TheSemicolon" });
    const res = (await handler(bashEvent("gh pr create --title x"), ctx)) as { block: boolean; reason: string };
    assert.equal(res.block, true);
    assert.match(res.reason, /created .*expected-identity/);
    assert.equal(await pinExists(cwd), "TheSemicolon\n");
    assert.doesNotMatch(calls.confirm[0].message, /suggested/);
  });
});
