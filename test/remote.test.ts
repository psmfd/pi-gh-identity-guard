/**
 * gh-identity-guard — remote-host resolution unit tests (ADR-0023).
 *
 * Covers the pure host-extraction helpers and the subprocess-backed
 * `resolvePushHost`/`scopeGitPushes` (via an injected fake Executor). The
 * security-relevant invariants under test:
 *   - exact `github.com` match (look-alikes are non-github);
 *   - SSH-alias resolution via `ssh -G`;
 *   - fail-closed on inline `-c …insteadOf=`, unresolvable upstream, and
 *     subprocess errors.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import type { GitPushInvocation } from "../lib/classifier.ts";
import type { Executor } from "../lib/identity.ts";
import {
  extractHost,
  isGithubHost,
  isSshForm,
  looksLikeUrl,
  resolvePushHost,
  scopeGitPushes,
} from "../lib/remote.ts";

// --- extractHost ------------------------------------------------------------

const HOST_CASES: ReadonlyArray<readonly [string, string]> = [
  ["https://github.com/o/r.git", "github.com"],
  ["https://github.com/o/r", "github.com"],
  ["git@github.com:o/r.git", "github.com"],
  ["ssh://git@github.com:22/o/r", "github.com"],
  ["https://token@github.com/o/r", "github.com"],
  ["https://user:pa@ss@github.com/o/r", "github.com"], // double-@ userinfo
  ["git@github.com.:o/r", "github.com"], // trailing-dot FQDN
  ["https://GitHub.COM/o/r", "github.com"], // case fold
  ["https://dev.azure.com/org/proj/_git/repo", "dev.azure.com"],
  ["git@ssh.dev.azure.com:v3/o/p/r", "ssh.dev.azure.com"],
  ["https://org.visualstudio.com/proj/_git/repo", "org.visualstudio.com"],
  ["org@vs-ssh.visualstudio.com:v3/o/p/r", "vs-ssh.visualstudio.com"],
  ["https://github.com.attacker.tld/o/r", "github.com.attacker.tld"],
  ["https://notgithub.com/o/r", "notgithub.com"],
  ["", ""],
];

test("extractHost handles scheme, userinfo, scp, port, trailing-dot, case", () => {
  for (const [url, host] of HOST_CASES) {
    assert.equal(extractHost(url), host, `extractHost(${JSON.stringify(url)})`);
  }
});

test("isGithubHost is exact, not substring", () => {
  assert.equal(isGithubHost("github.com"), true);
  assert.equal(isGithubHost("github.com.attacker.tld"), false);
  assert.equal(isGithubHost("notgithub.com"), false);
  assert.equal(isGithubHost("ssh.dev.azure.com"), false);
});

test("looksLikeUrl distinguishes URLs from named remotes", () => {
  assert.equal(looksLikeUrl("origin"), false);
  assert.equal(looksLikeUrl("upstream"), false);
  assert.equal(looksLikeUrl("https://github.com/o/r"), true);
  assert.equal(looksLikeUrl("git@github.com:o/r"), true);
  assert.equal(looksLikeUrl("/abs/path"), true);
  assert.equal(looksLikeUrl("./rel"), true);
});

test("isSshForm flags ssh:// and scp-style only", () => {
  assert.equal(isSshForm("git@github.com:o/r"), true);
  assert.equal(isSshForm("ssh://git@github.com/o/r"), true);
  assert.equal(isSshForm("https://github.com/o/r"), false);
  assert.equal(isSshForm("https://dev.azure.com/o/p/_git/r"), false);
  assert.equal(isSshForm("origin"), false);
});

// --- fake executor ----------------------------------------------------------

interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr?: string;
}
function fakeExecutor(map: {
  revParse?: ExecResult;
  getUrl?: ExecResult;
  ssh?: ExecResult;
}): Executor {
  return {
    exec(cmd, args) {
      if (cmd === "git" && args.includes("rev-parse")) {
        return Promise.resolve({
          stderr: "",
          ...(map.revParse ?? { exitCode: 128, stdout: "" }),
        });
      }
      if (cmd === "git" && args.includes("get-url")) {
        return Promise.resolve({
          stderr: "",
          ...(map.getUrl ?? { exitCode: 128, stdout: "" }),
        });
      }
      if (cmd === "ssh") {
        return Promise.resolve({
          stderr: "",
          ...(map.ssh ?? { exitCode: 255, stdout: "" }),
        });
      }
      return Promise.resolve({ exitCode: 127, stdout: "", stderr: "" });
    },
  };
}

function inv(partial: Partial<GitPushInvocation> = {}): GitPushInvocation {
  return {
    argv: ["git", "push"],
    cDirs: [],
    remoteArg: null,
    inlineConfigRewrite: false,
    repoDirOverride: false,
    ...partial,
  };
}

// --- resolvePushHost --------------------------------------------------------

test("inline insteadOf rewrite → indeterminate (fail closed)", async () => {
  const v = await resolvePushHost(
    fakeExecutor({ getUrl: { exitCode: 0, stdout: "https://dev.azure.com/x\n" } }),
    "/cwd",
    inv({ inlineConfigRewrite: true, remoteArg: "origin" }),
  );
  assert.equal(v, "indeterminate");
});

test("--git-dir/--work-tree override → indeterminate (fail closed)", async () => {
  const v = await resolvePushHost(
    fakeExecutor({ getUrl: { exitCode: 0, stdout: "https://dev.azure.com/x\n" } }),
    "/cwd",
    inv({ repoDirOverride: true, remoteArg: "origin" }),
  );
  assert.equal(v, "indeterminate");
});

test("detached-HEAD ref ('HEAD') resolves to no remote → indeterminate", async () => {
  // Some git versions emit `HEAD` (exit 0) for `@{push}` in detached HEAD;
  // `get-url --push --all HEAD` then fails → indeterminate (fail closed).
  const v = await resolvePushHost(
    fakeExecutor({
      revParse: { exitCode: 0, stdout: "HEAD\n" },
      getUrl: { exitCode: 128, stdout: "" },
    }),
    "/cwd",
    inv({ remoteArg: null }),
  );
  assert.equal(v, "indeterminate");
});

test("git subprocesses carry the fsmonitor/hooksPath hardening flags", async () => {
  const seen: string[][] = [];
  const recording: Executor = {
    exec(cmd, args) {
      if (cmd === "git") seen.push([...args]);
      if (cmd === "git" && args.includes("get-url")) {
        return Promise.resolve({
          exitCode: 0,
          stdout: "https://dev.azure.com/x\n",
          stderr: "",
        });
      }
      return Promise.resolve({ exitCode: 0, stdout: "origin/main\n", stderr: "" });
    },
  };
  await resolvePushHost(recording, "/cwd", inv({ remoteArg: null }));
  assert.ok(seen.length > 0, "git was invoked");
  for (const args of seen) {
    assert.equal(args[0], "-C");
    assert.ok(
      args.includes("core.fsmonitor=") && args.includes("core.hooksPath=/dev/null"),
      "hardening flags present in every git call",
    );
  }
});

test("explicit github.com URL arg → github (no subprocess)", async () => {
  const v = await resolvePushHost(
    fakeExecutor({}),
    "/cwd",
    inv({ remoteArg: "https://github.com/o/r.git" }),
  );
  assert.equal(v, "github");
});

test("explicit ADO URL arg → non-github", async () => {
  const v = await resolvePushHost(
    fakeExecutor({}),
    "/cwd",
    inv({ remoteArg: "https://dev.azure.com/o/p/_git/r" }),
  );
  assert.equal(v, "non-github");
});

test("named remote resolving to github.com → github", async () => {
  const v = await resolvePushHost(
    fakeExecutor({ getUrl: { exitCode: 0, stdout: "https://github.com/o/r.git\n" } }),
    "/cwd",
    inv({ remoteArg: "origin" }),
  );
  assert.equal(v, "github");
});

test("named remote resolving to ADO → non-github", async () => {
  const v = await resolvePushHost(
    fakeExecutor({ getUrl: { exitCode: 0, stdout: "https://dev.azure.com/o/p/_git/r\n" } }),
    "/cwd",
    inv({ remoteArg: "origin" }),
  );
  assert.equal(v, "non-github");
});

test("SSH remote resolved via ssh -G to github → github", async () => {
  const v = await resolvePushHost(
    fakeExecutor({
      getUrl: { exitCode: 0, stdout: "git@gh-personal:o/r.git\n" },
      ssh: { exitCode: 0, stdout: "hostname github.com\n" },
    }),
    "/cwd",
    inv({ remoteArg: "origin" }),
  );
  assert.equal(v, "github");
});

test("SSH remote whose ssh -G fails → indeterminate (fail closed)", async () => {
  const v = await resolvePushHost(
    fakeExecutor({
      getUrl: { exitCode: 0, stdout: "git@gh-personal:o/r.git\n" },
      ssh: { exitCode: 255, stdout: "" },
    }),
    "/cwd",
    inv({ remoteArg: "origin" }),
  );
  assert.equal(v, "indeterminate");
});

test("bare push with unresolvable @{push} → indeterminate", async () => {
  const v = await resolvePushHost(
    fakeExecutor({ revParse: { exitCode: 128, stdout: "" } }),
    "/cwd",
    inv({ remoteArg: null }),
  );
  assert.equal(v, "indeterminate");
});

test("bare push resolves @{push} then get-url → host", async () => {
  const v = await resolvePushHost(
    fakeExecutor({
      revParse: { exitCode: 0, stdout: "origin/main\n" },
      getUrl: { exitCode: 0, stdout: "https://github.com/o/r.git\n" },
    }),
    "/cwd",
    inv({ remoteArg: null }),
  );
  assert.equal(v, "github");
});

test("multiple push URLs: any github → github", async () => {
  const v = await resolvePushHost(
    fakeExecutor({
      getUrl: {
        exitCode: 0,
        stdout: "https://dev.azure.com/o/p/_git/r\nhttps://github.com/o/r.git\n",
      },
    }),
    "/cwd",
    inv({ remoteArg: "origin" }),
  );
  assert.equal(v, "github");
});

// --- scopeGitPushes ---------------------------------------------------------

test("scopeGitPushes: all non-github → non-github", async () => {
  const exec = fakeExecutor({
    getUrl: { exitCode: 0, stdout: "https://dev.azure.com/o/p/_git/r\n" },
  });
  const v = await scopeGitPushes(exec, "/cwd", [
    inv({ remoteArg: "origin" }),
    inv({ remoteArg: "https://dev.azure.com/o/p/_git/r2" }),
  ]);
  assert.equal(v, "non-github");
});

test("scopeGitPushes: any github → github", async () => {
  const v = await scopeGitPushes(fakeExecutor({}), "/cwd", [
    inv({ remoteArg: "https://dev.azure.com/o/p/_git/r" }),
    inv({ remoteArg: "https://github.com/o/r.git" }),
  ]);
  assert.equal(v, "github");
});

test("scopeGitPushes: any indeterminate (no github) → indeterminate", async () => {
  const v = await scopeGitPushes(fakeExecutor({}), "/cwd", [
    inv({ remoteArg: "https://dev.azure.com/o/p/_git/r" }),
    inv({ inlineConfigRewrite: true, remoteArg: "origin" }),
  ]);
  assert.equal(v, "indeterminate");
});
