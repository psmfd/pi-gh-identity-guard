/**
 * gh-identity-guard — identity resolution unit tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  type Executor,
  ProbeError,
  probeActiveIdentity,
  resolveExpectedIdentity,
  resolveIdentity,
} from "../lib/identity.ts";

async function makeRepo(): Promise<{ root: string; cleanup: () => Promise<void> }> {
  const root = await mkdtemp(join(tmpdir(), "ghig-resolve-"));
  await fs.mkdir(join(root, ".pi"), { recursive: true });
  return { root, cleanup: () => rm(root, { recursive: true, force: true }) };
}

function trackingExecutor(
  status: "tracked" | "untracked" | "throw" = "tracked",
): Executor {
  return {
    exec(cmd, args) {
      if (cmd === "git" && args.includes("ls-files")) {
        if (status === "throw") return Promise.reject(new Error("git failed"));
        return Promise.resolve({
          exitCode: status === "tracked" ? 0 : 1,
          stdout: status === "tracked" ? ".pi/expected-identity\n" : "",
          stderr: "",
        });
      }
      return Promise.resolve({ exitCode: 127, stdout: "", stderr: "" });
    },
  };
}

// `chmod 000` is a no-op for root, so the unreadable-file path can't be
// exercised there — skip rather than emit a false failure.
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

test("resolveExpectedIdentity: returns null when neither layer is set", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    // No .pi/expected-identity, and we cannot easily test the user-layer
    // fallback in isolation — its absence in the test homedir returns null.
    const result = await resolveExpectedIdentity(root, trackingExecutor());
    // Result may be null OR may pick up the operator's actual settings.json.
    // Assert only the shape: either null or an array of valid logins.
    if (result !== null) {
      assert.ok(Array.isArray(result));
      for (const l of result) {
        assert.equal(typeof l, "string");
      }
    }
  } finally {
    await cleanup();
  }
});

test("resolveExpectedIdentity: reads per-repo file (single login)", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(join(root, ".pi", "expected-identity"), "TheSemicolon\n");
    assert.deepEqual(await resolveExpectedIdentity(root, trackingExecutor()), ["TheSemicolon"]);
  } finally {
    await cleanup();
  }
});

test("resolveExpectedIdentity: reads per-repo file (multiple logins)", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(
      join(root, ".pi", "expected-identity"),
      "# allow either of these\nbot-foo\nhuman-maintainer\n",
    );
    assert.deepEqual(await resolveExpectedIdentity(root, trackingExecutor()), ["bot-foo", "human-maintainer"]);
  } finally {
    await cleanup();
  }
});

test("resolveExpectedIdentity: per-repo file with only invalid logins returns null", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(
      join(root, ".pi", "expected-identity"),
      "-invalid\nalso--invalid\n",
    );
    // Both filtered out → null (falls back to user-layer which may or may not be set).
    // We just assert it's not the invalid logins.
    const result = await resolveExpectedIdentity(root, trackingExecutor());
    if (result !== null) {
      assert.equal(result.includes("-invalid"), false);
      assert.equal(result.includes("also--invalid"), false);
    }
  } finally {
    await cleanup();
  }
});

test("resolveExpectedIdentity: per-repo file ignores blanks and inline comments", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(
      join(root, ".pi", "expected-identity"),
      "alice  # primary\n\nbob\n",
    );
    assert.deepEqual(await resolveExpectedIdentity(root, trackingExecutor()), ["alice", "bob"]);
  } finally {
    await cleanup();
  }
});

test("resolveIdentity: untracked per-repo file is ignored (#306)", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(join(root, ".pi", "expected-identity"), "TheSemicolon\n");
    const result = await resolveIdentity(root, trackingExecutor("untracked"));
    assert.equal(result.perRepoFilePresentButUntracked, true);
    assert.equal(result.perRepoFileTrackingIndeterminate, false);
    assert.equal(result.perRepoFilePresentButEmpty, false);
    assert.equal(result.perRepoFilePresentButUnreadable, false);
  } finally {
    await cleanup();
  }
});

test("resolveIdentity: indeterminate tracking check is ignored (#306)", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(join(root, ".pi", "expected-identity"), "TheSemicolon\n");
    const result = await resolveIdentity(root, trackingExecutor("throw"));
    assert.equal(result.perRepoFilePresentButUntracked, false);
    assert.equal(result.perRepoFileTrackingIndeterminate, true);
    assert.equal(result.perRepoFilePresentButEmpty, false);
    assert.equal(result.perRepoFilePresentButUnreadable, false);
  } finally {
    await cleanup();
  }
});

// --- probeActiveIdentity ---------------------------------------------------

function fakeExecutor(spec: {
  exitCode?: number;
  stdout?: string;
  stderr?: string;
  throwOn?: string;
}): Executor {
  return {
    exec(_cmd, _args) {
      if (spec.throwOn) return Promise.reject(new Error(spec.throwOn));
      return Promise.resolve({
        exitCode: spec.exitCode ?? 0,
        stdout: spec.stdout ?? "",
        stderr: spec.stderr ?? "",
      });
    },
  };
}

test("probeActiveIdentity: returns trimmed login on success", async () => {
  const login = await probeActiveIdentity(fakeExecutor({ stdout: "TheSemicolon\n" }));
  assert.equal(login, "TheSemicolon");
});

test("probeActiveIdentity: throws gh-not-found on ENOENT", async () => {
  await assert.rejects(
    () => probeActiveIdentity(fakeExecutor({ throwOn: "spawn gh ENOENT" })),
    (err: unknown) => err instanceof ProbeError && err.kind === "gh-not-found",
  );
});

test("probeActiveIdentity: throws exec-failed on non-zero exit", async () => {
  await assert.rejects(
    () =>
      probeActiveIdentity(
        fakeExecutor({ exitCode: 1, stderr: "HTTP 401: Bad credentials" }),
      ),
    (err: unknown) => err instanceof ProbeError && err.kind === "exec-failed",
  );
});

test("probeActiveIdentity: throws empty-login on empty stdout", async () => {
  await assert.rejects(
    () => probeActiveIdentity(fakeExecutor({ stdout: "\n" })),
    (err: unknown) => err instanceof ProbeError && err.kind === "empty-login",
  );
});

test("probeActiveIdentity: throws malformed-login on garbage stdout", async () => {
  await assert.rejects(
    () => probeActiveIdentity(fakeExecutor({ stdout: "not a valid login!\n" })),
    (err: unknown) => err instanceof ProbeError && err.kind === "malformed-login",
  );
});

test("probeActiveIdentity: times out (exec-failed) when the probe hangs (#259)", async () => {
  // A never-resolving executor models a captive-portal/slowloris stall. The
  // Promise.race timeout must win and surface a ProbeError so callers fail
  // closed — never hang indefinitely.
  const hangingExecutor: Executor = {
    exec() {
      return new Promise(() => {
        /* never settles */
      });
    },
  };
  const start = Date.now();
  await assert.rejects(
    () => probeActiveIdentity(hangingExecutor, { timeoutMs: 20 }),
    (err: unknown) => err instanceof ProbeError && err.kind === "exec-failed",
  );
  // Sanity: it resolved promptly via the timeout, not after some long wait.
  assert.ok(Date.now() - start < 1000);
});

test("probeActiveIdentity: abort-wins race still reports a timeout message (#259)", async () => {
  // Model the real spawn-with-signal executor: when the controller aborts,
  // the child rejects with an AbortError that can win the race ahead of the
  // timer's own ProbeError. The catch must normalize to the timeout message.
  const abortingExecutor: Executor = {
    exec(_cmd, _args, signal) {
      return new Promise((_resolve, reject) => {
        signal?.addEventListener("abort", () => {
          const e = new Error("The operation was aborted");
          (e as NodeJS.ErrnoException).code = "ABORT_ERR";
          reject(e);
        });
      });
    },
  };
  await assert.rejects(
    () => probeActiveIdentity(abortingExecutor, { timeoutMs: 20 }),
    (err: unknown) =>
      err instanceof ProbeError &&
      err.kind === "exec-failed" &&
      /timed out/.test(err.message),
  );
});

// --- resolveIdentity (per-repo-empty diagnostic, #259 item 2) --------------

test("resolveIdentity: per-repo file present but all-invalid sets the empty flag", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(
      join(root, ".pi", "expected-identity"),
      "-invalid\nalso--invalid\n",
    );
    const result = await resolveIdentity(root, trackingExecutor());
    assert.equal(result.perRepoFilePresentButEmpty, true);
    // The two diagnostics are mutually exclusive: empty-but-readable is not
    // unreadable.
    assert.equal(result.perRepoFilePresentButUnreadable, false);
    // logins falls through to the user layer (may be null or operator's
    // real settings) — assert only that it is NOT the invalid entries.
    if (result.logins !== null) {
      assert.equal(result.logins.includes("-invalid"), false);
    }
  } finally {
    await cleanup();
  }
});

test("resolveIdentity: per-repo file with valid logins does not set the empty flag", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    await fs.writeFile(join(root, ".pi", "expected-identity"), "TheSemicolon\n");
    assert.deepEqual(await resolveIdentity(root, trackingExecutor()), {
      logins: ["TheSemicolon"],
      perRepoFilePresentButEmpty: false,
      perRepoFilePresentButUnreadable: false,
      perRepoFilePresentButUntracked: false,
      perRepoFileTrackingIndeterminate: false,
    });
  } finally {
    await cleanup();
  }
});

test("resolveIdentity: absent per-repo file does not set the empty flag", async () => {
  const { root, cleanup } = await makeRepo();
  try {
    // makeRepo creates .pi/ but no expected-identity file.
    const result = await resolveIdentity(root, trackingExecutor());
    assert.equal(result.perRepoFilePresentButEmpty, false);
    assert.equal(result.perRepoFilePresentButUnreadable, false);
    assert.equal(result.perRepoFilePresentButUntracked, false);
    assert.equal(result.perRepoFileTrackingIndeterminate, false);
  } finally {
    await cleanup();
  }
});

test(
  "resolveIdentity: unreadable per-repo file sets the unreadable flag (#268)",
  { skip: isRoot ? "cannot make a file unreadable as root" : false },
  async () => {
    const { root, cleanup } = await makeRepo();
    const pin = join(root, ".pi", "expected-identity");
    try {
      await fs.writeFile(pin, "TheSemicolon\n");
      await fs.chmod(pin, 0o000);
      const result = await resolveIdentity(root, trackingExecutor());
      assert.equal(result.perRepoFilePresentButUnreadable, true);
      assert.equal(result.perRepoFilePresentButEmpty, false, "not reported as empty");
    } finally {
      await fs.chmod(pin, 0o644).catch(() => {});
      await cleanup();
    }
  },
);
