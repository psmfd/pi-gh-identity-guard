/**
 * gh-identity-guard — override-parsing unit tests.
 *
 * Sourced from ADR-0022 § Q5 and the security-review validation
 * 2026-05-26 (sharpenings: strict anchored parse, leading-assignment
 * support, duplicate-key rejection, GitHub-login regex pre-validation).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  loadAllowlist,
  matchesAllowlist,
  parseOverride,
} from "../lib/overrides.ts";
import { isValidGhLogin } from "../lib/identity.ts";

import { promises as fs } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function makeTmp(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

test("parseOverride: absent prefix returns kind none", () => {
  assert.deepEqual(parseOverride("gh pr create --title hi"), { kind: "none" });
  assert.deepEqual(parseOverride(""), { kind: "none" });
});

test("parseOverride: valid login at start", () => {
  assert.deepEqual(parseOverride("GH_IDENTITY_OVERRIDE=bot-foo gh pr comment 42 --body hi"), {
    kind: "valid",
    login: "bot-foo",
  });
});

test("parseOverride: valid login after other leading env-var assignments", () => {
  assert.deepEqual(
    parseOverride("GH_DEBUG=1 GH_TOKEN=xxx GH_IDENTITY_OVERRIDE=service-bot gh pr merge 42"),
    { kind: "valid", login: "service-bot" },
  );
});

test("parseOverride: double-quoted value is unwrapped", () => {
  assert.deepEqual(parseOverride('GH_IDENTITY_OVERRIDE="bot-foo" gh pr merge 42'), {
    kind: "valid",
    login: "bot-foo",
  });
});

test("parseOverride: single-quoted value is unwrapped", () => {
  assert.deepEqual(parseOverride("GH_IDENTITY_OVERRIDE='bot-foo' gh pr merge 42"), {
    kind: "valid",
    login: "bot-foo",
  });
});

test("parseOverride: leading whitespace is stripped", () => {
  assert.deepEqual(parseOverride("   GH_IDENTITY_OVERRIDE=alice gh pr create"), {
    kind: "valid",
    login: "alice",
  });
});

test("parseOverride: duplicate keys in leading run are rejected", () => {
  const result = parseOverride("GH_IDENTITY_OVERRIDE=a GH_IDENTITY_OVERRIDE=b gh pr merge 42");
  assert.equal(result.kind, "invalid");
  if (result.kind === "invalid") {
    assert.match(result.reason, /duplicate/i);
  }
});

test("parseOverride: empty value is rejected", () => {
  const result = parseOverride("GH_IDENTITY_OVERRIDE= gh pr merge 42");
  assert.equal(result.kind, "invalid");
});

test("parseOverride: malformed login is rejected (newline injection)", () => {
  const result = parseOverride("GH_IDENTITY_OVERRIDE=evil\\ninjection gh pr merge 42");
  assert.equal(result.kind, "invalid");
});

test("parseOverride: malformed login is rejected (leading hyphen)", () => {
  const result = parseOverride("GH_IDENTITY_OVERRIDE=-bad gh pr merge 42");
  assert.equal(result.kind, "invalid");
});

test("parseOverride: malformed login is rejected (consecutive hyphens)", () => {
  const result = parseOverride("GH_IDENTITY_OVERRIDE=foo--bar gh pr merge 42");
  assert.equal(result.kind, "invalid");
});

test("parseOverride: malformed login is rejected (>39 chars)", () => {
  const long = "a".repeat(40);
  const result = parseOverride(`GH_IDENTITY_OVERRIDE=${long} gh pr merge 42`);
  assert.equal(result.kind, "invalid");
});

test("parseOverride: prefix inside `bash -c '...'` is NOT recognized", () => {
  // Outer command is `bash`, no leading env-var assignment of our key.
  // The bypass-DENY net in the classifier handles this case separately.
  const result = parseOverride("bash -c 'GH_IDENTITY_OVERRIDE=evil gh pr merge 42'");
  assert.equal(result.kind, "none");
});

test("parseOverride: prefix inside a quoted string is NOT recognized", () => {
  // The token "echo" is not a leading assignment, so parser stops.
  const result = parseOverride(`echo 'GH_IDENTITY_OVERRIDE=evil'`);
  assert.equal(result.kind, "none");
});

test("isValidGhLogin: positive cases", () => {
  assert.ok(isValidGhLogin("a"));
  assert.ok(isValidGhLogin("TheSemicolon"));
  assert.ok(isValidGhLogin("bot-foo"));
  assert.ok(isValidGhLogin("a-b-c"));
  assert.ok(isValidGhLogin("a".repeat(39)));
  // EMU accounts (#262): <idp-username>_<shortcode>, shortcode 3–8 alnum.
  assert.ok(isValidGhLogin("Example-User_acme"));
  assert.ok(isValidGhLogin("mona-cat_octo"));
  assert.ok(isValidGhLogin("setup_admin8"));
  assert.ok(isValidGhLogin("a_xyz"), "3-char shortcode is min");
  assert.ok(isValidGhLogin("a_12345678"), "8-char shortcode is max");
});

test("isValidGhLogin: negative cases", () => {
  assert.equal(isValidGhLogin(""), false);
  assert.equal(isValidGhLogin("-leading-hyphen"), false);
  assert.equal(isValidGhLogin("trailing-hyphen-"), false);
  assert.equal(isValidGhLogin("double--hyphen"), false);
  assert.equal(isValidGhLogin("a".repeat(40)), false);
  assert.equal(isValidGhLogin("has space"), false);
  assert.equal(isValidGhLogin("has@symbol"), false);
  assert.equal(isValidGhLogin("has\nnewline"), false);
  // EMU regressions (#262).
  assert.equal(isValidGhLogin("_leading-underscore"), false);
  assert.equal(isValidGhLogin("name_xy"), false, "shortcode <3 chars rejected");
  assert.equal(
    isValidGhLogin("name_123456789"),
    false,
    "shortcode >8 chars rejected",
  );
  assert.equal(
    isValidGhLogin("name_short_extra"),
    false,
    "only one underscore separator allowed",
  );
  assert.equal(
    isValidGhLogin("name_short-code"),
    false,
    "shortcode must be alnum, no dashes",
  );
  // Total-length cap still authoritative across EMU form.
  assert.equal(
    isValidGhLogin("a".repeat(32) + "_abcdefgh"),
    false,
    "total >39 chars rejected even with valid EMU shape",
  );
});

test("loadAllowlist: returns empty when file absent", async () => {
  const tmp = await makeTmp("ghig-allow-");
  try {
    assert.deepEqual(loadAllowlist(tmp), []);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test("loadAllowlist: reads patterns, ignores blanks and comments", async () => {
  const tmp = await makeTmp("ghig-allow-");
  try {
    await fs.writeFile(
      join(tmp, ".gh-identity-allowlist"),
      "# this is a comment\n\ngh pr comment\n  gh issue comment  \n# trailing\n",
    );
    assert.deepEqual(loadAllowlist(tmp), ["gh pr comment", "gh issue comment"]);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test("matchesAllowlist: exact substring match", () => {
  const patterns = ["gh pr comment", "gh issue comment"];
  assert.equal(
    matchesAllowlist("gh pr comment 42 --body hi", patterns),
    "gh pr comment",
  );
  assert.equal(matchesAllowlist("gh pr merge 42", patterns), null);
});
