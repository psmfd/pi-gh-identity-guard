/**
 * gh-identity-guard — classifier unit tests.
 *
 * Test corpus sourced from ADR-0022 § Q2 (mutation matcher scope), which
 * inherited it from the shell-expert research brief attached to issue #250.
 *
 * Target: ≥35 positive (mutating) + ≥35 negative (non-mutating) cases.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classify,
  detectBypass,
  extractDollarParenInners,
  splitSegments,
  stripHeredocs,
  tokenize,
} from "../lib/classifier.ts";

// --- Positive cases (must classify as mutating) ----------------------------

const POSITIVE: ReadonlyArray<readonly [string, string]> = [
  // gh <noun> <verb>
  ['gh pr create --title "x" --body "y"', "gh pr create"],
  ["gh pr merge 42 --squash", "gh pr merge"],
  ["gh pr close 99", "gh pr close"],
  ["gh pr ready 42", "gh pr ready"],
  ['gh issue create --title "bug"', "gh issue create"],
  ["gh issue close 17 --reason completed", "gh issue close"],
  ["gh issue edit 17 --add-label triage", "gh issue edit"],
  ['gh release create v1.2.3 --notes "release"', "gh release create"],
  ["gh release delete v1.0.0 --yes", "gh release delete"],
  ["gh repo create foo/bar --public", "gh repo create"],
  ["gh repo delete foo/bar --yes", "gh repo delete"],
  ["gh repo fork upstream/proj", "gh repo fork"],
  ["gh repo archive foo/bar", "gh repo archive"],
  ["gh label create bug --color ff0000", "gh label create"],
  ['gh secret set DEPLOY_KEY --body "..."', "gh secret set"],
  ['gh variable set REGION --body "us-east-1"', "gh variable set"],
  ["gh workflow run ci.yml", "gh workflow run"],
  ["gh workflow enable nightly.yml", "gh workflow enable"],
  ['gh project create --owner @me --title "Q1"', "gh project create"],
  ["gh ruleset create --file ruleset.json", "gh ruleset create"],
  ["gh gist create file.txt", "gh gist create"],
  ["gh auth switch --user other-account", "gh auth switch"],
  ["gh auth login", "gh auth login"],
  ["gh alias set ship 'pr merge --squash'", "gh alias set"],
  // gh api mutating methods
  ["gh api -X POST repos/foo/bar/issues -f title=bug", "gh api -X POST"],
  [
    "gh api --method DELETE repos/foo/bar/issues/comments/123",
    "gh api --method DELETE",
  ],
  ["gh api repos/foo/bar/issues -f title=x", "gh api implicit POST via -f"],
  ["gh api -XPATCH repos/foo/bar -f description=new", "gh api -XPATCH"],
  ["gh api --method=DELETE repos/foo/bar/labels/old", "gh api --method=DELETE"],
  ["gh api --field title=x repos/foo/bar/issues", "gh api implicit POST via --field"],
  ["gh api -F sub_issue_id=42 repos/foo/bar/issues/1/sub_issues", "gh api -F"],
  ["gh api -X GET -X POST repos/foo/bar -f x=1", "gh api last -X POST wins (mutating)"],
  // git push variants
  ["git push", "git push bare"],
  ["git push origin main", "git push origin main"],
  ["git push origin +main", "git push +refspec"],
  ["git push --force-with-lease origin feature", "git push --force-with-lease"],
  ["git push -f", "git push -f"],
  ["git push --delete origin old-branch", "git push --delete"],
  ["git push -d origin old-branch", "git push -d"],
  ["git push --mirror backup", "git push --mirror"],
  ["git push --tags", "git push --tags"],
  ["git push --all origin", "git push --all"],
  // bypass-DENY net forces identity verification
  ["bash -c 'gh pr create --title hi'", "bash -c with gh"],
  ['sh -c "git push origin main"', "sh -c with git push"],
  ['eval "gh release create v9"', "eval with gh"],
  ["echo before && gh pr merge 1 && echo after", "compound && with mutation"],
  ["xargs gh pr close < ids.txt", "xargs gh"],
  ["$(echo gh) pr create", "command substitution containing gh"],
  // nested command substitution — gh after a nested close (#259 item 5)
  ["$(foo $(bar) gh pr merge 1)", "nested $() with gh after inner close"],
  ["echo $(printf '%s' \"$(gh auth token)\")", "deeply nested $() with gh"],
  // wrapper-binary bypass coverage (security-review 2026-05-26 HIGH)
  ["env GH_TOKEN=x gh pr create --title hi", "env wrapper"],
  ["nohup gh pr merge 42", "nohup wrapper"],
  ["timeout 60 gh pr merge 42", "timeout with duration"],
  ["timeout --signal=KILL 30s gh pr merge 42", "timeout with --signal=KILL"],
  ["sudo gh repo delete foo/bar --yes", "sudo wrapper"],
  ["nice -n 10 gh pr merge 42", "nice with -n value"],
  ["sudo env GH_TOKEN=x gh pr create --title hi", "nested sudo+env wrapper"],
  ["stdbuf -oL gh release create v1.2.3", "stdbuf wrapper"],
  // git-global-flag bypass coverage (security-review 2026-05-26 HIGH)
  ["git -C /tmp/repo push origin main", "git -C path push"],
  ["git -c user.name=foo push", "git -c push"],
  ["git --git-dir=/tmp/.git push", "git --git-dir=value push"],
  ["git --git-dir /tmp/.git push origin main", "git --git-dir value push"],
  ["git --no-pager push origin main", "git --no-pager push"],
  ["git -C /tmp -c user.email=x push --force", "git -C + -c + push"],
  // xargs option-args bypass (code-review 2026-05-26 ERROR)
  ["xargs -I {} gh pr close {} < ids.txt", "xargs -I {} gh"],
  ["xargs -L 5 gh pr close", "xargs -L N gh"],
  ["xargs -n 1 gh pr close", "xargs -n 1 gh"],
  // -h must NOT defuse classification (security-review MEDIUM)
  ["gh pr create --title 'fix -h bug'", "-h inside quoted title"],
];

// --- Negative cases (must NOT classify as mutating) ------------------------

const NEGATIVE: ReadonlyArray<readonly [string, string]> = [
  // read-only gh
  ["gh pr list", "gh pr list"],
  ["gh pr view 42", "gh pr view"],
  ["gh pr diff 42", "gh pr diff"],
  ["gh pr checks 42", "gh pr checks"],
  ['gh issue list --search "create new dashboard"', "gh issue list with create in search"],
  ["gh issue view 17 --comments", "gh issue view"],
  ["gh release list", "gh release list"],
  ["gh release view v1.0.0", "gh release view"],
  ["gh release download v1.0.0", "gh release download"],
  ["gh repo view foo/bar", "gh repo view"],
  ["gh repo list --limit 50", "gh repo list"],
  ["gh repo clone foo/bar", "gh repo clone (local)"],
  ["gh pr checkout 42", "gh pr checkout (local-only)"],
  ["gh run list", "gh run list"],
  ["gh run view 12345", "gh run view"],
  ["gh workflow list", "gh workflow list"],
  ["gh workflow view ci.yml", "gh workflow view"],
  ["gh secret list", "gh secret list"],
  ["gh variable list", "gh variable list"],
  ["gh auth status", "gh auth status"],
  ["gh api /user", "gh api GET /user"],
  ["gh api repos/foo/bar", "gh api GET repos/foo/bar"],
  ["gh api repos/foo/bar/issues --paginate", "gh api GET with --paginate"],
  // explicit read method overrides implicit-POST flags (#259 item 6)
  ["gh api -X GET -f q=octocat search/users", "gh api -X GET overrides -f"],
  ["gh api --method=GET -f per_page=100 search/issues", "gh api --method=GET overrides -f"],
  ["gh api -XGET -F x=1 repos/foo/bar", "gh api -XGET overrides -F"],
  ["gh api -X HEAD repos/foo/bar", "gh api -X HEAD"],
  ["gh api -X HEAD -f x=1 repos/foo/bar", "gh api -X HEAD overrides -f"],
  ["gh api -X POST -X GET search/issues -f q=x", "gh api last -X GET wins (non-mutating)"],
  // read-only git
  ["git pull", "git pull"],
  ["git fetch --all", "git fetch"],
  ["git fetch origin main", "git fetch origin"],
  ["git clone https://github.com/foo/bar", "git clone"],
  ["git status", "git status"],
  ["git log --oneline", "git log"],
  ["git diff", "git diff"],
  // help / dry-run short-circuits
  ["gh push --help", "--help short-circuit"],
  ["git push --help", "git push --help"],
  ["git push --dry-run origin main", "git push --dry-run"],
  ["gh pr create --help", "gh pr create --help"],
  ["gh release create --help", "gh release create --help"],
  // documentation / display via skip-list argv[0]
  ["echo 'gh pr create --title example'", "echo with gh literal"],
  ["printf 'run: %s\\n' 'gh release create v1'", "printf with gh literal"],
  ["grep 'gh pr create' ~/.bash_history", "grep with gh literal"],
  ["sed -n 's/gh pr create/REDACTED/p' notes.md", "sed with gh literal"],
  ["awk '/git push/ { print }' log.txt", "awk with git push literal"],
  ["jq -r '.commands[]' < gh-create-examples.json", "jq"],
  ["man gh-pr-create", "man"],
  ["cat README.md", "cat (no gh content)"],
  // wrapper around non-mutating call is still non-mutating
  ["env gh pr list", "env wrapper around non-mutating"],
  ["timeout 60 git status", "timeout wrapper around git status"],
];

// --- Tests -----------------------------------------------------------------

test("positive corpus — every entry classifies as mutating", () => {
  assert.ok(POSITIVE.length >= 35, `corpus too small: ${POSITIVE.length}`);
  for (const [cmd, label] of POSITIVE) {
    const result = classify(cmd);
    assert.equal(result.mutating, true, `expected mutating: ${label} :: ${cmd}`);
    assert.ok(
      typeof result.reason === "string" && result.reason.length > 0,
      `expected non-empty reason: ${label} :: ${cmd}`,
    );
  }
});

test("negative corpus — every entry classifies as not-mutating", () => {
  assert.ok(NEGATIVE.length >= 35, `corpus too small: ${NEGATIVE.length}`);
  for (const [cmd, label] of NEGATIVE) {
    const result = classify(cmd);
    assert.equal(
      result.mutating,
      false,
      `expected NOT mutating: ${label} :: ${cmd} (got reason: ${result.reason ?? "none"})`,
    );
  }
});

test("heredoc bodies are stripped before classification", () => {
  const cmd = "tee notes.md <<EOF\ngh pr merge 42 --squash\ngit push --force\nEOF";
  const result = classify(cmd);
  assert.equal(result.mutating, false, "heredoc body must not classify");
});

test("heredoc same-line suffix is preserved (regression: CRITICAL bypass)", () => {
  // `cat <<EOF; gh pr merge 42` — the `; gh pr merge 42` suffix must survive
  // stripping (it's a separate command in the list). Code-review 2026-05-26.
  const cmd = "cat <<EOF; gh pr merge 42\nbody\nEOF";
  const result = classify(cmd);
  assert.equal(result.mutating, true, "heredoc-suffix bypass must be caught");
});

test("heredoc same-line && suffix is preserved", () => {
  const cmd = "cat <<EOF && git push --force\nbody\nEOF";
  const result = classify(cmd);
  assert.equal(result.mutating, true);
});

test("heredoc with dash-stripped form (<<-EOF) is also stripped", () => {
  const cmd = "cat <<-EOF\n\tgh pr create --title hi\n\tEOF";
  const result = classify(cmd);
  assert.equal(result.mutating, false, "tab-stripped heredoc must not classify");
});

test("heredoc with quoted delimiter is stripped", () => {
  const cmd = "cat <<'END'\ngh release delete v1\nEND";
  const result = classify(cmd);
  assert.equal(result.mutating, false, "quoted-delimiter heredoc must not classify");
});

test("stripHeredocs preserves the line preceding <<EOF", () => {
  const cmd = "tee foo.md <<EOF\nbody\nEOF";
  const stripped = stripHeredocs(cmd);
  assert.match(stripped, /tee foo\.md/);
  assert.doesNotMatch(stripped, /body/);
});

test("splitSegments respects quoting", () => {
  const cmd = `gh issue create --title "foo; bar && baz" --body "x"`;
  const segments = splitSegments(cmd);
  assert.equal(segments.length, 1, "quoted separators must not split");
});

test("splitSegments splits on &&, ||, ;, |, newline", () => {
  const segments = splitSegments("a && b || c ; d | e\nf");
  assert.equal(segments.length, 6);
});

test("tokenize respects single and double quoting", () => {
  const tokens = tokenize(`gh pr create --title 'hello world' --body "x y"`);
  assert.deepEqual(tokens, ["gh", "pr", "create", "--title", "hello world", "--body", "x y"]);
});

test("tokenize handles backslash escape outside quotes", () => {
  const tokens = tokenize(`gh issue edit --body foo\\ bar`);
  assert.deepEqual(tokens, ["gh", "issue", "edit", "--body", "foo bar"]);
});

test("detectBypass only fires when gh/git push is mentioned", () => {
  assert.equal(detectBypass("bash -c 'echo hi'"), false, "no gh mention → no bypass");
  assert.equal(detectBypass("bash -c 'gh pr create'"), true, "gh inside bash -c → bypass");
  assert.equal(detectBypass("eval 'date'"), false, "eval without gh → no bypass");
  assert.equal(detectBypass("eval 'git push'"), true, "eval with git push → bypass");
});

test("detectBypass catches xargs gh and xargs git", () => {
  assert.equal(detectBypass("xargs gh issue close < ids.txt"), true);
  assert.equal(detectBypass("xargs git push"), true);
  assert.equal(detectBypass("xargs grep foo"), false);
});

test("detectBypass catches nested $() where gh follows a nested close (#259)", () => {
  // The old /\$\(([^)]*)\)/g regex stopped at the first ')', missing `gh`
  // sitting after a nested substitution's close.
  assert.equal(detectBypass("$(foo $(bar) gh pr merge 1)"), true);
  assert.equal(detectBypass("echo $(printf '%s' \"$(gh auth token)\")"), true);
  // Unbalanced `$(` mentioning gh still fires (conservative/fail-closed).
  assert.equal(detectBypass("$(gh pr merge 1"), true);
  // Nested substitution with no gh/git mention stays clean.
  assert.equal(detectBypass("$(foo $(bar) baz)"), false);
});

test("extractDollarParenInners performs balanced extraction (#259)", () => {
  assert.deepEqual(extractDollarParenInners("$(a)"), ["a"]);
  assert.deepEqual(extractDollarParenInners("$(a $(b) c)"), ["a $(b) c"]);
  assert.deepEqual(extractDollarParenInners("$(a) x $(b)"), ["a", "b"]);
  assert.deepEqual(extractDollarParenInners("no subs here"), []);
  // Unbalanced → remainder is the inner.
  assert.deepEqual(extractDollarParenInners("$(unterminated"), ["unterminated"]);
});

test("detectBypass catches $(...) and backtick command substitution", () => {
  assert.equal(detectBypass("$(echo gh) pr create"), true);
  assert.equal(detectBypass("`echo git push`"), true);
  assert.equal(detectBypass("$(date)"), false);
});

test("compound command with mutation in any segment classifies as mutating", () => {
  const result = classify("git status && gh pr merge 42 --squash");
  assert.equal(result.mutating, true);
});

test("argv[0] basename respects path prefix", () => {
  // /usr/local/bin/gh ... should still classify
  const result = classify("/usr/local/bin/gh pr create --title hi");
  assert.equal(result.mutating, true);
});

test("multiple leading env-var assignments before gh", () => {
  const result = classify("GH_DEBUG=1 GH_TOKEN=xxx gh pr merge 42");
  assert.equal(result.mutating, true);
});

test("--dry-run anywhere short-circuits", () => {
  assert.equal(classify("gh release create v1 --dry-run").mutating, false);
});

test("-h is NOT a short-circuit (would defuse via quoted args)", () => {
  // Regression for security-review MEDIUM. `-h` is not in SHORT_CIRCUIT_FLAGS;
  // gh/git itself handles it (prints help, no API call).
  assert.equal(
    classify("gh pr create --title 'fix -h bug'").mutating,
    true,
    "-h inside quoted arg must not defuse",
  );
});

// --- ADR-0023: unconditional flag + gitPushes parsing -----------------------

test("gh mutation is unconditional with no gitPushes", () => {
  const r = classify("gh pr create --title x");
  assert.equal(r.unconditional, true);
  assert.equal(r.gitPushes.length, 0);
});

test("bypass-net shape is unconditional with no gitPushes", () => {
  const r = classify("bash -c 'git push origin main'");
  assert.equal(r.unconditional, true);
  assert.equal(r.gitPushes.length, 0);
});

test("git push is host-scoped (not unconditional) and yields one invocation", () => {
  const r = classify("git push origin main");
  assert.equal(r.mutating, true);
  assert.equal(r.unconditional, false);
  assert.equal(r.gitPushes.length, 1);
  assert.equal(r.gitPushes[0].remoteArg, "origin");
  assert.deepEqual(r.gitPushes[0].cDirs, []);
  assert.equal(r.gitPushes[0].inlineConfigRewrite, false);
});

test("bare git push yields a null remoteArg", () => {
  const r = classify("git push");
  assert.equal(r.gitPushes[0].remoteArg, null);
});

test("git -C <dir> push captures the -C dir", () => {
  const r = classify("git -C /tmp/repo push origin main");
  assert.equal(r.gitPushes.length, 1);
  assert.deepEqual(r.gitPushes[0].cDirs, ["/tmp/repo"]);
  assert.equal(r.gitPushes[0].remoteArg, "origin");
});

test("explicit URL arg is captured as remoteArg", () => {
  const r = classify("git push https://github.com/o/r HEAD");
  assert.equal(r.gitPushes[0].remoteArg, "https://github.com/o/r");
});

test("inline -c url.*.insteadOf= sets inlineConfigRewrite (direction-agnostic)", () => {
  const a = classify("git -c url.https://github.com/.insteadOf=https://x/ push origin");
  assert.equal(a.gitPushes[0].inlineConfigRewrite, true);
  const b = classify("git -c url.https://github.com/.pushInsteadOf=https://x/ push");
  assert.equal(b.gitPushes[0].inlineConfigRewrite, true);
});

test("--git-dir / --work-tree set repoDirOverride (space and = forms)", () => {
  assert.equal(
    classify("git --git-dir=/other/.git push origin").gitPushes[0].repoDirOverride,
    true,
  );
  assert.equal(
    classify("git --work-tree /wt push origin main").gitPushes[0].repoDirOverride,
    true,
  );
  assert.equal(
    classify("git push origin main").gitPushes[0].repoDirOverride,
    false,
  );
});

test("push option -o value is not mistaken for the remote positional", () => {
  const r = classify("git push -o ci.skip origin main");
  assert.equal(r.gitPushes[0].remoteArg, "origin");
});

test("--repo= value is captured as the remote", () => {
  const r = classify("git push --repo=origin");
  assert.equal(r.gitPushes[0].remoteArg, "origin");
});

test("compound gh + git push is unconditional (gh wins) but still records pushes", () => {
  const r = classify("git push origin main && gh pr create --title x");
  assert.equal(r.unconditional, true);
  assert.equal(r.gitPushes.length, 1);
});

test("compound of two pushes records both invocations", () => {
  const r = classify("git push origin main && git push backup main");
  assert.equal(r.unconditional, false);
  assert.equal(r.gitPushes.length, 2);
  assert.equal(r.gitPushes[0].remoteArg, "origin");
  assert.equal(r.gitPushes[1].remoteArg, "backup");
});

// --- ADR-0024: per-command inline SKIP_GH_IDENTITY_GUARD=1 (#276) ------------

test("inline skip exempts a git push (not gated, flagged)", () => {
  const r = classify("SKIP_GH_IDENTITY_GUARD=1 git push origin main");
  assert.equal(r.inlineSkip, true);
  assert.equal(r.mutating, false, "exempt push is not gated");
  assert.equal(r.gitPushes.length, 0, "exempt push not collected for host-scoping");
});

test("inline skip exempts a gh mutation", () => {
  const r = classify("SKIP_GH_IDENTITY_GUARD=1 gh pr create --title x");
  assert.equal(r.inlineSkip, true);
  assert.equal(r.mutating, false);
});

test('inline skip honors quoted value SKIP_GH_IDENTITY_GUARD="1"', () => {
  assert.equal(classify('SKIP_GH_IDENTITY_GUARD="1" git push').inlineSkip, true);
  assert.equal(classify("SKIP_GH_IDENTITY_GUARD='1' git push").inlineSkip, true);
});

test("only =1 is a skip; =0/=true/empty are not", () => {
  for (const v of ["0", "true", "", "2"]) {
    const r = classify(`SKIP_GH_IDENTITY_GUARD=${v} git push origin`);
    assert.equal(r.inlineSkip, false, `value ${JSON.stringify(v)} must not skip`);
    assert.equal(r.mutating, true, "non-skip value still gates the push");
  }
});

test("skip is per-segment: SKIP=1 true && git push does NOT exempt the push", () => {
  const r = classify("SKIP_GH_IDENTITY_GUARD=1 true && git push origin main");
  // The skip prefixes `true` (non-mutating); the push segment has no prefix.
  assert.equal(r.inlineSkip, false, "skip on a non-mutating segment is not recorded");
  assert.equal(r.mutating, true);
  assert.equal(r.gitPushes.length, 1, "push is still gated");
});

test("bare assignment SKIP=1; git push does NOT exempt the push (semicolon)", () => {
  // `SKIP=1; git push` is a bare assignment then a separate command — the var
  // never reaches the push's environment, so the guard must still gate it.
  const r = classify("SKIP_GH_IDENTITY_GUARD=1; git push origin main");
  assert.equal(r.inlineSkip, false);
  assert.equal(r.mutating, true);
  assert.equal(r.gitPushes.length, 1, "push is still gated");
});

test("partial compound: SKIP=1 git push origin && git push backup gates the second", () => {
  const r = classify(
    "SKIP_GH_IDENTITY_GUARD=1 git push origin main && git push backup main",
  );
  assert.equal(r.inlineSkip, true, "first push exempted");
  assert.equal(r.mutating, true, "second push still gates");
  assert.equal(r.gitPushes.length, 1);
  assert.equal(r.gitPushes[0].remoteArg, "backup");
});

test("inline skip is IGNORED for bypass-net shapes (always gate)", () => {
  const r = classify("SKIP_GH_IDENTITY_GUARD=1 bash -c 'git push origin main'");
  assert.equal(r.unconditional, true, "bypass-net gates unconditionally");
  assert.equal(r.mutating, true);
  assert.equal(r.inlineSkip, false, "skip not honored for bypass-net");
});

test("skip token inside a quoted arg does not trigger (no smuggling)", () => {
  // SKIP=... appears as a --title value, not a leading assignment.
  const r = classify('gh pr create --title "SKIP_GH_IDENTITY_GUARD=1"');
  assert.equal(r.inlineSkip, false);
  assert.equal(r.mutating, true, "the gh mutation is still gated");
});
