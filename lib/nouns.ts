/**
 * gh-identity-guard — noun/verb table for mutating `gh` invocations.
 *
 * Source: ADR-0022 § Q2.A. Verbs are noun-scoped because semantics vary
 * (`gh project copy` mutates; `gh release download` does not).
 *
 * Match rule: argv[0] basename is `gh` AND argv[1] is a known noun AND
 * argv[2] is a mutating verb listed for that noun.
 */

export const MUTATING_VERBS: Readonly<Record<string, ReadonlySet<string>>> = {
  issue: new Set([
    "create",
    "edit",
    "close",
    "reopen",
    "delete",
    "comment",
    "lock",
    "unlock",
    "pin",
    "unpin",
    "transfer",
    "develop",
  ]),
  pr: new Set([
    "create",
    "edit",
    "close",
    "reopen",
    "merge",
    "ready",
    "comment",
    "lock",
    "unlock",
    "review",
    "update-branch",
  ]),
  release: new Set(["create", "edit", "delete", "upload", "delete-asset"]),
  repo: new Set([
    "create",
    "delete",
    "edit",
    "rename",
    "archive",
    "unarchive",
    "fork",
    "sync",
    "set-default",
    "deploy-key",
  ]),
  project: new Set([
    "create",
    "delete",
    "edit",
    "close",
    "copy",
    "link",
    "unlink",
    "field-create",
    "field-delete",
    "item-add",
    "item-create",
    "item-edit",
    "item-delete",
    "item-archive",
  ]),
  label: new Set(["create", "edit", "delete", "clone"]),
  secret: new Set(["set", "delete"]),
  variable: new Set(["set", "delete"]),
  workflow: new Set(["enable", "disable", "run"]),
  ruleset: new Set(["create", "edit", "delete"]),
  gist: new Set(["create", "edit", "delete", "rename"]),
  auth: new Set(["login", "logout", "refresh", "switch", "setup-git"]),
  alias: new Set(["set", "delete", "import"]),
  cache: new Set(["delete"]),
  run: new Set(["cancel", "delete", "rerun"]),
};

/** argv[0] basenames that NEVER count as mutating regardless of content. */
export const ARGV0_SKIP_LIST: ReadonlySet<string> = new Set([
  "echo",
  "printf",
  "cat",
  "less",
  "more",
  "head",
  "tail",
  "grep",
  "rg",
  "ag",
  "sed",
  "awk",
  "jq",
  "yq",
  "tr",
  "wc",
  "sort",
  "uniq",
  "diff",
  "man",
]);

/** Flags that short-circuit "not mutating" regardless of other content. */
export const SHORT_CIRCUIT_FLAGS: ReadonlySet<string> = new Set([
  "--help",
  "--dry-run",
]);

/**
 * Wrapper binaries commonly prefixed before `gh`/`git`. When seen as argv[0]
 * we strip them (along with any wrapper-specific options) and re-classify
 * against the residual argv. Source: security-review 2026-05-26 (HIGH).
 */
export const WRAPPER_BINARIES: ReadonlySet<string> = new Set([
  "env",
  "nohup",
  "nice",
  "ionice",
  "taskset",
  "stdbuf",
  "command",
  "sudo",
  "doas",
  "timeout",
  "time",
  "chronic",
  "ts",
  "unbuffer",
  "script",
]);

/**
 * `git` global flags that take an argument (must be skipped in pairs when
 * looking past them for a mutating subcommand like `push`). Source:
 * security-review 2026-05-26 (HIGH `git -C path push` bypass).
 */
export const GIT_GLOBAL_FLAGS_WITH_ARG: ReadonlySet<string> = new Set([
  "-C",
  "-c",
  "--exec-path",
  "--git-dir",
  "--work-tree",
  "--namespace",
  "--super-prefix",
  "--list-cmds",
  "--config-env",
  "--attr-source",
]);

/** `git` global flags that are bare (no argument). */
export const GIT_GLOBAL_FLAGS_BARE: ReadonlySet<string> = new Set([
  "-p",
  "-P",
  "--paginate",
  "--no-pager",
  "--no-replace-objects",
  "--no-optional-locks",
  "--bare",
  "--literal-pathspecs",
  "--glob-pathspecs",
  "--noglob-pathspecs",
  "--icase-pathspecs",
]);

/** HTTP methods on `gh api -X|--method` that are mutating. */
export const GH_API_MUTATING_METHODS: ReadonlySet<string> = new Set([
  "POST",
  "PATCH",
  "PUT",
  "DELETE",
]);

/**
 * HTTP methods on `gh api -X|--method` that are read-only. An explicit
 * non-mutating method overrides the implicit-POST flags (`-f`/`-F`/…): real
 * `gh` sends `-X GET -f q=x` as a GET with query params, not a POST.
 * ADR-0022 § Q2.F. Only a recognized read method overrides; an unrecognized
 * or malformed `-X` value falls through to implicit-POST detection (fail
 * closed). #259 item 6.
 */
export const GH_API_NONMUTATING_METHODS: ReadonlySet<string> = new Set([
  "GET",
  "HEAD",
]);

/**
 * `gh api` flags that implicitly switch the method to POST when no `-X`
 * is given. ADR-0022 § Q2.B.
 */
export const GH_API_IMPLICIT_POST_FLAGS: ReadonlySet<string> = new Set([
  "-f",
  "--field",
  "-F",
  "--raw-field",
  "--input",
]);
