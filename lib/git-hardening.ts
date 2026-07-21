/**
 * gh-identity-guard/lib/git-hardening.ts — the single source of truth for the
 * flags prepended to EVERY git subprocess this extension spawns.
 *
 * They neutralise local-config code execution in a possibly-hostile working
 * directory: `git remote get-url`, `git rev-parse`, and `git ls-files` can
 * trigger `core.fsmonitor` / hook execution, so pinning both to inert values
 * closes that vector. Extracted here (#801) so a future hardening change has
 * one place to edit instead of three identical copies in identity.ts,
 * remote.ts, and bootstrap.ts. Source: security-review #265.
 */
export const GIT_HARDENING: readonly string[] = [
  "-c",
  "core.fsmonitor=",
  "-c",
  "core.hooksPath=/dev/null",
];
