# Architecture

Sentiniel separates four concerns:

1. **Authentication** resolves a GitHub token from `--token`, `GITHUB_TOKEN`, `GH_TOKEN`, a stored
   login (`sentiniel login`), or an existing `gh` session. Local scanning needs none of these.
2. **Targets** acquire file candidates without executing them. `LocalTarget` walks a local
   repository with explicit excludes; `GitHubTarget` reads the default branch through the GitHub
   Contents/tree APIs.
3. **Strategies** inspect immutable `sentiniel.File` values. Each strategy returns evidence,
   severity, and a suggested action. The current registry contains `ioc` and `heuristic`.
4. **Remediation** is target-specific and explicit. Both local and remote remediation preserve
   originals in `.sentiniel-quarantine`, skip advisory findings, and run only after confirmation.
   Remote writes need `--force-remote` and become commits on the default branch; without it,
   GitHub access stays read-only.

The CLI keeps these phases separate:

- `login` validates a token and stores it without requiring `gh`.
- `scan` discovers and optionally writes a JSON plan. `--interactive` chooses an owner and
  repositories from the token's visible accounts and organizations.
- `action` consumes a reviewed plan and performs local changes only when explicitly confirmed.
- `run` chains both phases for controlled automation.

Remote bulk scans use bounded concurrency. A repository that returns an authorization or
availability error is reported as skipped and is never counted as clean.

To add a strategy, implement `Strategy`, register it in `NewScanner`, and add unit/fuzz tests. To
add a target, expose a `Files() ([]File, error)` implementation and keep its acquisition boundary
free of code execution. A future target may create reviewed pull requests, but should not mutate a
remote repository directly.
