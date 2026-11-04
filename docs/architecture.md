# Architecture

Sentiniel separates three concerns:

1. **Targets** acquire file candidates without executing them. `LocalTarget` walks a local
   repository; `GitHubTarget` reads the default branch through the GitHub Contents/tree APIs.
2. **Strategies** inspect immutable `sentiniel.File` values. Each strategy returns evidence,
   severity, and a suggested action. The current registry contains `ioc` and `heuristic`.
3. **Remediation** is target-specific and explicit. Local remediation is opt-in and preserves
   originals in `.sentiniel-quarantine`; GitHub scanning is read-only in this release.

The CLI keeps these phases separate:

- `scan` discovers and optionally writes a JSON plan.
- `action` consumes a reviewed plan and performs local changes only when explicitly confirmed.
- `run` chains both phases for controlled automation.

To add a strategy, implement `Strategy`, register it in `NewScanner`, and add unit/fuzz tests. To
add a target, expose a `Files() ([]File, error)` implementation and keep its acquisition boundary
free of code execution. A future target may create reviewed pull requests, but should not mutate a
remote repository directly.
