# Architecture

Sentiniel separates four concerns:

1. **Authentication** resolves a GitHub token from `--token`, `GITHUB_TOKEN`, `GH_TOKEN`, a stored
   login (`sentiniel login`), or an existing `gh` session. Local scanning needs none of these.
2. **Targets** acquire file candidates without executing them. `LocalTarget` walks a local
   repository with explicit excludes; `GitHubTarget` reads the default branch through the GitHub
   Contents/tree APIs.
3. **Strategies** inspect immutable `sentiniel.File` values. Each strategy returns evidence,
   severity, and a suggested action. The registry contains `ioc` (known payload names, hashes, and
   renamed font files), `workspace` (VS Code tasks and settings that run code on folder open), and
   `heuristic` (advisory `api.js` review). Detection patterns live only in strategy files; the
   scanner and targets do not name payloads, paths, or file formats. A strategy may implement
   `Candidate` so targets download only the files it can inspect, and `Fixer` so apply mode can
   repair what it finds. A strategy without `Fixer` is advisory.
4. **Remediation** is target-specific and explicit. Targets quarantine the original, ask the
   finding's strategy for the replacement bytes (or a delete), and write nothing when the strategy
   returns the input unchanged. Both local and remote remediation skip advisory findings and run
   only after confirmation. Remote writes need `--force-remote` and become commits on the
   default branch; without it, GitHub access stays read-only.

The CLI keeps these phases separate:

- `login` validates a token and stores it without requiring `gh`.
- `scan` discovers and optionally writes a JSON plan. `--interactive` chooses an owner and
  repositories from the token's visible accounts and organizations.
- `action` consumes a reviewed plan and performs local changes only when explicitly confirmed.
- `run` chains both phases for controlled automation.

Remote bulk scans use bounded concurrency. A repository that returns an authorization or
availability error is reported as skipped and is never counted as clean.

To add a strategy, implement `Strategy` in its own file, add it to `allStrategies`, and add
unit/fuzz tests. Implement `Candidate` unless the strategy really needs every file, and `Fixer`
only if its findings can be repaired safely. To add a target, expose a
`Files(func(string) bool) ([]File, error)` implementation and keep its acquisition boundary free of
code execution and free of payload names. A future target may create reviewed pull requests, but
should not mutate a remote repository directly.
