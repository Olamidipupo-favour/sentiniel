# Operations

## Authentication

Remote scans need a GitHub token. Local scans do not. Sign in without `gh`:

```sh
sentiniel login
```

Or use `GITHUB_TOKEN` / `GH_TOKEN`, `--token`, or an existing authenticated `gh` session as a
fallback. Tokens need `repo` for private repositories and `read:org` for organizations. Remove a
stored token with `sentiniel logout`.

## Safe workflow

1. Run a JSON dry run and save the output:

   ```sh
   sentiniel scan --owner Olamidipupo-favour --format json > findings.json
   ```

   For an organization, replace the owner with the organization login. The authenticated token
   must be authorized to list and read those repositories. Use `--interactive` to pick an owner and
   repositories instead of typing them:

   ```sh
   sentiniel scan --interactive --format json --output findings.json
   ```

   Remote repositories are read-only, so remediation needs a local copy. Add `--clone DIR` to
   download the selected repositories, scan them, and then apply changes to those copies:

   ```sh
   sentiniel run --interactive --clone ~/sentiniel-clones --apply --confirm
   ```

   Repositories that GitHub rejects or times out on are printed as warnings and skipped. They are
   not reported as clean.

2. Isolate any workstation where a payload may have executed. Do not open infected repositories
   in an editor with automatic tasks enabled.
3. Rotate credentials available to the workstation and review GitHub audit logs, repository events,
   commit history, editor settings, shell profiles, and CI secrets.
4. For local copies, review the plan before applying:

   ```sh
   sentiniel scan --path /repos/project --format json --output findings.json
   sentiniel action --path /repos/project --findings findings.json --mode apply --confirm
   ```

5. Commit cleanup through a reviewed branch or pull request. Never rewrite history until evidence
   is preserved and the organization approves it.

## Scheduling and webhooks

The included GitHub Actions workflow covers push, pull request, daily schedule, and manual runs.
For local scheduling, use cron, launchd, Task Scheduler, or systemd to invoke the read-only scan.
The webhook server is intentionally read-only:

```sh
sentiniel webhook --repo OWNER/REPO --listen 127.0.0.1:8080
curl -X POST http://127.0.0.1:8080/scan
```

Place it behind authentication, TLS, rate limiting, and a restricted network before exposing it
outside localhost.
