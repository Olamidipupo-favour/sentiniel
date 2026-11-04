# Sentiniel

Sentiniel is a cross-platform, defensive repository threat scanner for macOS, Windows, Linux,
and Arch Linux. It is dry-run-first, never executes suspicious repository content, and is designed
around pluggable detection strategies and target providers.

Created by **Olamidipupo Favour**. Profile: [github.com/Olamidipupo-favour](https://github.com/Olamidipupo-favour).
Contributions and responsible disclosure are welcome.

## What it detects

The initial IOC covers a confirmed propagation pattern: a hidden VS Code `folderOpen` task launches
obfuscated JavaScript stored under the misleading `.orc` font filename
`backend/app/routers/public/fonts/fa-brand-400.orc`. The known payload SHA-256 is:

```text
af747d14f1303252002c14f82ed3c14f1da79e4d8396999b79b26ac135a0c5af
```

The heuristic strategy reports large `api.js` files combining execution/network indicators with
possible obfuscation. It is advisory, not proof of compromise.

## Install and use

```sh
go build -o sentiniel ./cmd/sentiniel
./sentiniel scan --path /path/to/repository
./sentiniel scan --path /path/to/parent-of-repositories --recursive --json
./sentiniel scan --repo OWNER/REPO
./sentiniel scan --owner OWNER
./sentiniel scan --repo OWNER/REPO --strategies ioc,heuristic
./sentiniel scan --repo OWNER/REPO --format json --output findings.json
./sentiniel action --path /path/to/repository --findings findings.json --mode dry-run
./sentiniel action --path /path/to/repository --findings findings.json --mode apply --confirm
./sentiniel run --path /path/to/repository --apply --confirm
```

GitHub scanning uses `GITHUB_TOKEN`, `GH_TOKEN`, or an authenticated `gh` CLI session. Remote
scanning is read-only. Local scanning is also read-only unless both `--apply` and `--confirm` are
provided:

```sh
./sentiniel scan --path /path/to/repository --apply --confirm
```

`scan` is always read-only. `action` consumes a reviewed findings plan and defaults to dry-run;
`--mode apply --confirm` is required to change local files. `run` chains scan and action but still
requires `--apply --confirm`. Apply mode preserves originals in `.sentiniel-quarantine`, removes
the known folder-open task, and does not automatically apply heuristic findings.

## Extensibility

Implement `sentiniel.Strategy` and register it in `NewScanner` to add a detector. Target providers
implement the same `Files()` boundary, so local and remote scans share strategy logic. Fuzzing
belongs in Go fuzz tests for parsers and strategies; suspicious content must never be executed.

## Automation

- `.github/workflows/sentiniel.yml` scans on push, pull request, schedule, and manual dispatch.
- `.github/workflows/release.yml` builds Linux, macOS ARM64, and Windows binaries on version tags.
- `sentiniel scan --owner OWNER` scans all repositories visible to the authenticated account for
  that owner.
- `sentiniel schedule` prints external scheduler guidance.
- `sentiniel webhook --repo OWNER/REPO` exposes a read-only `POST /scan` endpoint and `GET /healthz`.

Current workflows are:

- **Sentiniel CI**: tests, vets, and scans on push, pull request, schedule, and manual dispatch.
- **CodeQL**: scheduled and change-triggered Go security analysis.
- **Release**: GoReleaser publishes Linux, macOS, and Windows archives for `v*` tags.

The webhook should be placed behind authentication, TLS, rate limiting, and network controls before
production use. It does not modify repositories.

## Incident response

If the payload may have executed, isolate the workstation, rotate tokens and credentials available
to developer tooling, inspect shell/VS Code startup locations, review GitHub audit logs and commit
history, and do not execute the payload for analysis.
