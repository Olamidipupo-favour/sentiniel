# Sentiniel

Sentiniel is a cross-platform, defensive repository threat scanner for macOS, Windows, Linux, and
Arch Linux. It is dry-run-first, never executes suspicious repository content, and is designed
around pluggable detection strategies and target providers.

Created by **Olamidipupo Favour**. Profile: [github.com/Olamidipupo-favour](https://github.com/Olamidipupo-favour).
Sentiniel is source-available; commercial use requires a paid licence. See [License](#license).

## What it detects

The initial IOC covers a confirmed propagation pattern: a hidden VS Code `folderOpen` task launches
obfuscated JavaScript stored under the misleading `.orc` font filename
`backend/app/routers/public/fonts/fa-brand-400.orc`. The known payload SHA-256 is:

```text
af747d14f1303252002c14f82ed3c14f1da79e4d8396999b79b26ac135a0c5af
```

The heuristic strategy reports large `api.js` files combining execution/network indicators with
possible obfuscation. It is advisory, not proof of compromise.

## Install

Full instructions for every platform are in [INSTALLATION.md](INSTALLATION.md).

```sh
# Prebuilt binary from the latest release, or:
go install github.com/Olamidipupo-favour/sentiniel/cmd/sentiniel@latest
```

## Sign in (no gh required)

Remote scanning uses a GitHub token. `gh` is optional; Sentiniel no longer depends on it.

```sh
sentiniel login              # prompted, validated, stored with 0600 permissions
sentiniel logout             # remove the stored token
export GITHUB_TOKEN=ghp_...  # or use an environment variable
sentiniel scan --repo OWNER/REPO --token ghp_...  # or pass it per command
```

Create a token with `repo` (private repositories) and `read:org` (organizations). Remote scans are
read-only. If `gh` is already authenticated, its token is used as a fallback.

## Use

```sh
sentiniel scan --path /path/to/repository
sentiniel scan --path /path/to/parent-of-repositories --recursive
sentiniel scan --path . --exclude fixtures/infected --format json
sentiniel scan --interactive
sentiniel run --interactive --clone ./clones --apply --confirm
sentiniel scan --repo OWNER/REPO
sentiniel scan --owner OWNER
sentiniel scan --repo OWNER/REPO --strategies ioc,heuristic
sentiniel scan --repo OWNER/REPO --format json --output findings.json
sentiniel action --path /path/to/repository --findings findings.json --mode dry-run
sentiniel action --path /path/to/repository --findings findings.json --mode apply --confirm
sentiniel run --path /path/to/repository --apply --confirm
```

`--interactive` lists the account and organizations visible to the authenticated token, then lets
you pick one owner and any number of repositories. Remote scans are read-only, so add
`--clone DIR` to download the selected repositories and scan those copies; `run --clone DIR
--apply --confirm` then fixes the local copies and leaves the originals in
`.sentiniel-quarantine` for review.

### Safety model

`scan` is always read-only and rejects `--apply` or `--confirm`. `action` consumes a reviewed
findings plan and defaults to dry-run; `--mode apply --confirm` is required to change local files.
`run` chains scan and action but still requires `--apply --confirm`. Apply mode preserves originals
in `.sentiniel-quarantine`, removes the known folder-open task, and does not automatically apply
heuristic findings.

Use `--exclude` only for intentional fixtures or approved generated content; exclusions are not
evidence of cleanliness.

## Extensibility

Implement `sentiniel.Strategy` and register it in `NewScanner` to add a detector. Target providers
implement the same `Files()` boundary, so local and remote scans share strategy logic. Fuzzing
belongs in Go fuzz tests for parsers and strategies; suspicious content must never be executed.

## Automation

- `.github/workflows/sentiniel.yml` scans on push, pull request, schedule, and manual dispatch.
- `.github/workflows/release.yml` builds Linux, macOS, and Windows binaries on version tags.
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

## License

Sentiniel is **source-available, not open source**. Personal and non-commercial use is free.
Any commercial or enterprise use requires a paid licence and attribution to
**Sentiniel by Olamidipupo Favour**. See [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the project licence.

## Incident response

If the payload may have executed, isolate the workstation, rotate tokens and credentials available
to developer tooling, inspect shell/VS Code startup locations, review GitHub audit logs and commit
history, and do not execute the payload for analysis.
