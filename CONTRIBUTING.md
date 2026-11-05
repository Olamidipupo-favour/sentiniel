# Contributing to Sentiniel

Sentiniel is a defensive scanner. Contributions must keep scanning read-only by default and must
never execute suspicious repository content. Remediation must be explicit, auditable, and preserve
evidence before changing files.

## Licence and attribution

Sentiniel is source-available under the [Sentiniel Source-Available License](LICENSE). By submitting
a contribution you agree that it is licensed to the copyright holder under the same terms, including
the right to relicense it commercially. Do not contribute code you cannot license this way.

## Development

Requires Go 1.23 or newer.

```sh
gofmt -w .
go test ./...
go vet ./...
go run ./cmd/sentiniel scan --path /path/to/repository --format json
```

Run a single test:

```sh
go test -run TestIOCDetectsFolderOpenPayloadTask ./...
```

Fuzz the GitHub content decoder:

```sh
go test -fuzz=FuzzDecodeGitHubContent -fuzztime=10s
```

## Branches

- `main` is always releasable.
- `develop` is the integration branch for larger changes.
- Use short-lived branches such as `fix/token-login` or `feature/strategy-name` for pull requests.

Open pull requests against `main` unless a maintainer asks for `develop`.

## Architecture rules

Add a strategy by implementing `sentiniel.Strategy`, registering it in `NewScanner`, and adding
focused tests. Strategies should report evidence and confidence, not silently delete files.

The public architecture is deliberately split into:

- **Strategies**: pure inspection of immutable file bytes.
- **Targets**: acquisition of local or remote repository files.
- **Actions**: explicit, auditable changes after a reviewed findings plan.

Do not couple a strategy to a target or perform writes during scanning. Add fuzz tests for parsers
and malformed remote content. Keep fixtures inert and never commit real payloads.

## Pull requests

Explain the threat model, evidence source, false-positive considerations, and dry-run behaviour.
Do not include live credentials, payload execution traces, or unnecessary copies of malicious code.
