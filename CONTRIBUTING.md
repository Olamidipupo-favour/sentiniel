# Contributing to Sentiniel

Sentiniel is a defensive scanner. Contributions must keep scanning read-only by default and must
never execute suspicious repository content. Remediation must be explicit, auditable, and preserve
evidence before changing files.

## Development

```sh
gofmt -w .
go test ./...
go vet ./...
go run ./cmd/sentiniel scan --path /path/to/repository --json
```

Add a strategy by implementing `sentiniel.Strategy`, registering it in `NewScanner`, and adding
focused tests. Strategies should report evidence and confidence, not silently delete files.

The public architecture is deliberately split into:

- **Strategies**: pure inspection of immutable file bytes.
- **Targets**: acquisition of local or remote repository files.
- **Actions**: explicit, auditable changes after a reviewed findings plan.

Do not couple a strategy to a target or perform writes during scanning. Add fuzz tests for parsers
and malformed remote content. Keep fixtures inert and never commit real payloads.

## Pull requests

Explain the threat model, evidence source, false-positive considerations, and dry-run behavior.
Do not include live credentials, payload execution traces, or unnecessary copies of malicious code.
