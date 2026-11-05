# Installation

Sentiniel is a single static binary. You do **not** need `gh`, Go, or a GitHub login to scan local
repositories. You only need a token for remote GitHub scanning.

## 1. Prebuilt binaries (recommended)

Download the archive for your platform from
<https://github.com/Olamidipupo-favour/sentiniel/releases/latest>:

| Platform | Architecture | Archive |
| --- | --- | --- |
| Linux | amd64 | `sentiniel_<version>_linux_amd64.tar.gz` |
| Linux | arm64 | `sentiniel_<version>_linux_arm64.tar.gz` |
| macOS | Intel | `sentiniel_<version>_darwin_amd64.tar.gz` |
| macOS | Apple Silicon | `sentiniel_<version>_darwin_arm64.tar.gz` |
| Windows | amd64 | `sentiniel_<version>_windows_amd64.zip` |
| Windows | arm64 | `sentiniel_<version>_windows_arm64.zip` |

Each release also publishes `checksums.txt`. Verify before running:

```sh
sha256sum -c checksums.txt --ignore-missing
```

### Linux and Arch Linux

```sh
tar -xzf sentiniel_*_linux_amd64.tar.gz
sudo install -m 0755 sentiniel /usr/local/bin/sentiniel
sentiniel version
```

Arch users can use the same binary, install with `go install` (below), or package it with their AUR
helper. There is no official AUR package yet.

### macOS

```sh
tar -xzf sentiniel_*_darwin_arm64.tar.gz
sudo install -m 0755 sentiniel /usr/local/bin/sentiniel
xattr -d com.apple.quarantine /usr/local/bin/sentiniel  # only if Gatekeeper blocks it
sentiniel version
```

### Windows

1. Extract the `.zip`.
2. Move `sentiniel.exe` to a folder such as `%LOCALAPPDATA%\Programs\sentiniel`.
3. Add that folder to `Path` in *System Properties → Environment Variables*.
4. Open a new terminal and run `sentiniel version`.

PowerShell users can also install with:

```powershell
go install github.com/Olamidipupo-favour/sentiniel/cmd/sentiniel@latest
```

## 2. Install with Go

Requires Go 1.23 or newer.

```sh
go install github.com/Olamidipupo-favour/sentiniel/cmd/sentiniel@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

## 3. Build from source

```sh
git clone https://github.com/Olamidipupo-favour/sentiniel.git
cd sentiniel
make build
./sentiniel version
```

Or build directly:

```sh
go build -trimpath -ldflags="-s -w" -o sentiniel ./cmd/sentiniel
```

Cross-compile without extra tooling:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o sentiniel.exe ./cmd/sentiniel
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -o sentiniel-macos ./cmd/sentiniel
```

## 4. Docker

The image includes an inert infected fixture so you can try detection safely in a container.

```sh
docker build -t sentiniel .
docker run --rm sentiniel scan --path /fixtures/infected --format json
```

The container runs as an unprivileged user. Mount a local repository read-only for a local scan:

```sh
docker run --rm -v "$PWD:/repo:ro" sentiniel scan --path /repo --format json
```

## 5. Sign in for remote scans (no gh required)

Remote GitHub scanning needs a token. Choose one of these methods:

### Option A: interactive login (recommended)

```sh
sentiniel login
```

Paste a GitHub personal access token when prompted. It is validated, then stored with `0600`
permissions in your user config directory:

- Linux: `~/.config/sentiniel/token`
- macOS: `~/Library/Application Support/sentiniel/token`
- Windows: `%AppData%\sentiniel\token`

Remove it with `sentiniel logout`.

### Option B: environment variable

```sh
export GITHUB_TOKEN=ghp_...   # or GH_TOKEN
```

### Option C: per-command flag

```sh
sentiniel scan --repo OWNER/REPO --token ghp_...
```

### Option D: existing gh session (optional)

If `gh` is already installed and authenticated, Sentiniel reuses its token as a fallback. This is a
convenience, not a requirement.

### Token scopes

Create a fine-grained or classic token with:

- `repo` — required for private repositories.
- `read:org` — required to list organizations and their repositories.
- `public_repo` is enough for public repositories only.

The token is sent only to `api.github.com`. Remote scans are read-only.

## 6. First run

```sh
# Local repository, read-only
sentiniel scan --path /path/to/repo --format text

# Interactive account/org/repository picker
sentiniel scan --interactive

# Pick repositories, download them, then fix the local copies
sentiniel run --interactive --clone ./clones --apply --confirm

# One remote repository
sentiniel scan --repo OWNER/REPO --format json --output findings.json

# All repositories for an account or organization
sentiniel scan --owner OWNER --format json --output findings.json
```

## 7. Upgrade and uninstall

- Binaries: download the newer release and replace the old file.
- Go install: rerun `go install ...@latest`.
- Docker: rebuild the image.
- Uninstall: delete the binary and `sentiniel logout` to remove the stored token.

## Troubleshooting

- **`no GitHub token`** — run `sentiniel login`, or set `GITHUB_TOKEN`.
- **`GitHub API 401`** — the token is invalid or expired; run `sentiniel login` again.
- **`GitHub API 403`** — missing scope, rate limit, or no access to the repository.
- **Some repositories are skipped** — Sentiniel prints a warning per repository and continues. A
  skipped repository is not reported as clean.
- **Windows Defender warning** — the release binaries are unsigned. Verify the checksum and, if
  needed, allow the specific file.
