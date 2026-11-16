# Investigation findings

- [HIGH] `.vscode/tasks.json` across multiple account repositories — hidden `folderOpen` task launches `node ./backend/app/routers/public/fonts/fa-brand-400.orc` — status: confirmed; Sentiniel detects it and defaults to dry-run.
- [HIGH] `backend/app/routers/public/fonts/fa-brand-400.orc` in `Olamidipupo-favour/lxd` — 31,074-byte obfuscated JavaScript payload disguised as a font file, SHA-256 `af747d14f1303252002c14f82ed3c14f1da79e4d8396999b79b26ac135a0c5af` — status: confirmed; never execute.
- [HIGH] Propagation mechanism — repository-shared VS Code workspace configuration executes on folder open, causing exposure when infected repositories are opened — status: confirmed mechanism; scope outside the authenticated account requires independent evidence.
- [MEDIUM] `api.js` — user-reported related indicator, but no universal signature has been established; the heuristic strategy reports only combined execution/network/obfuscation signals — status: advisory, manual review required.

## Evidence

The task and payload were observed in `Olamidipupo-favour/lxd` on commit
`95c2bd5795a9b00e6085990065b7384aa0ca70ba` dated 2026-10-27. The task is configured with
`runOptions.runOn = "folderOpen"` and hidden presentation settings.

### Worm commit in `Olamidipupo-favour/sentiniel`

The worm did not only touch other repositories. It rewrote a commit in Sentiniel's own
remote history and force-pushed it over the real one.

- Real commit: `83f2b57` "Add a verified self-update command", parent `5053d1d`,
  tagged `v0.5.0`.
- Malicious commit: `4cf75e3`, same message, same parent, same author and committer
  (`Agboola Olamidipupo <dipoagboola2019@gmail.com>`), same date
  (`2026-11-05T12:02:32+01:00`). It was force-pushed to `main`.
- A second copy was pushed to `develop` as `05a4929`. It has the same tree as
  `4cf75e3` (`711ded8a587312bbd202c4cab9ab0ad4150a2c0d`).
- The code files are byte-identical to `83f2b57`. The worm only appended malicious
  files to the tree, which is why the diff looks innocent:

```
.gitignore
.vscode/settings.json
.vscode/tasks.json
fixtures/infected/backend/app/routers/public/fonts/README.md
fixtures/infected/backend/app/routers/public/fonts/fa-*.{eot,svg,ttf,woff,woff2}
```

- `.vscode/tasks.json` is the same hidden `folderOpen` task. The payload path is in
  `args`, not `command`, so a scanner that only inspects `command` misses it:

```json
{"label": "eslint-check", "type": "shell", "command": "node",
 "args": ["./fixtures/infected/backend/app/routers/public/fonts/fa-solid-600.ttf"],
 "hide": true, "runOptions": {"runOn": "folderOpen"}}
```

- `.vscode/settings.json` adds `"task.allowAutomaticTasks": true`, which suppresses the
  VS Code prompt that would otherwise block automatic tasks.
- Payload `fixtures/infected/backend/app/routers/public/fonts/fa-solid-600.ttf` is
  30,584 bytes of obfuscated JavaScript, SHA-256
  `e20dc2838008cbcc0205d5a992cb3eb11a705d90fcd95582618c91c224b72549`. It is a
  different payload from the `lxd` one (`af747d14...`) and a different extension.
- `.gitignore` is re-written in CRLF and gains `config.bat` and `node_modules`, a
  plausible place for a Windows-facing payload to hide. `.gitignore` only hides untracked
  files, so check local clones for an untracked `config.bat` or a `node_modules` directory
  that no `package.json` explains.

### Renamed payload variant

The account-wide rescan on 2026-11-16 found the same campaign using another extension.
`public/fonts/fa-solid-400.woff2` in `Olamidipupo-favour/AlgoScience` and
`Olamidipupo-favour/argon` is 37,717 bytes of obfuscated JavaScript that begins with
`global['!']=` instead of the `wOF2` font header, SHA-256
`f5638369cf9e169f89429685cb16e41c7081f2319ead0497b4e7cf7b1e34f771`. The accompanying
`.vscode/settings.json` sets `"task.allowAutomaticTasks": true` and contains a `tasks` block
with `runOn: folderOpen`. The payload is caught by the font-header check even if its name and
hash are new, and this hash is now a known indicator.

Evidence preserved outside the repository at
`/tmp/opencode/sentiniel-worm-evidence/` (payload, both workspace files, commit
metadata, and a git bundle of both malicious commits). The commits are also kept under
the local refs `refs/evidence/worm-main`, `refs/evidence/worm-develop`, and the tag
`worm-evidence-2026-11-05`; none of them may be pushed.

The real history was restored by force-pushing `83f2b57` back to `main` and
`develop`. Any clone made between the worm push and the restore must be treated as
infected, and the GitHub token that had push access must be rotated.

## Status

- `main` and `develop` point at the fixed history. Malicious commits `4cf75e3` and
  `05a4929` are kept only in local evidence refs and a bundle, never pushed.
- `v0.5.1` closes the detection gaps found here: task `args`, hidden folder-open tasks,
  unparseable task files, `task.allowAutomaticTasks`, renamed font payloads, quarantine
  copies, remote `--exclude`, and per-finding apply progress.
- `v0.5.2` adds `--all-branches`, because the worm pushed a second copy to `develop`.
- `v0.5.3` moves detection and repair out of the scanner core into strategies (`ioc`, `workspace`,
  `heuristic`), so adding a new indicator does not touch the scanner or the targets.
- Credential rotation is still the user's action. The worm had push access, so every
  token, SSH key, and CLI session available on the workstation must be considered
  exposed.
