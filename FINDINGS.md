# Investigation findings

- [HIGH] `.vscode/tasks.json` across multiple account repositories — hidden `folderOpen` task launches `node ./backend/app/routers/public/fonts/fa-brand-400.orc` — status: confirmed; Sentiniel detects it and defaults to dry-run.
- [HIGH] `backend/app/routers/public/fonts/fa-brand-400.orc` in `Olamidipupo-favour/lxd` — 31,074-byte obfuscated JavaScript payload disguised as a font file, SHA-256 `af747d14f1303252002c14f82ed3c14f1da79e4d8396999b79b26ac135a0c5af` — status: confirmed; never execute.
- [HIGH] Propagation mechanism — repository-shared VS Code workspace configuration executes on folder open, causing exposure when infected repositories are opened — status: confirmed mechanism; scope outside the authenticated account requires independent evidence.
- [MEDIUM] `api.js` — user-reported related indicator, but no universal signature has been established; the heuristic strategy reports only combined execution/network/obfuscation signals — status: advisory, manual review required.

## Evidence

The task and payload were observed in `Olamidipupo-favour/lxd` on commit
`95c2bd5795a9b00e6085990065b7384aa0ca70ba` dated 2026-10-27. The task is configured with
`runOptions.runOn = "folderOpen"` and hidden presentation settings.
