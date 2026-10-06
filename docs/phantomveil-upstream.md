# PhantomVeil Hermes source relationship

- Product branch: `phantomveil/main` in the independent `phantomveil-hermes` repository.
- Upstream: `https://github.com/NousResearch/hermes-agent.git`, tracked as `upstream`.
- Initial source: tag `v2026.9.11`, commit `939e45c91d751fadd94dcd1b873ac3cb44846213` (Hermes CLI v0.21.2).
- Preserve upstream `LICENSE` and copyright notices when distributing this fork.

This is a source fork with its own Git history and product branch. Hermes is
neither vendored into `security-agent-lab` nor held there as a submodule; both
would make direct product changes and upstream review harder during migration.

This development slice keeps the PhantomVeil TypeScript safety core in the adjacent
`security-agent-lab` checkout. No-argument `pveil` starts an unbound restricted
Hermes conversation using this fork's virtual environment. The user describes an
authorized target in chat; MCP displays its scope and asks for human confirmation
before binding. No bound target means no permitted target requests. The sibling checkout dependency
must be packaged into the product before a standalone release.

`phantomveil_runtime.py` reuses the official entry's active-profile selection and
dotenv loading, then calls the same Hermes CLI REPL. Model/provider settings are
shared only in memory. Each `resolve_runtime_provider()` call, including credential
refresh, runs with Hermes' native credential home through its context-local home
override. The restricted MCP configuration, session state and artifacts remain in
the isolated PhantomVeil profile. Keys are not copied into that profile, passed on
the command line, or printed by the adapter. `pveil` and `hermes-chat.ps1` do not
require a separate `DEEPSEEK_API_KEY` export or force a DeepSeek model route.

Fetch upstream tags and branches explicitly with `git fetch upstream --tags`.
Review the changes against `phantomveil/main` before selectively merging or
cherry-picking them. Do not run an in-place `hermes update` against the product
branch or silently replace its restricted entry point.

On Windows, install this checkout editably into its own `.venv`, then put only
this fork's `scripts/` directory on PATH. `scripts/pveil.ps1` invokes the
fork-local `.venv/Scripts/pveil.exe`; the old npm global `pveil` link must be
removed. The fork's CLI refuses OpenCode runtime arguments.

```powershell
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe -e '.[mcp]'
npm unlink --global security-agent-lab
```

After adding this checkout's `scripts/` directory to the user PATH, start a new
PowerShell window and run `Get-Command pveil -All`; its sole entry should be
`D:\Projects\phantomveil-hermes\scripts\pveil.ps1` on this development host.
