# PhantomVeil Hermes source relationship

- Product branch: `phantomveil/main` in the independent `phantomveil-hermes` repository.
- Upstream: `https://github.com/NousResearch/hermes-agent.git`, tracked as `upstream`.
- Initial source: tag `v2026.9.11`, commit `939e45c91d751fadd94dcd1b873ac3cb44846213` (Hermes CLI v0.21.2).
- Preserve upstream `LICENSE` and copyright notices when distributing this fork.

This is a source fork with its own Git history and product branch. Hermes is
neither vendored into `security-agent-lab` nor held there as a submodule; both
would make direct product changes and upstream review harder during migration.

The PhantomVeil TypeScript safety core is vendored into this fork as a bundled
artifact at `vendor/security-core/`. It is built by `security-agent-lab`'s
`npm run build:hermes-core`, which esbuild-bundles `scripts/hermes-chat.mjs` and
`src/adapters/hermes/mcp-server.ts` (with their TypeScript and npm dependencies:
`@modelcontextprotocol/server`, `parse5`, `zod`) into standalone ESM, and copies
the two runtime assets they read at launch -- `benchmarks/hermes-eval/profiles/learning-off.yaml`
and `src/adapters/hermes/phantomveil-agent.md`. No-argument `pveil` resolves the
launcher from `vendor/security-core/scripts/hermes-chat.js` by default and spawns the
bundled `vendor/security-core/src/adapters/hermes/mcp-server.js` as its restricted
MCP server. The user describes an authorized target in chat; MCP displays its scope
and asks for human confirmation before binding. No bound target means no permitted
target requests. The fork no longer requires an adjacent `security-agent-lab`
checkout at runtime.

`phantomveil_runtime.py` reuses the official entry's active-profile selection and
dotenv loading, then calls the same Hermes CLI REPL. Model/provider settings are
shared only in memory. Each `resolve_runtime_provider()` call, including credential
refresh, runs with Hermes' native credential home through its context-local home
override. The restricted MCP configuration, session state and artifacts remain in
the isolated PhantomVeil profile. Keys are not copied into that profile, passed on
the command line, or printed by the adapter. `pveil` and `hermes-chat.ps1` do not
require a separate `DEEPSEEK_API_KEY` export or force a DeepSeek model route.

## Vendored security core

The committed `vendor/security-core/` tree is generated; do not edit it by hand.
Rebuild it from `security-agent-lab` whenever the TypeScript core or its assets
change:

```powershell
# from the security-agent-lab checkout
npm install        # once, to get the esbuild devDependency
npm run build:hermes-core   # writes ../phantomveil-hermes/vendor/security-core/
```

Override the launcher for development with `PVEIL_HERMES_CORE`, e.g. point it at a
sibling source checkout's `security-agent-lab/scripts/hermes-chat.mjs` to run the
un-bundled TypeScript directly. Live target configs are never vendored: the bundle
ships only code plus the two static assets above. For a standalone install that
needs the project deny-list cross-check at bind time, set `PVEIL_HERMES_CONFIG_ROOT`
to a directory containing `configs/scope.local.json` (etc.); when unset, the
unbound daily session still works and the bind-time source-scope check degrades
gracefully (missing config dir is treated as "no extra deny-list").

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
