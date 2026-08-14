# dsh-plugin-audit

[中文 README](./README.zh.md)

Security audit plugin for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH): static permission profiling of third-party plugins, plus a runtime sentinel that asks before tool calls touch credentials or move data to unknown hosts.

## Overview

DSH's ecosystem makes "everything is a plugin" literal — and the plugin radar is explicit that *runs ≠ audited*. `dsh-plugin-audit` closes that gap in two layers:

- **Static audit** — a `plugin_audit` tool that scans a plugin directory (source, `package.json`, `cordis.patch.yml`) and renders a permission profile card: which capabilities the code exercises (file reads/writes, subprocess, network, environment access, credential paths, dynamic execution, core-row patches), with file/line evidence, a `info / notice / review` risk grade, and a machine-readable JSON summary. The scanner is **read-only by contract** — every report carries `writesPerformed: false`, and an optional invariant companion enforces it at runtime.
- **Runtime sentinel** — a listener on the harness's `tools/pre-execute` waterfall that returns `ask` (routed to the host's normal approval prompt) when a pending tool call:
  1. references a credential path (`~/.ssh`, `~/.aws`, `.npmrc`, keychain, …) in any tool's arguments;
  2. runs a shell egress command (`curl`, `wget`, `nc`, `scp`, …) toward a host outside `allowedHosts`;
  3. writes to a home-directory dotfile outside the workspace.

The audit is an aid, not a verdict: it surfaces evidence so you can decide.

## Compatibility

| Requirement | Version |
| --- | --- |
| DSH mainline | verified against the 2026-08-14 snapshot (`npx @deepseek-ai/dsh`, web profile) |
| Node.js | `^22.19.0 || >=24.0.0` |
| Cordis | `^4.0.0-rc.7` (peer) |

DSH is in developer preview and ships breaking changes frequently; the date above records the mainline snapshot this release was verified against. The `./invariant` companion is exported but intentionally **not** wired into `cordis.patch.yml`: the stock web/base profiles do not provide the `invariants` service, and a pending row blocks boot. Profiles that do provide it can add a row `{ id: dsh-plugin-audit-invariant, name: 'dsh-plugin-audit/invariant' }`.

## Install

From npm (once published):

```bash
dsh plugin --profile web add dsh-plugin-audit
```

Directly from GitHub:

```bash
dsh plugin --profile web add github:jkrandom-sudo/dsh-plugin-audit
```

Both commands register the package in the profile's `dsh.profile.bundles` and apply this package's `cordis.patch.yml`, which inserts one row (`dsh-plugin-audit`, with `sentinelEnabled: true`). Restart the profile to pick it up.

## Uninstall

```bash
dsh plugin --profile web remove dsh-plugin-audit
```

This removes the dependency and the bundle row. Restart the profile. The plugin performs no writes outside the profile's own dependency metadata, so nothing else needs cleanup.

## Quick start

In any DSH session on a profile where the plugin is installed, ask the agent:

```
Audit the plugin at ~/some-third-party-plugin with plugin_audit
```

or the model can call the tool directly:

```json
{ "path": "/absolute/path/to/plugin", "format": "markdown" }
```

The tool returns a Markdown permission card (risk grade, capability table, findings with file/line evidence) plus a JSON summary `{ markdown, risk, filesScanned, findingsCount, writesPerformed }`.

The sentinel needs no invocation — once armed it watches every tool call in the session and routes suspicious ones to your normal approval prompt with a reason, e.g.:

> Tool "bash" runs curl toward "collector.unknown.io", which is not in allowedHosts. Outbound data movement needs your confirmation.

## Configuration

One row in the profile's composition (inserted automatically by the bundle patch):

```yaml
- id: dsh-plugin-audit
  name: 'dsh-plugin-audit'
  config:
    sentinelEnabled: true
    allowedHosts:
      - github.com
      - api.github.com
      - raw.githubusercontent.com
      - registry.npmjs.org
      - '*.deepseek.com'
```

| Key | Default | Effect |
| --- | --- | --- |
| `sentinelEnabled` | `true` | Master switch. `false` keeps the static `plugin_audit` tool and disables all runtime interception. |
| `allowedHosts` | see above | Hosts treated as pre-approved for shell egress. Exact match, or a leading `*.` suffix rule (`*.deepseek.com` also matches the bare domain). |

Notes:

- Without a host approval channel, an `ask` decision degrades to `deny` — the call is blocked, never silently allowed.
- The static scanner needs no configuration and never consults `allowedHosts`; it reports every network surface it finds.

## Permissions & data

- **Read-only scanner.** The audit walks the target directory with read handles only (capped at 400 files / 256 KB per file), and every report carries `writesPerformed: false`. The optional `dsh-plugin-audit/invariant` companion fails the session if a `plugin_audit` result ever loses that marker.
- **No network, no telemetry.** The plugin makes no network calls of its own and sends nothing anywhere. URL hosts appearing in a report are extracted from scanned source text, never contacted.
- **Sentinel decisions stay local.** `ask` verdicts are mediated by the host's existing approval prompt; the plugin only logs the decision reason via `ctx.logger`.
- **What the sentinel inspects:** tool name + arguments of calls passing through `tools/pre-execute`. It does not read files, environment variables, or conversation content beyond the call arguments themselves.

## Troubleshooting

- **Boot fails with `dsh-plugin-audit/invariant: pending (waiting for service: invariants)`** — you wired the invariant row into a profile that does not provide the `invariants` service. Remove that row (the shipped `cordis.patch.yml` already omits it).
- **`plugin_audit` not visible to the agent** — confirm the package appears in the profile's `package.json` `dsh.profile.bundles` and that `--dump-config` shows the `dsh-plugin-audit` row; then restart the profile.
- **Legitimate commands keep asking** — add the host to `allowedHosts`, or set `sentinelEnabled: false` to keep only the static auditor.
- **A scan reports fewer files than expected** — the walker caps at 400 files and 256 KB per file and skips `node_modules`, `.git`, `lib`, `dist`. Audit the package source, not an installed copy.

## Development

```bash
pnpm install
pnpm typecheck   # both tsconfigs
pnpm test        # vitest, 23 tests: scanner, sentinel rules, plugin lifecycle, invariant
pnpm build       # tsc -b && tsdown -> lib/
```

Layout: `src/scanner/` is a harness-agnostic pure engine (walk → detect → manifest → report), `src/report.ts` renders the Markdown card, `src/runtime.ts` adapts it to the Cordis/DSH tool contract, `src/sentinel/` holds the pure decision rules and the waterfall listener, `src/invariant.ts` is the read-only enforcement companion.

**End-to-end verification** (performed for v0.1.0 on 2026-08-14): after `pnpm typecheck && pnpm test && pnpm build` went green (23/23), the package was linked into a real local `web` profile via `dsh plugin --profile web add <path>`, and the exact profile composition was booted in-process (bundle patches + user layer + home layer, webserver on an OS-assigned port). Assertions, all passing: the `tools` service resolved; `plugin_audit` was registered in the real `ToolRuntime`; the armed sentinel returned `ask` for `cat ~/.ssh/id_rsa` and delegated `pnpm test`; and `plugin_audit` executed a real audit of a suspicious fixture plugin (`risk=review`, 10 findings, `writesPerformed=false`). The stock loader fails boot on any entry that does not activate, so a zero-error boot of the composed tree is itself load evidence.

## License & security

MIT — see [LICENSE](./LICENSE).

This plugin is an audit aid, not an antivirus: a clean report means "no evidence found by these rules", not "safe". Findings are heuristics with file/line evidence so a human can judge. If you find a bypass (a capability the scanner misses, a sentinel rule that can be dodged), please open an issue at <https://github.com/jkrandom-sudo/dsh-plugin-audit/issues> — or a private report for anything you would rather not disclose publicly first.
