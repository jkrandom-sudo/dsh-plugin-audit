/**
 * Real-environment verification for dsh-plugin-audit.
 *
 * Boots the actual local `web` profile composition in-process through the
 * public dsh-app-boot seam (same exports the dsh launcher's profile-boot
 * chunk uses), with the webserver overlaid to port 0 so the check never
 * collides with a running instance. The profile links this package via
 * `dsh.profile.bundles`, so the boot mounts the sentinel from the build in
 * ./lib — run `pnpm build` first.
 *
 * Against the live tree it dispatches the real host exec shape
 * `{ name, arguments }` through the tools/pre-execute waterfall and asserts:
 *
 *   1. a write whose CONTENT merely quotes dotfile paths (~/.dsh, ~/.zshrc,
 *      /Users/x/.local, $HOME/.config) while targeting a project file is
 *      allowed — the issue #5 regression
 *   2. a write TARGETING a home dotfile still returns ask (rule 3 intact)
 *   3. credential paths still route through rule 1
 *   4. shell egress to a non-allowlisted host still routes through rule 2
 *   5. every ask reason names the plugin and rule for traceability
 *   6. ordinary writes and allowlisted egress delegate (kind allow)
 *
 * Usage: pnpm build && node scripts/verify-web-profile.mjs
 * Exit code 0 = every assertion passed.
 */
import { homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { realpathSync } from 'node:fs'

const NM = join(homedir(), '.dsh', 'profiles', 'node_modules', '@deepseek-ai')
// The anchor must be the REAL dsh installation, not the flat fallback link in
// profiles/node_modules: healProfilesModuleFallback re-points that fallback
// directory from whatever the anchor's dependency closure resolves to, so an
// anchor inside the fallback would link every package onto itself (ELOOP).
const INSTALL_ANCHOR = realpathSync(join(NM, 'dsh', 'package.json'))

const importProfilePkg = name => import(pathToFileURL(join(NM, name, 'lib', 'index.js')).href)

const { boot, loadProfile, healProfilesModuleFallback, loadLayeredEnv } =
  await importProfilePkg('dsh-app-boot')
const { provideCmdline } = await importProfilePkg('dsh-cmdline')
const { DSH_LAUNCH_ENVIRONMENT_KEY } = await importProfilePkg('dsh-launch-environment')

let failures = 0
const check = (label, condition, detail) => {
  const ok = Boolean(condition)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok || detail === undefined ? '' : ` — ${detail}`}`)
  if (!ok) failures++
}

const watchdog = setTimeout(() => {
  console.error('FAIL  verification timed out after 120s')
  process.exit(2)
}, 120_000)

console.log('== dsh-plugin-audit real-environment verification (web profile) ==')

healProfilesModuleFallback(INSTALL_ANCHOR)
const profile = loadProfile('dsh', 'web', INSTALL_ANCHOR)
const patches = [
  ...profile.layers.flatMap(layer => layer.patches),
  ...profile.patches,
  // Overlay: never bind the default 3080 during verification.
  { id: 'webserver', config: { host: '127.0.0.1', port: 0 } },
]

const ctx = await boot('dsh', join(profile.dir, 'cordis.yml'), patches, hostCtx => {
  hostCtx.provide(
    DSH_LAUNCH_ENVIRONMENT_KEY,
    loadLayeredEnv('dsh', process.cwd(), () => {}),
  )
  provideCmdline(hostCtx, { args: [], exit: () => {} })
})
console.log('boot complete: web profile composition mounted in-process')

const preExecute = (name, args) =>
  ctx.waterfall(
    'tools/pre-execute',
    { callId: `verify-${name}`, name, arguments: args, signal: AbortSignal.timeout(30_000) },
    async () => ({ kind: 'allow' }),
  )

try {
  // ── 0. the plugin's sentinel listener is on the live waterfall ───────────
  // Indirect but conclusive: an ask decision below can only come from a
  // mounted pre-execute listener; the default terminal handler allows.

  // ── 1. issue #5 regression: dotfile quoted in CONTENT, not the target ────
  const contentCases = [
    ['write', { file_path: 'AGENTS.md', content: 'Global rules live in ~/.dsh/rules.md' }],
    ['write', { file_path: 'README.md', content: 'Edit ~/.zshrc, then check $HOME/.config/dsh' }],
    ['write', { file_path: 'docs/setup.md', content: 'Installs to /Users/user/.local/bin' }],
    ['edit', { path: 'docs/setup.md', content: 'Or /home/user/.local/bin on Linux' }],
  ]
  for (const [name, args] of contentCases) {
    const decision = await preExecute(name, args)
    check(
      `content quoting a dotfile path is allowed (${args.file_path ?? args.path})`,
      decision?.kind === 'allow',
      JSON.stringify(decision),
    )
  }

  // ── 2. rule 3 intact: write TARGETING a home dotfile asks ────────────────
  const dotfileTarget = await preExecute('write', { file_path: '~/.zshrc', content: 'x' })
  check('write targeting ~/.zshrc asks', dotfileTarget?.kind === 'ask', JSON.stringify(dotfileTarget))
  check(
    'rule 3 reason names the plugin and rule',
    typeof dotfileTarget?.reason === 'string' &&
      dotfileTarget.reason.includes('dsh-plugin-audit sentinel rule 3'),
    dotfileTarget?.reason,
  )

  // ── 3. rule 1 intact: credential paths ask ────────────────────────────────
  const credential = await preExecute('write', { file_path: '~/.ssh/config', content: 'x' })
  check('write targeting ~/.ssh/config asks (rule 1)', credential?.kind === 'ask', JSON.stringify(credential))
  check(
    'rule 1 reason names the plugin and rule',
    typeof credential?.reason === 'string' &&
      credential.reason.includes('dsh-plugin-audit sentinel rule 1'),
    credential?.reason,
  )

  // ── 4. rule 2 intact: egress to a non-allowlisted host asks ───────────────
  const egress = await preExecute('bash', { command: 'curl https://collector.unknown.io/x' })
  check('curl toward an unknown host asks (rule 2)', egress?.kind === 'ask', JSON.stringify(egress))
  check(
    'rule 2 reason names the plugin and rule',
    typeof egress?.reason === 'string' &&
      egress.reason.includes('dsh-plugin-audit sentinel rule 2'),
    egress?.reason,
  )

  // ── 5. ordinary calls delegate ────────────────────────────────────────────
  const plainWrite = await preExecute('write', { file_path: 'src/index.ts', content: 'export {}' })
  check('ordinary write delegates (allow)', plainWrite?.kind === 'allow', JSON.stringify(plainWrite))
  const allowedEgress = await preExecute('bash', { command: 'curl https://api.github.com/repos/cli/cli' })
  check('allowlisted egress delegates (allow)', allowedEgress?.kind === 'allow', JSON.stringify(allowedEgress))
} finally {
  await ctx.fiber.dispose()
  clearTimeout(watchdog)
}

console.log(
  failures === 0 ? '== all real-environment checks passed ==' : `== ${failures} check(s) FAILED ==`,
)
process.exit(failures === 0 ? 0 : 1)
