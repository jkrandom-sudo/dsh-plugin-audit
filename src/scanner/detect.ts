/**
 * Heuristic capability detection over collected source files.
 *
 * The scanner is a static aid, not a judge: it pairs module imports with
 * call-site patterns and records every match as inspectable evidence.
 * @module dsh-plugin-audit/scanner/detect
 */

import type { Capability, Finding, Severity } from './types.ts'
import type { SourceFile } from './walk.ts'

/** Env var names that look credential-bearing. */
const SENSITIVE_ENV = /TOKEN|KEY|SECRET|PASSW|CREDENTIAL|AUTH|COOKIE|SESSION/i

/** Path fragments that usually hold credentials or identities. */
const CREDENTIAL_PATH = /(\.ssh|\.aws|\.gnupg|\.git-credentials|\.netrc|\.npmrc|id_rsa|id_ed25519|keychain|\.docker\/config\.json)/i

/** Module specifiers grouped by capability family. */
const MODULES = {
  fs: new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']),
  childProcess: new Set(['child_process', 'node:child_process']),
  http: new Set(['http', 'node:http', 'https', 'node:https', 'http2', 'node:http2']),
  net: new Set(['net', 'node:net', 'tls', 'node:tls', 'dgram', 'node:dgram']),
  vm: new Set(['vm', 'node:vm']),
  networkLibs: new Set([
    'axios', 'got', 'undici', 'node-fetch', 'ws', 'socket.io', 'socket.io-client',
    'superagent', 'ky', 'ofetch', 'ssh2',
  ]),
}

interface Rule {
  capability: Capability
  severity: Severity
  /** Module families that must be imported for the pattern to match. */
  requires?: ReadonlySet<string>[]
  pattern: RegExp
  detail: string
}

const RULES: Rule[] = [
  {
    capability: 'fs-read',
    severity: 'info',
    requires: [MODULES.fs],
    pattern: /\b(readFileSync|readFile|createReadStream|readdirSync|readdir|statSync|lstatSync|readlinkSync|accessSync|watch)\s*\(/,
    detail: 'Reads files from the filesystem.',
  },
  {
    capability: 'fs-write',
    severity: 'notice',
    requires: [MODULES.fs],
    pattern: /\b(writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync|rmSync|unlinkSync|renameSync|copyFileSync|chmodSync|chownSync)\s*\(/,
    detail: 'Writes to the filesystem.',
  },
  {
    capability: 'subprocess',
    severity: 'notice',
    requires: [MODULES.childProcess],
    pattern: /\b(execSync|execFileSync|spawnSync|exec|execFile|spawn|fork)\s*\(/,
    detail: 'Spawns child processes.',
  },
  {
    capability: 'network',
    severity: 'notice',
    requires: [MODULES.http],
    pattern: /\b(request|get|createServer|createSecureServer)\s*\(/,
    detail: 'Uses the http/https module.',
  },
  {
    capability: 'network',
    severity: 'notice',
    requires: [MODULES.net],
    pattern: /\b(connect|createConnection|createServer)\s*\(/,
    detail: 'Opens raw network connections.',
  },
  {
    capability: 'network',
    severity: 'notice',
    pattern: /(?<![.\w])fetch\s*\(/,
    detail: 'Calls the global fetch API.',
  },
  {
    capability: 'network',
    severity: 'notice',
    pattern: /\bnew\s+WebSocket\s*\(/,
    detail: 'Opens a WebSocket connection.',
  },
  {
    capability: 'dynamic-exec',
    severity: 'review',
    pattern: /(?<![.\w])eval\s*\(|new\s+Function\s*\(/,
    detail: 'Evaluates dynamically constructed code.',
  },
  {
    capability: 'dynamic-exec',
    severity: 'review',
    requires: [MODULES.vm],
    pattern: /\bvm\.(runInThisContext|runInNewContext|runInContext|compileFunction|Script)/,
    detail: 'Executes code through the vm module.',
  },
  {
    capability: 'credential-access',
    severity: 'review',
    pattern: CREDENTIAL_PATH,
    detail: 'References a credential-bearing path.',
  },
]

const IMPORT_FROM = /\bimport\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]/g
const REQUIRE_CALL = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g
const DYNAMIC_IMPORT = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
const ENV_DOT = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g
const ENV_INDEX = /process\.env\[['"]([^'"]+)['"]\]/g
const URL_LITERAL = /https?:\/\/([a-zA-Z0-9.-]+(?::\d+)?)/g
const INJECT_DECL = /export\s+const\s+inject\s*(?::[^=]+)?=\s*\[([^\]]*)\]/

/** Per-file detection outcome: findings plus profile contributions. */
export interface FileDetection {
  findings: Finding[]
  envVars: string[]
  sensitiveEnvVars: string[]
  hosts: string[]
  inject: string[]
}

function collectImports(content: string): Set<string> {
  const modules = new Set<string>()
  for (const pattern of [IMPORT_FROM, REQUIRE_CALL, DYNAMIC_IMPORT]) {
    pattern.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = pattern.exec(content)) !== null) {
      if (match[1]) modules.add(match[1])
    }
  }
  return modules
}

function importsAny(modules: Set<string>, families: ReadonlySet<string>[]): boolean {
  return families.some(family => [...family].some(specifier => modules.has(specifier)))
}

/**
 * Run every detection rule over one source file.
 * @param file - Collected source file.
 * @returns Findings and profile contributions for the file.
 */
export function detectFile(file: SourceFile): FileDetection {
  const modules = collectImports(file.content)
  const findings: Finding[] = []
  const envVars = new Set<string>()
  const sensitiveEnvVars = new Set<string>()
  const hosts = new Set<string>()
  const inject: string[] = []

  const lines = file.content.split('\n')
  lines.forEach((rawLine, index) => {
    const line = index + 1
    const evidence = rawLine.trim().slice(0, 160)
    if (evidence === '') return

    for (const rule of RULES) {
      if (rule.requires && !importsAny(modules, rule.requires)) continue
      rule.pattern.lastIndex = 0
      if (rule.pattern.test(rawLine)) {
        findings.push({
          capability: rule.capability,
          severity: rule.severity,
          file: file.relativePath,
          line,
          evidence,
          detail: rule.detail,
        })
      }
    }

    ENV_DOT.lastIndex = 0
    let envMatch: RegExpExecArray | null
    while ((envMatch = ENV_DOT.exec(rawLine)) !== null) {
      const name = envMatch[1]
      if (!name) continue
      if (SENSITIVE_ENV.test(name)) sensitiveEnvVars.add(name)
      else envVars.add(name)
    }
    ENV_INDEX.lastIndex = 0
    while ((envMatch = ENV_INDEX.exec(rawLine)) !== null) {
      const name = envMatch[1]
      if (!name) continue
      if (SENSITIVE_ENV.test(name)) sensitiveEnvVars.add(name)
      else envVars.add(name)
    }

    URL_LITERAL.lastIndex = 0
    let urlMatch: RegExpExecArray | null
    while ((urlMatch = URL_LITERAL.exec(rawLine)) !== null) {
      const host = urlMatch[1]
      if (host) hosts.add(host.replace(/:\d+$/, '').toLowerCase())
    }
  })

  for (const name of sensitiveEnvVars) {
    findings.push({
      capability: 'env-access',
      severity: 'review',
      file: file.relativePath,
      evidence: `process.env.${name}`,
      detail: 'Reads a credential-looking environment variable.',
    })
  }

  // Flag network-library imports at their import line.
  lines.forEach((rawLine, index) => {
    if (!/^\s*(import\b|const\b|let\b|var\b)/.test(rawLine)) return
    IMPORT_FROM.lastIndex = 0
    REQUIRE_CALL.lastIndex = 0
    for (const pattern of [IMPORT_FROM, REQUIRE_CALL]) {
      pattern.lastIndex = 0
      const match = pattern.exec(rawLine)
      const specifier = match?.[1]
      if (specifier && MODULES.networkLibs.has(specifier)) {
        findings.push({
          capability: 'network',
          severity: 'notice',
          file: file.relativePath,
          line: index + 1,
          evidence: rawLine.trim().slice(0, 160),
          detail: `Imports the HTTP client library "${specifier}".`,
        })
      }
    }
  })

  const injectMatch = INJECT_DECL.exec(file.content)
  if (injectMatch?.[1]) {
    const quoted = injectMatch[1].match(/['"]([^'"]+)['"]/g) ?? []
    for (const entry of quoted) inject.push(entry.slice(1, -1))
  }

  return {
    findings,
    envVars: [...envVars],
    sensitiveEnvVars: [...sensitiveEnvVars],
    hosts: [...hosts],
    inject,
  }
}
