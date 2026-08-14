/**
 * Heuristic capability detection over collected source files.
 *
 * The scanner is a static aid, not a judge: it parses import bindings
 * (including aliases) and matches call sites against the bound names, then
 * records every match as inspectable evidence.
 * @module dsh-plugin-audit/scanner/detect
 */

import { CREDENTIAL_PATH, SENSITIVE_ENV } from './patterns.ts'
import type { Capability, Finding, Severity } from './types.ts'
import type { SourceFile } from './walk.ts'

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

/** One capability family: the module specifiers and the methods that count. */
interface FamilyRule {
  capability: Capability
  severity: Severity
  family: ReadonlySet<string>
  /** Exported names whose use is evidence of the capability. */
  methods: string[]
  detail: string
}

const FAMILY_RULES: FamilyRule[] = [
  {
    capability: 'fs-read',
    severity: 'info',
    family: MODULES.fs,
    methods: [
      'readFileSync', 'readFile', 'createReadStream', 'readdirSync', 'readdir',
      'statSync', 'stat', 'lstatSync', 'lstat', 'readlinkSync', 'readlink',
      'accessSync', 'access', 'watch', 'open', 'read', 'opendir', 'existsSync',
    ],
    detail: 'Reads files from the filesystem.',
  },
  {
    capability: 'fs-write',
    severity: 'notice',
    family: MODULES.fs,
    methods: [
      'writeFileSync', 'writeFile', 'appendFileSync', 'appendFile',
      'createWriteStream', 'mkdirSync', 'mkdir', 'rmSync', 'rm', 'rmdirSync',
      'rmdir', 'unlinkSync', 'unlink', 'renameSync', 'rename', 'copyFileSync',
      'copyFile', 'chmodSync', 'chmod', 'chownSync', 'chown', 'truncateSync',
      'truncate', 'cpSync', 'cp', 'symlinkSync', 'symlink', 'utimesSync', 'utimes',
    ],
    detail: 'Writes to the filesystem.',
  },
  {
    capability: 'subprocess',
    severity: 'notice',
    family: MODULES.childProcess,
    methods: ['execSync', 'execFileSync', 'spawnSync', 'exec', 'execFile', 'spawn', 'fork'],
    detail: 'Spawns child processes.',
  },
  {
    capability: 'network',
    severity: 'notice',
    family: MODULES.http,
    methods: ['request', 'get', 'createServer', 'createSecureServer'],
    detail: 'Uses the http/https module.',
  },
  {
    capability: 'network',
    severity: 'notice',
    family: MODULES.net,
    methods: ['connect', 'createConnection', 'createServer'],
    detail: 'Opens raw network connections.',
  },
  {
    capability: 'dynamic-exec',
    severity: 'review',
    family: MODULES.vm,
    methods: [
      'runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction',
      'Script', 'createContext', 'measureMemory',
    ],
    detail: 'Executes code through the vm module.',
  },
]

/** Capability rules that need no module import. */
interface StaticRule {
  capability: Capability
  severity: Severity
  pattern: RegExp
  detail: string
}

const STATIC_RULES: StaticRule[] = [
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
    capability: 'credential-access',
    severity: 'review',
    pattern: CREDENTIAL_PATH,
    detail: 'References a credential-bearing path.',
  },
]

const IDENT = '[A-Za-z_$][\\w$]*'

const IMPORT_TYPE = /^\s*import\s+type\b/
const IMPORT_NS = new RegExp(`\\bimport\\s+\\*\\s+as\\s+(${IDENT})\\s+from\\s*['"]([^'"]+)['"]`, 'g')
const IMPORT_NAMED = /\bimport\s+\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g
const IMPORT_DEFAULT = new RegExp(
  `\\bimport\\s+(${IDENT})\\s*(?:,\\s*\\{([^}]*)\\})?\\s*(?:,\\s*\\*\\s*as\\s+(${IDENT})\\s*)?from\\s*['"]([^'"]+)['"]`,
  'g',
)
const IMPORT_SIDE_EFFECT = /\bimport\s*['"]([^'"]+)['"]/g
const REQUIRE_NS = new RegExp(`\\b(?:const|let|var)\\s+(${IDENT})\\s*=\\s*require\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`, 'g')
const REQUIRE_NAMED = /\b(?:const|let|var)\s+\{([^}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g
const AWAIT_IMPORT_NS = new RegExp(
  `\\b(?:const|let|var)\\s+(${IDENT})\\s*=\\s*await\\s+import\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`,
  'g',
)
const DYNAMIC_IMPORT = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
const EXPORT_FROM = /\bexport\s+(?:\*|\{[^}]*\})\s*from\s*['"]([^'"]+)['"]/g
/** Any module-specifier use on a line, for network-library flagging. */
const SPECIFIER_USE = /\b(?:from\s+|require\s*\(\s*|import\s*\(\s*|import\s+)['"]([^'"]+)['"]/g

const ENV_DOT = /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g
const ENV_INDEX = /process\.env\[['"]([^'"]+)['"]\]/g
const URL_LITERAL = /https?:\/\/(?:[^@/\s'"]*@)?(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9][a-zA-Z0-9.-]*)(?::\d+)?/g
const INJECT_DECL = /\bexport\s+const\s+inject\s*(?::[^=]+)?=\s*\[([\s\S]*?)\]\s*(?:\n|$)/

/** Local names one module specifier was bound to in a file. */
interface ModuleBindings {
  /** Whole-module bindings (default/namespace import, plain require, await import). */
  namespaces: string[]
  /** Named bindings: the local alias plus the export it refers to. */
  named: { local: string; imported: string }[]
}

/** Parse a `{ a, b as c }` import clause into named bindings. */
function parseNamedClause(clause: string): { local: string; imported: string }[] {
  const named: { local: string; imported: string }[] = []
  for (const entry of clause.split(',')) {
    const trimmed = entry.trim().replace(/^type\s+/, '')
    if (trimmed === '') continue
    const parts = trimmed.split(/\s+as\s+/)
    const imported = parts[0]?.trim()
    if (!imported || !new RegExp(`^${IDENT}$`).test(imported)) continue
    const local = (parts[1] ?? parts[0])?.trim()
    if (local && new RegExp(`^${IDENT}$`).test(local)) named.push({ local, imported })
  }
  return named
}

/** Parse a `{ a, b: c }` require destructuring into named bindings. */
function parseRequireClause(clause: string): { local: string; imported: string }[] {
  const named: { local: string; imported: string }[] = []
  for (const entry of clause.split(',')) {
    const trimmed = entry.trim()
    if (trimmed === '') continue
    const parts = trimmed.split(/\s*:\s*/)
    const imported = parts[0]?.trim()
    if (!imported || !new RegExp(`^${IDENT}$`).test(imported)) continue
    const local = (parts[1] ?? parts[0])?.trim()
    if (local && new RegExp(`^${IDENT}$`).test(local)) named.push({ local, imported })
  }
  return named
}

/** Collect every module specifier a file binds, with its local names. */
function collectBindings(content: string): Map<string, ModuleBindings> {
  const bindings = new Map<string, ModuleBindings>()
  const ensure = (specifier: string): ModuleBindings => {
    let entry = bindings.get(specifier)
    if (!entry) {
      entry = { namespaces: [], named: [] }
      bindings.set(specifier, entry)
    }
    return entry
  }

  const lines = content.split('\n')
  lines.forEach((rawLine) => {
    if (IMPORT_TYPE.test(rawLine)) return

    IMPORT_NS.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = IMPORT_NS.exec(rawLine)) !== null) {
      if (match[1] && match[2]) ensure(match[2]).namespaces.push(match[1])
    }
    IMPORT_NAMED.lastIndex = 0
    while ((match = IMPORT_NAMED.exec(rawLine)) !== null) {
      if (match[1] && match[2]) ensure(match[2]).named.push(...parseNamedClause(match[1]))
    }
    IMPORT_DEFAULT.lastIndex = 0
    while ((match = IMPORT_DEFAULT.exec(rawLine)) !== null) {
      if (match[1] && match[4]) ensure(match[4]).namespaces.push(match[1])
      if (match[2] && match[4]) ensure(match[4]).named.push(...parseNamedClause(match[2]))
      if (match[3] && match[4]) ensure(match[4]).namespaces.push(match[3])
    }
    IMPORT_SIDE_EFFECT.lastIndex = 0
    while ((match = IMPORT_SIDE_EFFECT.exec(rawLine)) !== null) {
      if (match[1]) ensure(match[1])
    }
    REQUIRE_NS.lastIndex = 0
    while ((match = REQUIRE_NS.exec(rawLine)) !== null) {
      if (match[1] && match[2]) ensure(match[2]).namespaces.push(match[1])
    }
    REQUIRE_NAMED.lastIndex = 0
    while ((match = REQUIRE_NAMED.exec(rawLine)) !== null) {
      if (match[1] && match[2]) ensure(match[2]).named.push(...parseRequireClause(match[1]))
    }
    AWAIT_IMPORT_NS.lastIndex = 0
    while ((match = AWAIT_IMPORT_NS.exec(rawLine)) !== null) {
      if (match[1] && match[2]) ensure(match[2]).namespaces.push(match[1])
    }
    DYNAMIC_IMPORT.lastIndex = 0
    while ((match = DYNAMIC_IMPORT.exec(rawLine)) !== null) {
      if (match[1]) ensure(match[1])
    }
    EXPORT_FROM.lastIndex = 0
    while ((match = EXPORT_FROM.exec(rawLine)) !== null) {
      if (match[1]) ensure(match[1])
    }
  })
  return bindings
}

/** Build the call-site pattern for one family rule from the file's bindings. */
function familyPattern(rule: FamilyRule, bindings: Map<string, ModuleBindings>): RegExp | undefined {
  const namespaces = new Set<string>()
  const locals = new Set<string>()
  for (const [specifier, entry] of bindings) {
    if (!rule.family.has(specifier)) continue
    for (const ns of entry.namespaces) namespaces.add(ns)
    for (const named of entry.named) {
      if (rule.methods.includes(named.imported)) locals.add(named.local)
    }
  }
  const alternatives: string[] = []
  if (namespaces.size > 0) {
    alternatives.push(`(?:${[...namespaces].join('|')})\\.(?:${rule.methods.join('|')})`)
  }
  if (locals.size > 0) {
    alternatives.push(`(?<![.\\w])(?:${[...locals].join('|')})`)
  }
  if (alternatives.length === 0) return undefined
  return new RegExp(`(?:${alternatives.join('|')})\\s*\\(`)
}

/** Per-file detection outcome: findings plus profile contributions. */
export interface FileDetection {
  findings: Finding[]
  envVars: string[]
  sensitiveEnvVars: string[]
  hosts: string[]
  inject: string[]
}

/**
 * Run every detection rule over one source file.
 * @param file - Collected source file.
 * @returns Findings and profile contributions for the file.
 */
export function detectFile(file: SourceFile): FileDetection {
  const bindings = collectBindings(file.content)
  const activeFamilyRules = FAMILY_RULES
    .map(rule => ({ rule, pattern: familyPattern(rule, bindings) }))
    .filter((entry): entry is { rule: FamilyRule; pattern: RegExp } => entry.pattern !== undefined)

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

    for (const { rule, pattern } of activeFamilyRules) {
      pattern.lastIndex = 0
      const match = pattern.exec(rawLine)
      if (match) {
        findings.push({
          capability: rule.capability,
          severity: rule.severity,
          file: file.relativePath,
          line,
          evidence,
          detail: rule.detail,
          match: match[0],
        })
      }
    }
    for (const rule of STATIC_RULES) {
      rule.pattern.lastIndex = 0
      const match = rule.pattern.exec(rawLine)
      if (match) {
        findings.push({
          capability: rule.capability,
          severity: rule.severity,
          file: file.relativePath,
          line,
          evidence,
          detail: rule.detail,
          match: match[1] ?? match[0],
        })
      }
    }

    ENV_DOT.lastIndex = 0
    let envMatch: RegExpExecArray | null
    while ((envMatch = ENV_DOT.exec(rawLine)) !== null) {
      const name = envMatch[1]
      if (!name) continue
      envVars.add(name)
      if (SENSITIVE_ENV.test(name)) sensitiveEnvVars.add(name)
    }
    ENV_INDEX.lastIndex = 0
    while ((envMatch = ENV_INDEX.exec(rawLine)) !== null) {
      const name = envMatch[1]
      if (!name) continue
      envVars.add(name)
      if (SENSITIVE_ENV.test(name)) sensitiveEnvVars.add(name)
    }

    URL_LITERAL.lastIndex = 0
    let urlMatch: RegExpExecArray | null
    while ((urlMatch = URL_LITERAL.exec(rawLine)) !== null) {
      const host = urlMatch[1]
      if (host) hosts.add(host.replace(/\.$/, '').toLowerCase())
    }

    // Flag network-library imports at the line where they appear.
    SPECIFIER_USE.lastIndex = 0
    let specifierMatch: RegExpExecArray | null
    const flagged = new Set<string>()
    while ((specifierMatch = SPECIFIER_USE.exec(rawLine)) !== null) {
      const specifier = specifierMatch[1]
      if (!specifier || !MODULES.networkLibs.has(specifier) || flagged.has(specifier)) continue
      flagged.add(specifier)
      findings.push({
        capability: 'network',
        severity: 'notice',
        file: file.relativePath,
        line,
        evidence,
        detail: `Imports the HTTP client library "${specifier}".`,
        match: specifier,
      })
    }
  })

  for (const name of sensitiveEnvVars) {
    findings.push({
      capability: 'env-access',
      severity: 'review',
      file: file.relativePath,
      evidence: `process.env.${name}`,
      detail: 'Reads a credential-looking environment variable.',
      match: name,
    })
  }

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
