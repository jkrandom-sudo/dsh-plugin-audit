/**
 * Pure decision rules for the runtime sentinel.
 *
 * Kept harness-free so the rule set is unit-testable without a Cordis context
 * and reusable by other harness adapters.
 * @module dsh-plugin-audit/sentinel/rules
 */

import { CREDENTIAL_PATH } from '../scanner/patterns.ts'

/** What the sentinel decided about one pending tool call. */
export type SentinelVerdict =
  | { action: 'pass' }
  | { action: 'ask'; reason: string }

/** Rule inputs needed to evaluate one call. */
export interface SentinelRuleConfig {
  /** Hosts treated as pre-approved (exact or leading `*.` suffix match). */
  allowedHosts: string[]
}

/** Tools whose arguments are shell command text. */
const SHELL_TOOLS = new Set(['bash', 'pwsh', 'terminal_send'])

/** Shell commands that move data across the network. */
const EGRESS_COMMAND = /\b(curl|wget|nc|ncat|scp|rsync|sftp|ftp)\b/

/** Host inside an explicit URL. */
const URL_HOST = /https?:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)(?::\d+)?/gi

/** Host-like tokens inside a shell command (fallback when no URL is present). */
const HOST_TOKEN = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?::\d+)?\b/gi

/**
 * Tokens ending in a known file extension are files, not destinations — this
 * keeps `curl -o out.json` / `scp data.log …` style commands from producing
 * false-positive asks in the no-URL fallback path.
 */
const FILE_EXTENSION = /\.(json|txt|log|md|ya?ml|xml|csv|ts|tsx|jsx?|mjs|cjs|py|lock|html?|css|map|sh|gz|zip|tar|env|pem|key|crt)$/i

/** Home-directory dotfile targets: ~/…, $HOME/…, or absolute /Users|/home paths. */
const HOME_DOTFILE = /(?:~|\$HOME|\{HOME\})\/\.[A-Za-z]|\/(?:Users|home)\/[^/\s"']+\/\.[A-Za-z]/i

function hostAllowed(host: string, allowedHosts: string[]): boolean {
  const normalized = host.toLowerCase()
  return allowedHosts.some(entry => {
    const rule = entry.toLowerCase()
    if (rule.startsWith('*.')) {
      const suffix = rule.slice(1)
      return normalized.endsWith(suffix) || normalized === rule.slice(2)
    }
    return normalized === rule
  })
}

function shellCommandOf(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const record = args as Record<string, unknown>
  for (const key of ['command', 'input', 'text', 'data']) {
    const value = record[key]
    if (typeof value === 'string') return value
  }
  return undefined
}

function serialized(args: unknown): string {
  try {
    return JSON.stringify(args) ?? ''
  } catch {
    return ''
  }
}

/**
 * Write tools name their target differently across hosts (`path`, `file_path`,
 * …). Rule 3 judges the write *target* only — matching the serialized args
 * would also scan the file body, so a README that merely mentions `~/.zshrc`
 * would be refused as if it overwrote `~/.zshrc` itself.
 */
function writeTargetOf(args: unknown): string | undefined {
  if (typeof args !== 'object' || args === null) return undefined
  const record = args as Record<string, unknown>
  for (const key of ['file_path', 'path', 'filePath', 'target_file', 'notebook_path']) {
    const value = record[key]
    if (typeof value === 'string') return value
  }
  return undefined
}

/**
 * Evaluate one pending tool call against the sentinel rule set.
 * @param name - Registered tool name (e.g. `bash`, `read`).
 * @param args - Parsed tool arguments.
 * @param config - Sentinel rule configuration.
 * @returns `pass` to delegate, or `ask` with a human-readable reason.
 */
export function evaluateCall(name: string, args: unknown, config: SentinelRuleConfig): SentinelVerdict {
  const text = serialized(args)

  // Rule 1: any tool call touching credential-bearing paths.
  const credentialMatch = CREDENTIAL_PATH.exec(text)
  if (credentialMatch?.[1]) {
    return {
      action: 'ask',
      reason: `dsh-plugin-audit sentinel rule 1 (credential path): Tool "${name}" references the credential path "${credentialMatch[1]}". Approve only if you expected this access.`,
    }
  }

  // Rule 2: shell egress toward hosts outside the allowlist. Explicit URLs
  // take precedence; bare host tokens are a fallback so filenames like
  // "data.json" are not mistaken for destinations.
  if (SHELL_TOOLS.has(name)) {
    const command = shellCommandOf(args)
    if (command && EGRESS_COMMAND.test(command)) {
      const executable = EGRESS_COMMAND.exec(command)?.[1] ?? 'network command'
      const hosts: string[] = []
      URL_HOST.lastIndex = 0
      let urlMatch: RegExpExecArray | null
      while ((urlMatch = URL_HOST.exec(command)) !== null) {
        if (urlMatch[1]) hosts.push(urlMatch[1])
      }
      if (hosts.length === 0) {
        HOST_TOKEN.lastIndex = 0
        let hostMatch: RegExpExecArray | null
        while ((hostMatch = HOST_TOKEN.exec(command)) !== null) {
          if (hostMatch[1] && !FILE_EXTENSION.test(hostMatch[1])) hosts.push(hostMatch[1])
        }
      }
      for (const host of hosts) {
        if (!hostAllowed(host, config.allowedHosts)) {
          return {
            action: 'ask',
            reason: `dsh-plugin-audit sentinel rule 2 (shell egress): Tool "${name}" runs ${executable} toward "${host}", which is not in allowedHosts. Outbound data movement needs your confirmation.`,
          }
        }
      }
    }
  }

  // Rule 3: path-carrying write tools aimed at home-directory dotfiles
  // (credential paths already returned via rule 1). Only the write *target*
  // is matched — the file body may legitimately quote dotfile paths.
  if (name === 'write' || name === 'edit' || name === 'str_replace_editor') {
    const target = writeTargetOf(args)
    if (target && HOME_DOTFILE.test(target)) {
      return {
        action: 'ask',
        reason: `dsh-plugin-audit sentinel rule 3 (home-dotfile write): Tool "${name}" writes to the home-directory dotfile path "${target}". Confirm this configuration change.`,
      }
    }
  }

  return { action: 'pass' }
}
