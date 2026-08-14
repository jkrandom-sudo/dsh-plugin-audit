/**
 * Markdown permission-card rendering for audit reports.
 * @module dsh-plugin-audit/report
 */

import type { AuditReport, Finding, Severity } from './scanner/types.ts'

/** Display labels for the severity ladder. */
const SEVERITY_LABEL: Record<Severity, string> = {
  info: 'INFO — no elevated capabilities observed',
  notice: 'NOTICE — elevated capabilities present, skim the list',
  review: 'REVIEW — human review recommended before installing',
}

/** Cap the findings table so the card stays readable in chat. */
const MAX_FINDINGS_ROWS = 30

/**
 * Escape attacker-controlled text before it enters the card: pipes terminate
 * table cells (even inside code spans), backticks break code spans, and
 * newlines inject document structure.
 */
function escapeCell(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, '\\`')
    .replace(/[\r\n]+/g, ' ')
}

function yesNo(value: boolean): string {
  return value ? '**yes**' : 'no'
}

function listOrDash(values: string[]): string {
  return values.length > 0 ? values.map(v => `\`${escapeCell(v)}\``).join(', ') : '—'
}

function findingRow(finding: Finding): string {
  const location = finding.line !== undefined
    ? `${finding.file}:${finding.line}`
    : finding.file
  return `| ${finding.severity} | ${finding.capability} | \`${escapeCell(location)}\` | ${escapeCell(finding.detail)} |`
}

/**
 * Render an audit report as a Markdown permission card.
 * @param report - Completed audit report.
 * @returns Markdown text safe to drop into a chat reply or a README.
 */
export function renderMarkdownCard(report: AuditReport): string {
  const { permissions: p } = report
  const title = escapeCell(report.target.name ?? report.target.dir)

  const caveats: string[] = []
  if (report.target.truncated) caveats.push('file cap reached, results partial')
  if (report.target.skippedUnreadable) {
    caveats.push(`${report.target.skippedUnreadable} unreadable entr${report.target.skippedUnreadable === 1 ? 'y' : 'ies'} skipped`)
  }

  const lines: string[] = [
    `## Plugin audit: ${title}`,
    '',
    `**Risk: ${report.risk.toUpperCase()}** — ${SEVERITY_LABEL[report.risk]}`,
    '',
    `> ${report.summary}${caveats.length > 0 ? ` (${caveats.join('; ')})` : ''}`,
    '',
    '### Permission profile',
    '',
    '| Surface | Observed |',
    '|---|---|',
    `| Filesystem read | ${yesNo(p.fsRead)} |`,
    `| Filesystem write | ${yesNo(p.fsWrite)} |`,
    `| Child processes | ${yesNo(p.subprocess)} |`,
    `| Network | ${yesNo(p.network)} |`,
    `| Outbound hosts | ${listOrDash(p.hosts)} |`,
    `| Env variables | ${listOrDash(p.envVars)} |`,
    `| Credential-looking env | ${listOrDash(p.sensitiveEnvVars)} |`,
    `| Credential paths | ${listOrDash(p.credentialPaths)} |`,
    `| Dynamic code execution | ${yesNo(p.dynamicExec)} |`,
    `| Injected services | ${listOrDash(p.inject)} |`,
    `| Declared dependencies | ${listOrDash(p.dependencies)} |`,
    `| Bundle patch | ${p.patch.present ? `insert ${p.patch.inserts} / override ${p.patch.overrides} / delete ${p.patch.deletes}` : 'none'} |`,
    '',
  ]

  if (report.findings.length > 0) {
    lines.push(
      '### Findings',
      '',
      '| severity | capability | location | detail |',
      '|---|---|---|---|',
    )
    const shown = report.findings.slice(0, MAX_FINDINGS_ROWS)
    for (const finding of shown) lines.push(findingRow(finding))
    if (report.findings.length > shown.length) {
      lines.push(`| … | … | … | ${report.findings.length - shown.length} more findings omitted |`)
    }
    lines.push('')
  }

  lines.push(
    '---',
    '_Static heuristic audit: evidence for human review, not a verdict. '
      + '"No findings" is not a guarantee of safety._',
  )
  return lines.join('\n')
}
