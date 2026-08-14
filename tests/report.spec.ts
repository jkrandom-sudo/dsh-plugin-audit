import { describe, expect, it } from 'vitest'

import { renderMarkdownCard } from '../src/report.ts'
import type { AuditReport, Finding } from '../src/scanner/types.ts'

/** Build a minimal valid report; tests override what they exercise. */
function baseReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    target: { dir: '/plugins/demo', name: 'demo', filesScanned: 3, truncated: false },
    permissions: {
      fsRead: false,
      fsWrite: false,
      subprocess: false,
      network: false,
      hosts: [],
      envVars: [],
      sensitiveEnvVars: [],
      credentialPaths: [],
      dynamicExec: false,
      inject: [],
      dependencies: [],
      patch: { present: false, inserts: 0, overrides: 0, deletes: 0 },
    },
    findings: [],
    risk: 'info',
    summary: '3 files scanned; risk=info; 0 findings (0 review, 0 notice, 0 info)',
    writesPerformed: false,
    ...overrides,
  }
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    capability: 'fs-write',
    severity: 'notice',
    file: 'src/index.js',
    evidence: 'writeFileSync(...)',
    detail: 'Writes to the filesystem.',
    ...overrides,
  }
}

describe('renderMarkdownCard — edge rendering', () => {
  it('falls back to the directory when no package name is known', () => {
    const report = baseReport()
    delete report.target.name
    const card = renderMarkdownCard(report)
    expect(card).toContain('## Plugin audit: /plugins/demo')
  })

  it('appends the truncation caveat when the walk hit a cap', () => {
    const card = renderMarkdownCard(baseReport({
      target: { dir: '/plugins/demo', name: 'demo', filesScanned: 400, truncated: true },
    }))
    expect(card).toContain('file cap reached, results partial')
  })

  it('appends the unreadable-entry caveat with correct pluralization', () => {
    const one = renderMarkdownCard(baseReport({
      target: { dir: '/plugins/demo', name: 'demo', filesScanned: 2, truncated: false, skippedUnreadable: 1 },
    }))
    expect(one).toContain('1 unreadable entry skipped')

    const many = renderMarkdownCard(baseReport({
      target: { dir: '/plugins/demo', name: 'demo', filesScanned: 2, truncated: false, skippedUnreadable: 3 },
    }))
    expect(many).toContain('3 unreadable entries skipped')
  })

  it('caps the findings table at 30 rows and notes the remainder', () => {
    const findings = Array.from({ length: 35 }, (_, i) => finding({ line: i + 1 }))
    const card = renderMarkdownCard(baseReport({ findings, risk: 'notice' }))

    const rows = card.split('\n').filter(line => line.startsWith('| notice |'))
    expect(rows).toHaveLength(30)
    expect(card).toContain('5 more findings omitted')
  })

  it('renders patch statistics and the dependencies row', () => {
    const report = baseReport()
    report.permissions.patch = { present: true, inserts: 2, overrides: 1, deletes: 0 }
    report.permissions.dependencies = ['cordis', 'schemastery']
    const card = renderMarkdownCard(report)

    expect(card).toContain('| Bundle patch | insert 2 / override 1 / delete 0 |')
    expect(card).toContain('| Declared dependencies | `cordis`, `schemastery` |')
  })

  it('escapes Markdown table metacharacters in attacker-controlled text', () => {
    const report = baseReport()
    report.target.name = 'evil | `injected`\nname'
    report.permissions.envVars = ['TOKEN|x']
    report.findings = [finding({ detail: 'cell | break with `code`' })]
    const card = renderMarkdownCard(report)

    // No raw pipe from the payload may survive inside a table cell.
    expect(card).not.toContain('evil | ')
    expect(card).toContain('evil \\|')
    expect(card).not.toContain('\ninjected')
    expect(card).toContain('`TOKEN\\|x`')
    expect(card).toContain('cell \\| break with \\`code\\`')
  })

  it('renders the findings location with and without a line number', () => {
    const withLine = renderMarkdownCard(baseReport({
      findings: [finding({ file: 'src/a.js', line: 7 })],
      risk: 'notice',
    }))
    expect(withLine).toContain('`src/a.js:7`')

    const withoutLine = renderMarkdownCard(baseReport({
      findings: [finding({ file: 'package.json' })],
      risk: 'notice',
    }))
    expect(withoutLine).toContain('`package.json` |')
  })
})
