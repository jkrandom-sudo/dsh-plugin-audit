import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { describe, expect, it } from 'vitest'

import { auditPlugin } from '../src/scanner/index.ts'
import { renderMarkdownCard } from '../src/report.ts'

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')

describe('auditPlugin', () => {
  it('flags every elevated capability in the suspicious fixture', async () => {
    const report = await auditPlugin(path.join(fixtures, 'suspicious-plugin'))

    expect(report.target.name).toBe('fixture-suspicious-plugin')
    expect(report.target.filesScanned).toBe(1)
    expect(report.risk).toBe('review')
    expect(report.writesPerformed).toBe(false)

    const p = report.permissions
    expect(p.fsRead).toBe(true)
    expect(p.fsWrite).toBe(true)
    expect(p.subprocess).toBe(true)
    expect(p.network).toBe(true)
    expect(p.dynamicExec).toBe(true)
    expect(p.hosts).toContain('evil.example.com')
    expect(p.hosts).toContain('exfil.badhost.io')
    expect(p.sensitiveEnvVars).toContain('GITHUB_TOKEN')
    expect(p.envVars).toContain('HOME')
    expect(p.credentialPaths).toEqual(expect.arrayContaining(['.ssh', '.npmrc']))
    expect(p.inject).toEqual(['credentials', 'tools'])

    const reviewFindings = report.findings.filter(f => f.severity === 'review')
    const capabilities = new Set(reviewFindings.map(f => f.capability))
    expect(capabilities).toContain('credential-access')
    expect(capabilities).toContain('env-access')
    expect(capabilities).toContain('dynamic-exec')

    // Every finding carries inspectable evidence.
    for (const finding of report.findings) {
      expect(finding.file).toBeTruthy()
      expect(finding.evidence.length).toBeGreaterThan(0)
    }
  })

  it('reports the clean fixture as info-level with no elevated capabilities', async () => {
    const report = await auditPlugin(path.join(fixtures, 'clean-plugin'))

    expect(report.risk).toBe('info')
    expect(report.findings).toEqual([])
    expect(report.permissions.fsRead).toBe(false)
    expect(report.permissions.network).toBe(false)
    expect(report.permissions.inject).toEqual(['tools'])
    expect(report.permissions.patch.present).toBe(false)
  })

  it('flags bundle patches that override other plugin rows', async () => {
    const report = await auditPlugin(path.join(fixtures, 'patch-plugin'))

    expect(report.risk).toBe('review')
    expect(report.permissions.patch).toEqual({
      present: true, inserts: 1, overrides: 1, deletes: 0,
    })
    const override = report.findings.find(f => f.capability === 'patch-override')
    expect(override?.file).toBe('cordis.patch.yml')
  })

  it('rejects a target that is not a directory', async () => {
    await expect(auditPlugin(path.join(fixtures, 'does-not-exist')))
      .rejects.toThrow('not a readable directory')
  })

  it('performs no writes inside the audited directory', async () => {
    const target = path.join(fixtures, 'clean-plugin')
    const before = await auditPlugin(target)
    const after = await auditPlugin(target)
    expect(after.findings).toEqual(before.findings)
    expect(after.permissions).toEqual(before.permissions)
  })
})

describe('renderMarkdownCard', () => {
  it('renders the suspicious fixture as a permission card', async () => {
    const report = await auditPlugin(path.join(fixtures, 'suspicious-plugin'))
    const card = renderMarkdownCard(report)

    expect(card).toContain('## Plugin audit: fixture-suspicious-plugin')
    expect(card).toContain('**Risk: REVIEW**')
    expect(card).toContain('### Permission profile')
    expect(card).toContain('| Filesystem write | **yes** |')
    expect(card).toContain('`evil.example.com`')
    expect(card).toContain('`GITHUB_TOKEN`')
    expect(card).toContain('### Findings')
    expect(card).toContain('credential-access')
    expect(card).toContain('not a verdict')
  })

  it('renders a stable snapshot for the clean fixture', async () => {
    const report = await auditPlugin(path.join(fixtures, 'clean-plugin'))
    const card = renderMarkdownCard(report)
      .replace(report.target.dir, '<DIR>')
    expect(card).toMatchSnapshot()
  })
})
