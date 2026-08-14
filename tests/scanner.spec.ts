import { createHash } from 'node:crypto'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { auditPlugin } from '../src/scanner/index.ts'
import { renderMarkdownCard } from '../src/report.ts'

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')

const tempRoots: string[] = []

async function makeTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-audit-scan-'))
  tempRoots.push(dir)
  return dir
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map(dir =>
    fs.rm(dir, { recursive: true, force: true }).catch(() => undefined),
  ))
})

/** Hash every file's path and content under a directory, recursively. */
async function hashTree(dir: string): Promise<string> {
  const hash = createHash('sha256')
  async function visit(current: string): Promise<void> {
    const entries = await fs.readdir(current, { withFileTypes: true })
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const entry of entries) {
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) {
        await visit(full)
      } else if (entry.isFile()) {
        hash.update(path.relative(dir, full))
        hash.update(await fs.readFile(full))
      }
    }
  }
  await visit(dir)
  return hash.digest('hex')
}

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
    const target = path.join(fixtures, 'suspicious-plugin')
    const before = await hashTree(target)
    await auditPlugin(target)
    const after = await hashTree(target)
    // Byte-level proof of the read-only contract: identical tree hash.
    expect(after).toBe(before)
  })

  it('keeps sensitiveEnvVars a subset of envVars at the report level', async () => {
    const report = await auditPlugin(path.join(fixtures, 'suspicious-plugin'))
    for (const name of report.permissions.sensitiveEnvVars) {
      expect(report.permissions.envVars).toContain(name)
    }
  })

  it('sorts findings by severity descending, then file, then line', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'sort-demo', main: 'b.js' }))
    await fs.writeFile(path.join(dir, 'b.js'), [
      `eval('one')`,
      `eval('two')`,
      '',
    ].join('\n'))
    await fs.writeFile(path.join(dir, 'a.js'), `eval('three')`)

    const report = await auditPlugin(dir)
    const dynamicExec = report.findings.filter(f => f.capability === 'dynamic-exec')
    // Same severity: 'a.js' (code point 97) sorts before 'b.js', lines ascending.
    expect(dynamicExec.map(f => [f.file, f.line])).toEqual([
      ['a.js', 1],
      ['b.js', 1],
      ['b.js', 2],
    ])

    // Severity dominates file order: a notice in 'a.js' still trails the reviews.
    const severities = report.findings.map(f => f.severity)
    const ranks = severities.map(s => (s === 'review' ? 2 : s === 'notice' ? 1 : 0))
    expect([...ranks].sort((x, y) => y - x)).toEqual(ranks)
  })

  it('never returns a clean card for a plugin that ships only build output', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'dist-only', main: 'dist/index.js' }))
    await fs.mkdir(path.join(dir, 'dist'))
    await fs.writeFile(path.join(dir, 'dist', 'index.js'), `require('child_process').execSync('id')`)

    const report = await auditPlugin(dir)
    expect(report.target.filesScanned).toBe(0)
    expect(report.risk).not.toBe('info')
    expect(report.findings.some(f =>
      f.capability === 'manifest' && f.detail.includes('No source files were scanned'),
    )).toBe(true)
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
