import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { analyzeManifest } from '../src/scanner/manifest.ts'

const tempRoots: string[] = []

async function makeTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-audit-manifest-'))
  tempRoots.push(dir)
  return dir
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map(dir =>
    fs.rm(dir, { recursive: true, force: true }).catch(() => undefined),
  ))
})

describe('analyzeManifest', () => {
  it('raises a notice when package.json is missing', async () => {
    const dir = await makeTempDir()
    const analysis = await analyzeManifest(dir)

    expect(analysis.name).toBeUndefined()
    expect(analysis.findings.some(f =>
      f.capability === 'manifest' && f.evidence === '(missing)',
    )).toBe(true)
  })

  it('raises a notice when package.json is unparseable', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'package.json'), '{ not json')
    const analysis = await analyzeManifest(dir)

    expect(analysis.name).toBeUndefined()
    expect(analysis.findings.some(f => f.evidence === '(unparseable JSON)')).toBe(true)
  })

  it('raises a notice when the name is missing or empty', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: '', main: 'index.js' }))
    const analysis = await analyzeManifest(dir)

    expect(analysis.name).toBeUndefined()
    expect(analysis.findings.some(f => f.evidence === '"name" missing or empty')).toBe(true)
  })

  it('raises a notice when no entry point is declared', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({ name: 'demo' }))
    const analysis = await analyzeManifest(dir)

    expect(analysis.findings.some(f => f.evidence === 'no "main" or "exports" entry')).toBe(true)
  })

  it('collects runtime and peer dependency names', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify({
      name: 'demo',
      main: 'index.js',
      dependencies: { cordis: '^4.0.0' },
      peerDependencies: { schemastery: '^3.0.0' },
    }))
    const analysis = await analyzeManifest(dir)

    expect(analysis.name).toBe('demo')
    expect(analysis.dependencies).toEqual(expect.arrayContaining(['cordis', 'schemastery']))
    expect(analysis.patch.present).toBe(false)
  })

  it('counts delete rows and flags them for review', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'cordis.patch.yml'), [
      '- insert:',
      '    id: demo',
      '- delete:',
      '    id: other-plugin',
      '',
    ].join('\n'))
    const analysis = await analyzeManifest(dir)

    expect(analysis.patch).toEqual({ present: true, inserts: 1, overrides: 0, deletes: 1 })
    const finding = analysis.findings.find(f => f.capability === 'patch-override')
    expect(finding?.severity).toBe('review')
  })

  it('does not count indented list items as patch rows', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'cordis.patch.yml'), [
      '- insert:',
      '    id: demo',
      '    config:',
      '      steps:',
      '      - override: not-a-row',
      '      - delete: also-not-a-row',
      '',
    ].join('\n'))
    const analysis = await analyzeManifest(dir)

    expect(analysis.patch).toEqual({ present: true, inserts: 1, overrides: 0, deletes: 0 })
    expect(analysis.findings.filter(f => f.capability === 'patch-override')).toEqual([])
  })

  it('treats insert-only patches as unremarkable', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'cordis.patch.yml'), '- insert:\n    id: demo\n')
    const analysis = await analyzeManifest(dir)

    expect(analysis.patch.present).toBe(true)
    expect(analysis.findings.filter(f => f.capability === 'patch-override')).toEqual([])
  })
})
