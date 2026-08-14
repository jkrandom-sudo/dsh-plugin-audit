import { describe, expect, it } from 'vitest'

import { detectFile } from '../src/scanner/detect.ts'
import type { SourceFile } from '../src/scanner/walk.ts'

/** Wrap source text as one collected file. */
function file(content: string, relativePath = 'src/index.js'): SourceFile {
  return { relativePath, content }
}

describe('detectFile — binding-aware family rules', () => {
  it('follows aliased named imports to the call site', () => {
    const detection = detectFile(file(
      `import { readFileSync as rfs } from 'node:fs'\nconst data = rfs('/etc/passwd', 'utf8')`,
    ))
    const finding = detection.findings.find(f => f.capability === 'fs-read')
    expect(finding?.match).toBe('rfs(')
  })

  it('flags async fs write methods imported from node:fs/promises', () => {
    const detection = detectFile(file(
      `import { rm, mkdir } from 'node:fs/promises'\nawait rm('/tmp/x', { recursive: true })`,
    ))
    expect(detection.findings.some(f => f.capability === 'fs-write' && f.match === 'rm(')).toBe(true)
  })

  it('flags vm destructuring used through new Script(...)', () => {
    const detection = detectFile(file(
      `import { Script } from 'node:vm'\nconst script = new Script(userSupplied)`,
    ))
    const finding = detection.findings.find(f => f.capability === 'dynamic-exec')
    expect(finding?.severity).toBe('review')
  })

  it('does not flag map.get when no http module is imported', () => {
    const detection = detectFile(file(
      `const map = new Map()\nmap.get('key')`,
    ))
    expect(detection.findings.filter(f => f.capability === 'network')).toEqual([])
  })

  it('does not flag map.get when node:http is imported (namespace-scoped matching)', () => {
    const detection = detectFile(file(
      `import http from 'node:http'\nconst map = new Map()\nmap.get('key')`,
    ))
    expect(detection.findings.filter(f => f.capability === 'network')).toEqual([])
  })

  it('flags the qualified call when node:http is used', () => {
    const detection = detectFile(file(
      `import http from 'node:http'\nhttp.get('https://example.com')`,
    ))
    const finding = detection.findings.find(f => f.capability === 'network')
    expect(finding?.match).toBe('http.get(')
  })

  it('follows require destructuring aliases', () => {
    const detection = detectFile(file(
      `const { execSync: run } = require('node:child_process')\nrun('rm -rf /')`,
    ))
    const finding = detection.findings.find(f => f.capability === 'subprocess')
    expect(finding?.match).toBe('run(')
  })

  it('flags namespace require bindings', () => {
    const detection = detectFile(file(
      `const cp = require('child_process')\ncp.spawn('sh', ['-c', 'id'])`,
    ))
    expect(detection.findings.some(f => f.capability === 'subprocess' && f.match === 'cp.spawn(')).toBe(true)
  })

  it('ignores import type declarations entirely', () => {
    const detection = detectFile(file(
      `import type { readFileSync } from 'node:fs'\nexport const nothing = 1`,
    ))
    expect(detection.findings).toEqual([])
  })

  it('flags network libraries used through export-from and dynamic import', () => {
    const detection = detectFile(file(
      `export { helper } from 'axios'\nconst got = await import('got')`,
    ))
    const network = detection.findings.filter(f => f.capability === 'network')
    expect(network.some(f => f.match === 'axios')).toBe(true)
    expect(network.some(f => f.match === 'got')).toBe(true)
  })

  it('flags unaliased named imports at the call site', () => {
    const detection = detectFile(file(
      `import { writeFileSync } from 'fs'\nwriteFileSync('/tmp/out', 'x')`,
    ))
    expect(detection.findings.some(f => f.capability === 'fs-write')).toBe(true)
  })
})

describe('detectFile — static rules and profile extraction', () => {
  it('keeps sensitiveEnvVars a subset of envVars', () => {
    const detection = detectFile(file(
      `const token = process.env.GITHUB_TOKEN\nconst home = process.env.HOME\nconst keyed = process.env['API_KEY']`,
    ))
    expect(detection.envVars).toEqual(expect.arrayContaining(['GITHUB_TOKEN', 'HOME', 'API_KEY']))
    for (const name of detection.sensitiveEnvVars) {
      expect(detection.envVars).toContain(name)
    }
    expect(detection.sensitiveEnvVars).toEqual(expect.arrayContaining(['GITHUB_TOKEN', 'API_KEY']))
    expect(detection.sensitiveEnvVars).not.toContain('HOME')
    expect(detection.findings.some(f => f.capability === 'env-access' && f.match === 'GITHUB_TOKEN')).toBe(true)
  })

  it('extracts the host from URLs with userinfo', () => {
    const detection = detectFile(file(
      `const endpoint = 'https://user:secret@evil.example.com/api'`,
    ))
    expect(detection.hosts).toContain('evil.example.com')
  })

  it('extracts bracketed IPv6 hosts and strips trailing dots', () => {
    const detection = detectFile(file(
      `const a = 'http://[::1]:8080/'\nconst b = 'https://Example.com./path'`,
    ))
    expect(detection.hosts).toContain('[::1]')
    expect(detection.hosts).toContain('example.com')
  })

  it('records the matched credential fragment on the finding', () => {
    const detection = detectFile(file(
      `const key = read('~/.ssh/id_rsa') // a much longer line that would be truncated in evidence`,
    ))
    const finding = detection.findings.find(f => f.capability === 'credential-access')
    expect(finding?.match).toBe('.ssh')
  })

  it('captures inject declarations', () => {
    const detection = detectFile(file(
      `export const inject = ['tools', 'credentials']`,
    ))
    expect(detection.inject).toEqual(['tools', 'credentials'])
  })
})
