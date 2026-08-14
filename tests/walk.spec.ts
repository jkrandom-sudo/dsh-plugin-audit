import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { afterEach, describe, expect, it } from 'vitest'

import { collectSourceFiles, MAX_FILE_BYTES, MAX_FILES } from '../src/scanner/walk.ts'

const tempRoots: string[] = []

/** Create a throwaway directory, cleaned up after each test. */
async function makeTempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-audit-walk-'))
  tempRoots.push(dir)
  return dir
}

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map(dir =>
    fs.rm(dir, { recursive: true, force: true }).catch(() => undefined),
  ))
})

describe('collectSourceFiles', () => {
  it('rejects a target that is a plain file', async () => {
    const dir = await makeTempDir()
    const filePath = path.join(dir, 'index.js')
    await fs.writeFile(filePath, 'export {}')
    await expect(collectSourceFiles(filePath)).rejects.toThrow('not a readable directory')
  })

  it('skips node_modules and other build-output directories', async () => {
    const dir = await makeTempDir()
    await fs.mkdir(path.join(dir, 'node_modules', 'pkg'), { recursive: true })
    await fs.writeFile(path.join(dir, 'node_modules', 'pkg', 'index.js'), 'export {}')
    await fs.mkdir(path.join(dir, 'dist'), { recursive: true })
    await fs.writeFile(path.join(dir, 'dist', 'bundle.js'), 'export {}')
    await fs.writeFile(path.join(dir, 'index.ts'), 'export {}')

    const walk = await collectSourceFiles(dir)
    expect(walk.files.map(f => f.relativePath)).toEqual(['index.ts'])
    expect(walk.truncated).toBe(false)
  })

  it('ignores non-source extensions', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'data.json'), '{}')
    await fs.writeFile(path.join(dir, 'notes.md'), '# hi')
    await fs.writeFile(path.join(dir, 'main.mjs'), 'export {}')

    const walk = await collectSourceFiles(dir)
    expect(walk.files.map(f => f.relativePath)).toEqual(['main.mjs'])
  })

  it('flags truncation when the file cap is reached', async () => {
    const dir = await makeTempDir()
    for (let i = 0; i < MAX_FILES + 1; i += 1) {
      await fs.writeFile(path.join(dir, `f${String(i).padStart(4, '0')}.js`), 'export {}')
    }
    const walk = await collectSourceFiles(dir)
    expect(walk.files).toHaveLength(MAX_FILES)
    expect(walk.truncated).toBe(true)
  })

  it('flags truncation when the depth cap is exceeded', async () => {
    const dir = await makeTempDir()
    let current = dir
    for (let i = 0; i < 14; i += 1) {
      current = path.join(current, `d${i}`)
      await fs.mkdir(current)
    }
    await fs.writeFile(path.join(current, 'deep.js'), 'export {}')
    await fs.writeFile(path.join(dir, 'shallow.js'), 'export {}')

    const walk = await collectSourceFiles(dir)
    expect(walk.truncated).toBe(true)
    expect(walk.files.map(f => f.relativePath)).toEqual(['shallow.js'])
  })

  it('truncates oversized file contents at MAX_FILE_BYTES', async () => {
    const dir = await makeTempDir()
    await fs.writeFile(path.join(dir, 'big.js'), 'a'.repeat(MAX_FILE_BYTES + 4096))

    const walk = await collectSourceFiles(dir)
    expect(walk.files).toHaveLength(1)
    expect(walk.files[0]?.content.length).toBe(MAX_FILE_BYTES)
    expect(walk.truncated).toBe(false)
  })

  it('skips unreadable files and counts them instead of failing', async () => {
    const dir = await makeTempDir()
    const locked = path.join(dir, 'locked.js')
    await fs.writeFile(locked, 'export {}')
    await fs.chmod(locked, 0o000)
    await fs.writeFile(path.join(dir, 'ok.js'), 'export {}')

    try {
      const walk = await collectSourceFiles(dir)
      expect(walk.files.map(f => f.relativePath)).toEqual(['ok.js'])
      expect(walk.skippedUnreadable).toBe(1)
    } finally {
      await fs.chmod(locked, 0o644)
    }
  })

  it('returns forward-slash relative paths sorted by code point', async () => {
    const dir = await makeTempDir()
    await fs.mkdir(path.join(dir, 'sub'), { recursive: true })
    await fs.writeFile(path.join(dir, 'sub', 'b.js'), 'export {}')
    // Code-point order: 'B' (66) < 'a' (97) < 's' (115). Avoid A/a — the
    // default macOS filesystem is case-insensitive and would merge them.
    await fs.writeFile(path.join(dir, 'B.js'), 'export {}')
    await fs.writeFile(path.join(dir, 'a.js'), 'export {}')

    const walk = await collectSourceFiles(dir)
    expect(walk.files.map(f => f.relativePath)).toEqual(['B.js', 'a.js', 'sub/b.js'])
  })
})
