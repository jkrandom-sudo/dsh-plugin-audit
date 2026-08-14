/**
 * Read-only source file collection for the audit engine.
 * @module dsh-plugin-audit/scanner/walk
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'

/** Source extensions the scanner reads. */
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs'])

/** Directories never entered during the walk. */
const SKIP_DIRECTORIES = new Set([
  'node_modules', '.git', 'lib', 'dist', 'build', 'out', 'coverage', '.pnpm-store',
])

/** Upper bound on files scanned; the report flags truncation beyond it. */
export const MAX_FILES = 400

/** Upper bound on bytes read per file. */
export const MAX_FILE_BYTES = 256 * 1024

/** Deepest directory nesting the walk descends into. */
export const MAX_DEPTH = 12

/** One collected source file. */
export interface SourceFile {
  /** Repository-relative path using forward slashes. */
  relativePath: string
  /** File contents (possibly truncated at {@link MAX_FILE_BYTES}). */
  content: string
}

/** Result of walking one plugin directory. */
export interface WalkResult {
  /** Collected source files. */
  files: SourceFile[]
  /** True when the file or depth cap was reached and files were skipped. */
  truncated: boolean
  /** Files or directories skipped because they could not be read. */
  skippedUnreadable: number
}

/** Locale-independent code-point ordering, stable across machines. */
function byCodePoint(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

/**
 * Collect source files under a directory without ever writing to it.
 * Unreadable files and directories are skipped and counted, never fatal.
 * @param dir - Absolute directory to walk.
 * @returns Collected files, a truncation flag, and the unreadable count.
 * @throws {Error} when `dir` is not a readable directory.
 */
export async function collectSourceFiles(dir: string): Promise<WalkResult> {
  const stat = await fs.stat(dir).catch(() => undefined)
  if (!stat?.isDirectory()) {
    throw new Error(`audit target is not a readable directory: ${dir}`)
  }

  const files: SourceFile[] = []
  let truncated = false
  let skippedUnreadable = 0

  async function visit(current: string, depth: number): Promise<void> {
    if (files.length >= MAX_FILES || depth > MAX_DEPTH) {
      truncated = true
      return
    }
    const entries = await fs.readdir(current, { withFileTypes: true })
      .catch(() => {
        skippedUnreadable += 1
        return undefined
      })
    if (!entries) return
    entries.sort((a, b) => byCodePoint(a.name, b.name))
    for (const entry of entries) {
      if (files.length >= MAX_FILES) {
        truncated = true
        return
      }
      const full = path.join(current, entry.name)
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) await visit(full, depth + 1)
        continue
      }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path.extname(entry.name))) continue
      const handle = await fs.open(full, 'r').catch(() => {
        skippedUnreadable += 1
        return undefined
      })
      if (!handle) continue
      try {
        const { size } = await handle.stat()
        const length = Math.min(size, MAX_FILE_BYTES)
        const buffer = Buffer.alloc(length)
        const { bytesRead } = await handle.read(buffer, 0, length, 0)
        files.push({
          relativePath: path.relative(dir, full).split(path.sep).join('/'),
          content: buffer.subarray(0, bytesRead).toString('utf8'),
        })
      } catch {
        skippedUnreadable += 1
      } finally {
        await handle.close()
      }
    }
  }

  await visit(dir, 0)
  return { files, truncated, skippedUnreadable }
}
