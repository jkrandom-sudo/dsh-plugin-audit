/**
 * Manifest and bundle-patch analysis for the audit engine.
 * @module dsh-plugin-audit/scanner/manifest
 */

import { promises as fs } from 'node:fs'
import path from 'node:path'

import type { Finding } from './types.ts'

/** Outcome of inspecting package.json and cordis.patch.yml. */
export interface ManifestAnalysis {
  /** package.json name, when present and valid. */
  name?: string
  /** package.json version, when present and valid. */
  version?: string
  /** Declared runtime + peer dependency specifiers. */
  dependencies: string[]
  /** Patch row counts. */
  patch: { present: boolean; inserts: number; overrides: number; deletes: number }
  /** Findings raised from manifest inspection. */
  findings: Finding[]
}

const PATCH_ROW = /^\s*-\s*(insert|override|delete)\s*:/

/**
 * Inspect the two manifest files a DSH plugin ships.
 * @param dir - Absolute plugin directory.
 * @returns Parsed manifest facts and findings.
 */
export async function analyzeManifest(dir: string): Promise<ManifestAnalysis> {
  const findings: Finding[] = []
  const dependencies: string[] = []
  let name: string | undefined
  let version: string | undefined

  const packageJsonPath = path.join(dir, 'package.json')
  const packageJsonRaw = await fs.readFile(packageJsonPath, 'utf8').catch(() => undefined)
  if (packageJsonRaw === undefined) {
    findings.push({
      capability: 'manifest',
      severity: 'notice',
      file: 'package.json',
      evidence: '(missing)',
      detail: 'No package.json found; the radar minimum bar requires one.',
    })
  } else {
    try {
      const parsed = JSON.parse(packageJsonRaw) as Record<string, unknown>
      if (typeof parsed.name === 'string' && parsed.name !== '') name = parsed.name
      if (typeof parsed.version === 'string') version = parsed.version
      for (const field of ['dependencies', 'peerDependencies'] as const) {
        const table = parsed[field]
        if (table && typeof table === 'object') {
          dependencies.push(...Object.keys(table as Record<string, unknown>))
        }
      }
      if (!name) {
        findings.push({
          capability: 'manifest',
          severity: 'notice',
          file: 'package.json',
          evidence: '"name" missing or empty',
          detail: 'package.json lacks a non-empty name.',
        })
      }
      if (parsed.main === undefined && parsed.exports === undefined) {
        findings.push({
          capability: 'manifest',
          severity: 'notice',
          file: 'package.json',
          evidence: 'no "main" or "exports" entry',
          detail: 'No resolvable entry point declared.',
        })
      }
    } catch {
      findings.push({
        capability: 'manifest',
        severity: 'notice',
        file: 'package.json',
        evidence: '(unparseable JSON)',
        detail: 'package.json could not be parsed.',
      })
    }
  }

  const patch = { present: false, inserts: 0, overrides: 0, deletes: 0 }
  const patchPath = path.join(dir, 'cordis.patch.yml')
  const patchRaw = await fs.readFile(patchPath, 'utf8').catch(() => undefined)
  if (patchRaw !== undefined) {
    patch.present = true
    for (const rawLine of patchRaw.split('\n')) {
      const row = PATCH_ROW.exec(rawLine)
      if (!row) continue
      if (row[1] === 'insert') patch.inserts += 1
      if (row[1] === 'override') patch.overrides += 1
      if (row[1] === 'delete') patch.deletes += 1
    }
    if (patch.overrides > 0 || patch.deletes > 0) {
      findings.push({
        capability: 'patch-override',
        severity: 'review',
        file: 'cordis.patch.yml',
        evidence: `overrides: ${patch.overrides}, deletes: ${patch.deletes}`,
        detail: 'The bundle patch overrides or removes existing plugin rows, replacing the behavior of other components.',
      })
    }
  }

  const result: ManifestAnalysis = { dependencies, patch, findings }
  if (name !== undefined) result.name = name
  if (version !== undefined) result.version = version
  return result
}
