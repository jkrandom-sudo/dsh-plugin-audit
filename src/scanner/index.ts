/**
 * Audit orchestration: walk, detect, manifest, and risk rollup.
 * @module dsh-plugin-audit/scanner
 */

import path from 'node:path'

import { detectFile } from './detect.ts'
import { analyzeManifest } from './manifest.ts'
import { severityRank, type AuditReport, type Finding, type Severity } from './types.ts'
import { collectSourceFiles } from './walk.ts'

export { analyzeManifest } from './manifest.ts'
export { collectSourceFiles } from './walk.ts'
export { detectFile } from './detect.ts'
export type {
  AuditReport,
  Capability,
  Finding,
  PermissionProfile,
  Severity,
} from './types.ts'

/**
 * Statically audit one plugin directory. Read-only by construction: the only
 * filesystem operations are stat/open/read against the target.
 * @param dir - Plugin directory to audit (relative paths are resolved).
 * @returns The complete audit report.
 * @throws {Error} when the target is not a readable directory.
 */
export async function auditPlugin(dir: string): Promise<AuditReport> {
  const absoluteDir = path.resolve(dir)
  const [walk, manifest] = await Promise.all([
    collectSourceFiles(absoluteDir),
    analyzeManifest(absoluteDir),
  ])

  const findings: Finding[] = [...manifest.findings]
  const envVars = new Set<string>()
  const sensitiveEnvVars = new Set<string>()
  const hosts = new Set<string>()
  const credentialPaths = new Set<string>()
  const inject = new Set<string>()

  let fsRead = false
  let fsWrite = false
  let subprocess = false
  let network = false
  let dynamicExec = false

  for (const file of walk.files) {
    const detection = detectFile(file)
    for (const finding of detection.findings) {
      findings.push(finding)
      switch (finding.capability) {
        case 'fs-read': fsRead = true; break
        case 'fs-write': fsWrite = true; break
        case 'subprocess': subprocess = true; break
        case 'network': network = true; break
        case 'dynamic-exec': dynamicExec = true; break
        case 'credential-access': {
          // Prefer the exact matched fragment over re-parsing truncated evidence.
          credentialPaths.add(finding.match ?? finding.evidence)
          break
        }
        default: break
      }
    }
    for (const name of detection.envVars) envVars.add(name)
    for (const name of detection.sensitiveEnvVars) sensitiveEnvVars.add(name)
    for (const host of detection.hosts) hosts.add(host)
    for (const service of detection.inject) inject.add(service)
  }

  // A plugin that ships only build output (dist/lib are skipped) would
  // otherwise receive a clean info card with zero evidence behind it.
  if (walk.files.length === 0) {
    findings.push({
      capability: 'manifest',
      severity: 'notice',
      file: '(walk)',
      evidence: '0 source files scanned',
      detail: 'No source files were scanned (build-output directories are skipped); '
        + 'review the shipped artifacts manually before installing.',
    })
  }

  findings.sort((a, b) =>
    severityRank(b.severity) - severityRank(a.severity)
    || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0)
    || (a.line ?? 0) - (b.line ?? 0),
  )

  const risk: Severity = findings.reduce<Severity>(
    (current, finding) =>
      severityRank(finding.severity) > severityRank(current) ? finding.severity : current,
    'info',
  )

  const reviewCount = findings.filter(f => f.severity === 'review').length
  const noticeCount = findings.filter(f => f.severity === 'notice').length
  const summary = `${walk.files.length} files scanned; risk=${risk}; `
    + `${findings.length} findings (${reviewCount} review, ${noticeCount} notice, `
    + `${findings.length - reviewCount - noticeCount} info)`

  const target: AuditReport['target'] = {
    dir: absoluteDir,
    filesScanned: walk.files.length,
    truncated: walk.truncated,
  }
  if (walk.skippedUnreadable > 0) target.skippedUnreadable = walk.skippedUnreadable
  if (manifest.name !== undefined) target.name = manifest.name
  if (manifest.version !== undefined) target.version = manifest.version

  return {
    target,
    permissions: {
      fsRead,
      fsWrite,
      subprocess,
      network,
      hosts: [...hosts].sort(),
      envVars: [...envVars].sort(),
      sensitiveEnvVars: [...sensitiveEnvVars].sort(),
      credentialPaths: [...credentialPaths].sort(),
      dynamicExec,
      inject: [...inject].sort(),
      dependencies: [...manifest.dependencies].sort(),
      patch: manifest.patch,
    },
    findings,
    risk,
    summary,
    writesPerformed: false,
  }
}
