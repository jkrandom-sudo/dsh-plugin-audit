/**
 * Shared types for the static audit engine.
 * @module dsh-plugin-audit/scanner/types
 */

/** Severity ladder for findings and the overall verdict. */
export type Severity = 'info' | 'notice' | 'review'

/** Capability categories the scanner recognizes. */
export type Capability =
  | 'fs-read'
  | 'fs-write'
  | 'subprocess'
  | 'network'
  | 'env-access'
  | 'credential-access'
  | 'dynamic-exec'
  | 'patch-override'
  | 'manifest'

/** One observed capability usage, with source evidence. */
export interface Finding {
  /** Capability category. */
  capability: Capability
  /** Severity assigned by the detection rule. */
  severity: Severity
  /** Repository-relative file path, or a manifest file name. */
  file: string
  /** 1-based line number, when the evidence is a source line. */
  line?: number
  /** Trimmed source line or manifest excerpt. */
  evidence: string
  /** Human-readable explanation of why this was flagged. */
  detail: string
}

/** Aggregate permission profile derived from findings. */
export interface PermissionProfile {
  /** File-system reads observed. */
  fsRead: boolean
  /** File-system writes observed. */
  fsWrite: boolean
  /** Child-process spawning observed. */
  subprocess: boolean
  /** Network usage observed. */
  network: boolean
  /** Outbound hosts referenced in source literals, deduplicated. */
  hosts: string[]
  /** All process.env variables referenced. */
  envVars: string[]
  /** Subset of envVars whose names look credential-bearing. */
  sensitiveEnvVars: string[]
  /** Credential-related path literals observed. */
  credentialPaths: string[]
  /** eval / new Function / vm execution observed. */
  dynamicExec: boolean
  /** Cordis services declared via `inject`. */
  inject: string[]
  /** Bundle patch statistics. */
  patch: {
    /** Whether a cordis.patch.yml was found. */
    present: boolean
    /** Rows inserted by the patch. */
    inserts: number
    /** Rows overriding existing plugin rows. */
    overrides: number
    /** Rows removed by the patch. */
    deletes: number
  }
}

/** The complete static audit result. */
export interface AuditReport {
  /** What was scanned. */
  target: {
    /** Absolute directory that was scanned. */
    dir: string
    /** package.json name, when present. */
    name?: string
    /** package.json version, when present. */
    version?: string
    /** Number of source files scanned. */
    filesScanned: number
    /** True when the file walk hit its safety cap. */
    truncated: boolean
  }
  /** Aggregate permission profile. */
  permissions: PermissionProfile
  /** Every finding, in scan order. */
  findings: Finding[]
  /** Highest severity across findings; 'info' when clean. */
  risk: Severity
  /** One-sentence human summary. */
  summary: string
  /**
   * Contract marker consumed by the invariant companion: the audit engine is
   * read-only and never writes inside the audited directory.
   */
  writesPerformed: false
}

/** Numeric rank so severities can be compared. */
export function severityRank(severity: Severity): number {
  switch (severity) {
    case 'info': return 0
    case 'notice': return 1
    case 'review': return 2
  }
}
