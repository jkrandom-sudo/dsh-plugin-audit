/**
 * Serializable configuration, schema, and direct-call defaults.
 * @module dsh-plugin-audit/config
 */

import z from 'schemastery'

/** Hosts the sentinel never interrupts, exact or `*.` suffix matches. */
export const DEFAULT_ALLOWED_HOSTS = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  '*.deepseek.com',
]

/** Plugin configuration supplied by the profile composition. */
export interface Config {
  /** Enable the runtime sentinel on the tool pipeline. Default true. */
  sentinelEnabled?: boolean
  /** Outbound hosts the sentinel treats as pre-approved. */
  allowedHosts?: string[]
}

/** Configuration after defaults have been resolved. */
export interface ResolvedConfig {
  /** Enable the runtime sentinel on the tool pipeline. */
  sentinelEnabled: boolean
  /** Outbound hosts the sentinel treats as pre-approved. */
  allowedHosts: string[]
}

/** Loader-visible configuration schema and defaults. */
export const Config: z<Config> = z.object({
  sentinelEnabled: z.boolean()
    .description('Intercept risky tool calls (credential paths, unknown outbound hosts) with an approval prompt.')
    .default(true),
  allowedHosts: z.array(z.string())
    .description('Hosts the sentinel never interrupts; exact match or leading "*." suffix match.')
    .default(DEFAULT_ALLOWED_HOSTS),
})

/**
 * Resolve the same defaults for direct callers that bypass Cordis Loader.
 * @param config - Partial serialized configuration.
 * @returns Configuration with all defaults applied.
 */
export function resolveConfig(config: Config = {}): ResolvedConfig {
  return {
    sentinelEnabled: config.sentinelEnabled ?? true,
    allowedHosts: config.allowedHosts ?? [...DEFAULT_ALLOWED_HOSTS],
  }
}
