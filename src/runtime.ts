/**
 * Runtime boundary and Cordis activation for dsh-plugin-audit.
 * @module dsh-plugin-audit/runtime
 */

import type { Context } from 'cordis'

import { resolveConfig, type Config } from './config.ts'
import { renderMarkdownCard } from './report.ts'
import { auditPlugin } from './scanner/index.ts'
import { installSentinel } from './sentinel/index.ts'

/** JSON-schema node in the subset enforced by the host tool registry. */
interface JsonSchemaNode {
  type?: string
  description?: string
  properties?: Record<string, JsonSchemaNode>
  required?: string[]
  additionalProperties?: boolean
  items?: JsonSchemaNode
  enum?: (string | number | boolean | null)[]
}

/** One model-facing content block. */
interface ContentBlock {
  type: string
  text?: string
}

/** The slice of the host tool registry this plugin consumes. */
interface ToolRegistry {
  register(definition: {
    name: string
    description: string
    parameters: JsonSchemaNode
    output: { schema: JsonSchemaNode; render(args: unknown, value: unknown): ContentBlock[] }
    execute(args: unknown, exec: unknown): Promise<unknown>
    isConcurrencySafe?(args: unknown): boolean
  }): () => void
}

/** Canonical value returned by the plugin_audit tool. */
export interface PluginAuditValue {
  /** Rendered Markdown permission card. */
  markdown: string
  /** Highest severity found: info | notice | review. */
  risk: string
  /** Number of source files scanned. */
  filesScanned: number
  /** Total findings. */
  findingsCount: number
  /** Read-only contract marker checked by the invariant companion. */
  writesPerformed: false
}

interface PluginAuditArgs {
  path: string
  format?: 'markdown' | 'json'
}

function narrowArgs(args: unknown): PluginAuditArgs {
  if (typeof args !== 'object' || args === null) {
    throw new Error('plugin_audit expects an object argument')
  }
  const record = args as Record<string, unknown>
  if (typeof record.path !== 'string' || record.path.trim() === '') {
    throw new Error('plugin_audit requires a non-empty "path" string')
  }
  const narrowed: PluginAuditArgs = { path: record.path }
  if (record.format === 'markdown' || record.format === 'json') narrowed.format = record.format
  return narrowed
}

/**
 * Build the plugin_audit tool definition.
 * @returns Host-ready tool definition.
 */
export function createPluginAuditTool(): Parameters<ToolRegistry['register']>[0] {
  return {
    name: 'plugin_audit',
    description:
      'Statically audit a DeepSeek Harness plugin directory before installing it. '
      + 'Reports the permission profile (filesystem, network hosts, env variables, '
      + 'credential paths, dynamic execution, bundle patch) with per-line evidence. '
      + 'Read-only: never modifies the audited directory.',
    parameters: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to the plugin directory to audit (absolute, or relative to the workspace).',
        },
        format: {
          type: 'string',
          enum: ['markdown', 'json'],
          description: 'Output format: "markdown" permission card (default) or "json" summary.',
        },
      },
      required: ['path'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          markdown: { type: 'string' },
          risk: { type: 'string' },
          filesScanned: { type: 'number' },
          findingsCount: { type: 'number' },
          writesPerformed: { type: 'boolean' },
        },
        required: ['markdown', 'risk', 'filesScanned', 'findingsCount', 'writesPerformed'],
      },
      render: (_args, value) => {
        const audit = value as PluginAuditValue
        return [{ type: 'text', text: audit.markdown }]
      },
    },
    execute: async (args) => {
      const { path: target, format } = narrowArgs(args)
      const report = await auditPlugin(target)
      const value: PluginAuditValue = {
        // The markdown field carries the model-facing rendering: the permission
        // card, or the pretty-printed structured report when format is "json".
        markdown: format === 'json' ? JSON.stringify(report, null, 2) : renderMarkdownCard(report),
        risk: report.risk,
        filesScanned: report.target.filesScanned,
        findingsCount: report.findings.length,
        writesPerformed: false,
      }
      return value
    },
    isConcurrencySafe: () => true,
  }
}

/**
 * Apply the plugin to its Cordis context.
 * @param ctx - Scoped plugin context; registrations are owned by its fiber.
 * @param config - Configuration resolved by Cordis from the exported schema.
 */
export function apply(ctx: Context, config: Config): void {
  const resolved = resolveConfig(config)

  const tools = ctx.get('tools') as ToolRegistry | undefined
  if (tools === undefined) {
    throw new Error('dsh-plugin-audit requires the "tools" service')
  }

  ctx.effect(() => {
    const unregisterTool = tools.register(createPluginAuditTool())

    const detachSentinel = resolved.sentinelEnabled
      ? installSentinel(ctx, { allowedHosts: resolved.allowedHosts })
      : () => undefined

    ctx.logger.info(
      `dsh-plugin-audit loaded: plugin_audit tool registered`
        + (resolved.sentinelEnabled ? ', sentinel armed' : ', sentinel disabled'),
    )

    return () => {
      unregisterTool()
      detachSentinel()
    }
  })
}
