/**
 * Package-owned invariant companion for `dsh-plugin-audit`.
 *
 * The package's authoritative contract: the plugin_audit tool is read-only.
 * Its canonical value carries the `writesPerformed: false` marker; the
 * companion observes the post-execute waterfall and fails if an audit result
 * ever loses that marker.
 * @module dsh-plugin-audit/invariant
 */

import type { Context } from 'cordis'

const PACKAGE_NAME = 'dsh-plugin-audit'

/** A package-attributed invariant failure reported by the host registry. */
type InvariantFailure = (message: string) => never

/** Installer callback accepted by the host's invariant registry. */
type InvariantInstaller = (ctx: Context, fail: InvariantFailure) => void | Promise<void>

/** Minimal runtime contract used by the companion without a host checkout. */
interface InvariantRegistry {
  register(packageName: string, installer: InvariantInstaller): () => void
}

/** Cordis companion plugin name. */
export const name = 'dsh-plugin-audit-invariant'

/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

interface AuditExecution {
  name?: string
}

interface AuditResultValue {
  value?: { writesPerformed?: boolean }
}

type PostToolDecision = { kind: 'accept' } | { kind: 'block'; feedback: unknown }

/**
 * Watch plugin_audit results and enforce the read-only contract.
 * @param ctx - Cordis context carrying the event bus.
 * @param fail - Registry-provided failure reporter.
 */
const install: InvariantInstaller = (ctx, fail) => {
  ctx.on('tools/post-execute' as never, (async (
    exec: AuditExecution,
    result: AuditResultValue,
    next: () => Promise<PostToolDecision>,
  ): Promise<PostToolDecision> => {
    if (exec?.name === 'plugin_audit' && result?.value?.writesPerformed !== false) {
      fail('plugin_audit result lost its read-only marker (writesPerformed !== false)')
    }
    return next()
  }) as never)
}

/**
 * Resolve the host registry through Cordis's named service lookup.
 * @param ctx - Cordis context carrying the host service.
 * @returns the host invariant registry.
 * @throws {Error} when the companion is loaded without its host service.
 */
function getInvariantRegistry(ctx: Context): InvariantRegistry {
  const registry = ctx.get('invariants') as InvariantRegistry | undefined
  if (registry === undefined) {
    throw new Error(`invariant companion requires the "invariants" service for ${PACKAGE_NAME}`)
  }
  return registry
}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(getInvariantRegistry(ctx).register(PACKAGE_NAME, install))
