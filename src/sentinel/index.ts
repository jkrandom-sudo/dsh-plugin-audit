/**
 * Cordis wiring for the runtime sentinel.
 * @module dsh-plugin-audit/sentinel
 */

import type { Context } from 'cordis'

import { evaluateCall, type SentinelRuleConfig } from './rules.ts'

export { evaluateCall } from './rules.ts'
export type { SentinelRuleConfig, SentinelVerdict } from './rules.ts'

/** Minimal shape of the pending call the pipeline waterfall hands over. */
interface PendingExecution {
  name?: string
  args?: unknown
}

/** Minimal decision vocabulary of the tools/pre-execute waterfall. */
type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason?: string }

type WaterfallNext = () => Promise<PreToolDecision>

/**
 * Install the sentinel as a `tools/pre-execute` waterfall listener.
 *
 * Risky calls return `ask`, which the host routes through its own approval
 * service (`ctx.approval` one-shot prompt); everything else delegates with
 * `next()` so downstream policy still runs.
 * @param ctx - Scoped plugin context.
 * @param config - Resolved sentinel configuration.
 * @param log - Decision logger, defaults to the plugin logger.
 * @returns Disposer that detaches the listener.
 */
export function installSentinel(
  ctx: Context,
  config: SentinelRuleConfig,
  log: (message: string) => void = message => { ctx.logger.info(message) },
): () => void {
  const listener = async (exec: PendingExecution, next: WaterfallNext): Promise<PreToolDecision> => {
    const verdict = evaluateCall(exec.name ?? '', exec.args, config)
    if (verdict.action === 'ask') {
      log(`sentinel: ask — ${verdict.reason}`)
      return { kind: 'ask', reason: verdict.reason }
    }
    return next()
  }
  // ctx.on returns its own disposer; the fiber also auto-disposes listeners.
  const off = ctx.on('tools/pre-execute' as never, listener as never) as () => boolean
  return () => {
    off()
  }
}
