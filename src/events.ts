/**
 * Local typing for the host's tool-pipeline waterfall events.
 *
 * The DSH tools runtime dispatches `tools/pre-execute` / `tools/post-execute`
 * as cordis waterfalls (listeners receive the call plus a `next` delegate).
 * Declaring them here removes `as never` casts and lets the compiler check
 * listener shapes against the host contract — the v0.1.x sentinel no-op
 * (reading `args` where the host provides `arguments`) is the kind of drift
 * this file exists to catch at compile time.
 * @module dsh-plugin-audit/events
 */

/** Minimal shape of the pending execution the waterfalls hand over. */
export interface PendingExecution {
  /** Registered tool name (e.g. `bash`, `write`). */
  name?: string
  /** Parsed tool arguments — the host's field name. */
  arguments?: unknown
  /** Legacy/test-shape fallback. */
  args?: unknown
}

/** Decision vocabulary of the tools/pre-execute waterfall. */
export type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'ask'; reason?: string }

/** Decision vocabulary of the tools/post-execute waterfall. */
export type PostToolDecision =
  | { kind: 'accept' }
  | { kind: 'block'; feedback: unknown }

/** Minimal shape of a finished tool call's result. */
export interface ToolResult {
  /** Failed calls carry isError and no value. */
  isError?: boolean
  /** The tool's canonical return value on success. */
  value?: unknown
}

declare module 'cordis' {
  interface Events {
    'tools/pre-execute'(
      exec: PendingExecution,
      next: () => Promise<PreToolDecision>,
    ): Promise<PreToolDecision>
    'tools/post-execute'(
      exec: PendingExecution,
      result: ToolResult,
      next: () => Promise<PostToolDecision>,
    ): Promise<PostToolDecision>
  }
}
