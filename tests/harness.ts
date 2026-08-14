import { Context } from 'cordis'
import { vi } from 'vitest'

import * as plugin from '../src/index.ts'

/** Minimal fake of the host tools service, capturing registrations. */
export function createFakeTools() {
  const registered: unknown[] = []
  const unregistered: unknown[] = []
  return {
    registered,
    unregistered,
    service: {
      register: vi.fn((definition: unknown) => {
        registered.push(definition)
        return () => {
          unregistered.push(definition)
        }
      }),
    },
  }
}

/** Mount the production plugin against a fake tools service. */
export async function createPluginHarness(config: plugin.Config = {}) {
  const ctx = new Context()
  const tools = createFakeTools()
  ctx.provide('tools', tools.service)
  const info = vi.spyOn(ctx.logger, 'info').mockImplementation(() => undefined)
  const fiber = await ctx.plugin(plugin, config)

  return {
    ctx,
    fiber,
    tools,
    info,
    async dispose(): Promise<void> {
      try {
        await fiber.dispose()
      } finally {
        info.mockRestore()
      }
    },
  }
}

/** Dispatch one tools/pre-execute waterfall, mirroring the host registry. */
export function dispatchPreExecute(
  ctx: Context,
  exec: { name: string; args: unknown },
): Promise<{ kind: string; reason?: string }> {
  type Decision = { kind: string; reason?: string }
  const dispatch = ctx.waterfall as (
    name: string,
    exec: { name: string; args: unknown },
    inner: () => Promise<Decision>,
  ) => Promise<Decision>
  return dispatch('tools/pre-execute', exec, async () => ({ kind: 'allow' }))
}
