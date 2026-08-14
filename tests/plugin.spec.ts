import { fileURLToPath } from 'node:url'
import path from 'node:path'

import Loader from '@cordisjs/plugin-loader'
import { Context } from 'cordis'
import { describe, expect, it, vi } from 'vitest'

import * as plugin from '../src/index.ts'
import * as invariant from '../src/invariant.ts'
import { resolveConfig } from '../src/config.ts'
import { createPluginHarness, dispatchPreExecute } from './harness.ts'

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'fixtures')

describe('dsh-plugin-audit', () => {
  it('preserves the function-plugin namespace through Loader unwrapping', () => {
    expect('default' in plugin).toBe(false)

    const loader = Object.create(Loader.prototype) as Loader
    const unwrapped = loader.unwrapExports(plugin) as Record<string, unknown>
    expect(unwrapped).toBe(plugin)
    expect(unwrapped.name).toBe('dsh-plugin-audit')
    expect(unwrapped.inject).toEqual(['tools'])
    expect(unwrapped.Config).toBeDefined()
    expect(typeof unwrapped.apply).toBe('function')
  })

  it('resolves schema defaults', () => {
    expect(resolveConfig()).toEqual({
      sentinelEnabled: true,
      allowedHosts: expect.arrayContaining(['github.com', '*.deepseek.com']),
    })
    expect(resolveConfig({ sentinelEnabled: false, allowedHosts: [] })).toEqual({
      sentinelEnabled: false,
      allowedHosts: [],
    })
  })

  it('registers the plugin_audit tool and logs activation', async () => {
    const harness = await createPluginHarness()
    expect(harness.tools.service.register).toHaveBeenCalledTimes(1)

    const definition = harness.tools.registered[0] as {
      name: string
      parameters: { required?: string[] }
    }
    expect(definition.name).toBe('plugin_audit')
    expect(definition.parameters.required).toEqual(['path'])
    expect(harness.info).toHaveBeenCalledWith(expect.stringContaining('sentinel armed'))
    await harness.dispose()
  })

  it('executes an audit end-to-end through the tool definition', async () => {
    const harness = await createPluginHarness()
    const definition = harness.tools.registered[0] as {
      execute(args: unknown, exec: unknown): Promise<unknown>
    }
    const value = await definition.execute(
      { path: path.join(fixtures, 'suspicious-plugin') },
      undefined,
    ) as { markdown: string; risk: string; writesPerformed: false }

    expect(value.risk).toBe('review')
    expect(value.markdown).toContain('## Plugin audit: fixture-suspicious-plugin')
    expect(value.writesPerformed).toBe(false)
    await harness.dispose()
  })

  it('rejects tool calls without a path', async () => {
    const harness = await createPluginHarness()
    const definition = harness.tools.registered[0] as {
      execute(args: unknown, exec: unknown): Promise<unknown>
    }
    await expect(definition.execute({}, undefined)).rejects.toThrow('"path"')
    await harness.dispose()
  })

  it('sentinel asks on credential access and delegates clean calls', async () => {
    const harness = await createPluginHarness()

    const risky = await dispatchPreExecute(harness.ctx, {
      name: 'bash',
      args: { command: 'cat ~/.ssh/id_rsa' },
    })
    expect(risky.kind).toBe('ask')
    expect(risky.reason).toContain('.ssh')

    const clean = await dispatchPreExecute(harness.ctx, {
      name: 'bash',
      args: { command: 'pnpm test' },
    })
    expect(clean.kind).toBe('allow')
    await harness.dispose()
  })

  it('does not intercept when the sentinel is disabled', async () => {
    const harness = await createPluginHarness({ sentinelEnabled: false })
    const decision = await dispatchPreExecute(harness.ctx, {
      name: 'bash',
      args: { command: 'cat ~/.ssh/id_rsa' },
    })
    expect(decision.kind).toBe('allow')
    expect(harness.info).toHaveBeenCalledWith(expect.stringContaining('sentinel disabled'))
    await harness.dispose()
  })

  it('unregisters the tool and detaches the sentinel on disposal', async () => {
    const harness = await createPluginHarness()
    await harness.dispose()
    expect(harness.tools.unregistered).toHaveLength(1)

    const decision = await dispatchPreExecute(harness.ctx, {
      name: 'bash',
      args: { command: 'cat ~/.ssh/id_rsa' },
    })
    expect(decision.kind).toBe('allow')
  })

  it('registers the invariant companion through its local host contract', async () => {
    const ctx = new Context()
    const unregister = vi.fn()
    const register = vi.fn<(packageName: string, installer: unknown) => () => void>(() => unregister)
    ctx.provide('invariants', { register })

    const fiber = await ctx.plugin(invariant)
    expect(register).toHaveBeenCalledTimes(1)
    expect(register.mock.calls[0]?.[0]).toBe('dsh-plugin-audit')
    expect(typeof register.mock.calls[0]?.[1]).toBe('function')

    await fiber.dispose()
    expect(unregister).toHaveBeenCalledTimes(1)
  })

  it('invariant fails when an audit result loses its read-only marker', async () => {
    const ctx = new Context()
    let installer: ((c: Context, fail: (m: string) => never) => void) | undefined
    ctx.provide('invariants', {
      register: (_name: string, fn: typeof installer) => {
        installer = fn
        return () => undefined
      },
    })
    const fiber = await ctx.plugin(invariant)
    expect(installer).toBeDefined()

    const fail = vi.fn((message: string): never => {
      throw new Error(message)
    })
    installer!(ctx, fail)

    type Decision = { kind: string }
    const dispatch = ctx.waterfall as (
      name: string,
      exec: { name: string },
      result: { value?: { writesPerformed?: boolean } },
      inner: () => Promise<Decision>,
    ) => Promise<Decision>

    // A conforming audit result passes through untouched.
    const ok = await dispatch(
      'tools/post-execute',
      { name: 'plugin_audit' },
      { value: { writesPerformed: false } },
      async () => ({ kind: 'accept' }),
    )
    expect(ok.kind).toBe('accept')
    expect(fail).not.toHaveBeenCalled()

    // A result that lost the marker trips the invariant.
    await expect(dispatch(
      'tools/post-execute',
      { name: 'plugin_audit' },
      { value: { writesPerformed: true } },
      async () => ({ kind: 'accept' }),
    )).rejects.toThrow('read-only marker')
    expect(fail).toHaveBeenCalledTimes(1)

    await fiber.dispose()
  })
})
