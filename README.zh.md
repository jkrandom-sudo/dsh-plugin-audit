# dsh-plugin-audit

[English README](./README.md)

面向 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）的安全审计插件：对第三方插件做静态权限画像，并提供运行时哨兵——当工具调用触及凭证或向未知主机外发数据时先行询问。

## 概览

DSH 生态把「一切皆插件」贯彻到底，而插件雷达明确区分「能跑 ≠ 已审计」。`dsh-plugin-audit` 用两层补齐这个空白：

- **静态审计** —— `plugin_audit` 工具扫描插件目录（源码、`package.json`、`cordis.patch.yml`），输出权限画像卡：代码实际行使了哪些能力（文件读写、子进程、网络、环境变量、凭证路径、动态执行、核心行 patch），附文件/行号证据、`info / notice / review` 风险分级，以及机器可读的 JSON 摘要。扫描器**按契约只读**——每份报告都带 `writesPerformed: false` 标记，另有可选的 invariant 伴随插件在运行时强制执行该约束。
- **运行时哨兵** —— 挂在宿主工具管线 `tools/pre-execute` waterfall 上的监听器，当待执行的工具调用命中以下规则时返回 `ask`（交给宿主原有的审批提示处理）：
  1. 任意工具的参数引用凭证路径（`~/.ssh`、`~/.aws`、`.npmrc`、keychain 等）；
  2. shell 外发命令（`curl`、`wget`、`nc`、`scp` 等）指向 `allowedHosts` 之外的主机；
  3. 向工作区之外的家目录 dotfile 写入。

审计是辅助而非裁决：它呈现实证，把判断留给你。

## 兼容性

| 依赖 | 版本 |
| --- | --- |
| DSH 主线 | 已验证 2026-08-14 快照（`npx @deepseek-ai/dsh`，web profile） |
| Node.js | `^22.19.0 || >=24.0.0` |
| Cordis | `^4.0.0-rc.7`（peer） |

DSH 处于开发者预览期，破坏性变更频繁；上表日期记录本发布验证过的主线快照。`./invariant` 伴随插件已导出但**有意不**接入 `cordis.patch.yml`：官方 web/base profile 不提供 `invariants` 服务，挂起（pending）的行会阻断启动。提供该服务的 profile 可自行添加一行 `{ id: dsh-plugin-audit-invariant, name: 'dsh-plugin-audit/invariant' }`。

## 安装

从 npm 安装（发布后）：

```bash
dsh plugin --profile web add dsh-plugin-audit
```

直接从 GitHub 安装：

```bash
dsh plugin --profile web add github:jkrandom-sudo/dsh-plugin-audit
```

两条命令都会把包注册进 profile 的 `dsh.profile.bundles` 并应用本包的 `cordis.patch.yml`（插入一行 `dsh-plugin-audit`，含 `sentinelEnabled: true`）。重启 profile 后生效。

## 卸载

```bash
dsh plugin --profile web remove dsh-plugin-audit
```

该命令移除依赖与 bundle 行，重启 profile 即可。本插件除 profile 自身的依赖元数据外不做任何写入，无需其他清理。

## 快速上手

在安装了本插件的 profile 会话中，直接对 agent 说：

```
用 plugin_audit 审计 ~/some-third-party-plugin 这个插件
```

或让模型直接调用工具：

```json
{ "path": "/absolute/path/to/plugin", "format": "markdown" }
```

工具返回 Markdown 权限卡（风险分级、能力表、带文件/行号的发现列表）以及 JSON 摘要 `{ markdown, risk, filesScanned, findingsCount, writesPerformed }`。

哨兵无需调用——武装后自动监视会话中的每一次工具调用，命中规则时把调用转到你熟悉的审批提示并附上原因，例如：

> Tool "bash" runs curl toward "collector.unknown.io", which is not in allowedHosts. Outbound data movement needs your confirmation.

## 配置

组合树中的一行（由 bundle patch 自动插入）：

```yaml
- id: dsh-plugin-audit
  name: 'dsh-plugin-audit'
  config:
    sentinelEnabled: true
    allowedHosts:
      - github.com
      - api.github.com
      - raw.githubusercontent.com
      - registry.npmjs.org
      - '*.deepseek.com'
```

| 键 | 默认值 | 作用 |
| --- | --- | --- |
| `sentinelEnabled` | `true` | 总开关。`false` 时保留静态 `plugin_audit` 工具，关闭全部运行时拦截。 |
| `allowedHosts` | 见上 | shell 外发的预批准主机。精确匹配，或前导 `*.` 后缀规则（`*.deepseek.com` 同时匹配裸域名）。 |

说明：

- 宿主无审批通道时，`ask` 决策降级为 `deny`——调用被拦截，绝不静默放行。
- 静态扫描器无需配置，也不参考 `allowedHosts`；它如实报告发现的每一个网络面。

## 权限与数据

- **扫描器只读。** 审计只以读句柄遍历目标目录（上限 400 个文件 / 单文件 256 KB），每份报告携带 `writesPerformed: false`。可选的 `dsh-plugin-audit/invariant` 伴随插件会在 `plugin_audit` 结果丢失该标记时让会话失败。
- **无网络、无遥测。** 本插件自身不发起任何网络请求，不向任何地方发送数据。报告中出现的 URL 主机是从被扫描源码中提取的文本，从不被访问。
- **哨兵决策留在本地。** `ask` 裁决由宿主既有审批提示中介；插件仅通过 `ctx.logger` 记录决策原因。
- **哨兵检查范围：** 经过 `tools/pre-execute` 的工具名与调用参数。它不读取文件、环境变量，也不触碰调用参数之外的会话内容。

## 故障排查

- **启动失败，报 `dsh-plugin-audit/invariant: pending (waiting for service: invariants)`** —— 你把 invariant 行接入了不提供 `invariants` 服务的 profile。移除该行（随包的 `cordis.patch.yml` 默认就不含它）。
- **agent 看不到 `plugin_audit`** —— 确认包已出现在 profile `package.json` 的 `dsh.profile.bundles` 中，且 `--dump-config` 显示 `dsh-plugin-audit` 行；然后重启 profile。
- **正常命令频繁触发询问** —— 把主机加入 `allowedHosts`，或设 `sentinelEnabled: false` 只保留静态审计。
- **扫描到的文件比预期少** —— 遍历上限为 400 个文件、单文件 256 KB，并跳过 `node_modules`、`.git`、`lib`、`dist`。请审计包的源码目录，而不是安装产物。

## 开发

```bash
pnpm install
pnpm typecheck   # 两个 tsconfig
pnpm test        # vitest，23 个测试：scanner、哨兵规则、插件生命周期、invariant
pnpm build       # tsc -b && tsdown -> lib/
```

目录结构：`src/scanner/` 是与 harness 无关的纯引擎（walk → detect → manifest → report），`src/report.ts` 渲染 Markdown 卡，`src/runtime.ts` 将其适配到 Cordis/DSH 工具契约，`src/sentinel/` 存放纯决策规则与 waterfall 监听器，`src/invariant.ts` 是只读强制伴随插件。

**端到端验证**（v0.1.0，2026-08-14 执行）：`pnpm typecheck && pnpm test && pnpm build` 全绿（23/23）后，通过 `dsh plugin --profile web add <路径>` 将本包链接进本机真实 `web` profile，并以与 CLI 完全相同的方式在进程内启动完整组合（bundle patches + 用户层 + home 层，webserver 使用系统分配端口）。全部断言通过：`tools` 服务可解析；`plugin_audit` 已注册进真实 `ToolRuntime`；武装的哨兵对 `cat ~/.ssh/id_rsa` 返回 `ask`、对 `pnpm test` 正常委托；`plugin_audit` 对可疑样本插件完成真实审计（`risk=review`、10 项发现、`writesPerformed=false`）。官方加载器对任何未激活条目都会中止启动，因此组合树零错误启动本身即为加载证据。

## 许可与安全

MIT —— 见 [LICENSE](./LICENSE)。

本插件是审计辅助工具，不是杀毒软件：干净的报告含义是「这些规则未发现证据」，而非「安全」。发现项是带文件/行号证据的启发式结论，供人判断。如果你发现绕过方式（扫描器漏检的能力、可规避的哨兵规则），请在 <https://github.com/jkrandom-sudo/dsh-plugin-audit/issues> 开 issue——不宜公开的内容请先私下报告。
