# 技术设计：配置自动修复

需求见 `prd.md`；现有约定见 `.trellis/spec/backend/`、`.trellis/spec/frontend/`；no-resolve 语义见 `.trellis/spec/backend/mihomo-semantics.md`。

## 1. 结构

```
internal/ruleparse/   逻辑规则子规则记录在父规则 Raw 中的字节区间（新字段，见 §3）
internal/config/      新增 nodes.go：Doc / Find(path) 按位置路径找回 yaml.Node，并标出锚点 / 别名 / 合并
internal/fix/         新包：修改计划（纯函数，不读写文件，不含提示文字）
  fix.go              Plan / Edit / Skip / Build()、Eligible()
  text.go             按原文字节做最小修改：标量区间、追加 no-resolve、改键名、删除 / 替换列表项
  diff.go             行级 Myers 差异 → unified diff 片段
internal/app/         新增 PlanFix()（编排：读文件 → fix.Build → 校验 → 复查）、SaveFix()（同文件判断 + 原子写入）
internal/report/      FixResult、BuildFixResult、WriteFix；CheckResult.findings[].auto_fix；文字进 messages_zh.go
cmd/dnsnitch/         fix 子命令
gui/app.go            PlanFix() / SaveFix() 绑定
gui/frontend/src/     composables/useFix.ts、components/FixPreview.vue；SummaryBar 加按钮
```

依赖方向（新增部分）：`app → fix → config, ruleparse, model`；`report → fix`（只用数据类型）；`cmd, gui → app, report`。`fix` 不依赖 `analyze` / `app`：重新检查通过 `Build` 的回调参数注入，避免环。

## 2. 修改流程（`fix.Build`）

```go
type CheckFunc func(data []byte) ([]model.Finding, error) // 由 app 提供：config.Parse + analyze，同一 home

func Build(file string, data []byte, check CheckFunc) (*Plan, error)
```

1. **规则阶段**（最多 8 轮）：`check(当前文本)` → 取 `Eligible` 的 RULE-01..04 与 CFG-01 → 生成字节级修改 → 应用 → 下一轮。某轮没有新修改即停止。这些修改都不增减行，行号始终等于原文件行号。
2. **DNS 阶段**（一轮）：对规则阶段结束时的检查结果中的 DNS-02 / DNS-09 生成列表修改（可能删行）。同一列表的多个修改合并为一次。所有修改按字节偏移从后往前应用。
3. **CFG-01 回退**：对最终文本 `check`，出现原文件没有的 `error` 级结果（按 ID + 首个位置路径比较）时，撤销全部 CFG-01 修改并记为跳过（原因 `rename-breaks-load`），重新执行 1–2。只有改键名会让本来被忽略的设置生效、从而引出新错误；加 no-resolve 和删除明文 DNS 不会。
4. 返回 `Plan{Original, Fixed, Edits, Skips, Hunks, Passes}`。`Fixed == Original` 时 `Edits` 为空。

`Eligible(f)`（同时用于 check 的 `auto_fix`）：

| ID | 条件 |
|---|---|
| RULE-01 / 02 | `Args["kind"] == "always"` 且 `Severity > Info` |
| RULE-03 / 04 | `kind` 为 `always` 或 `conditional`，且 `Severity > Info` |
| DNS-02 / DNS-09 | 总是 |
| CFG-01 | `suggest != ""` 且 `anchor != "true"` |

每条可修结果最终要么出现在 `Edits`，要么出现在 `Skips`，不会两边都没有。唯一例外：SUB-RULE 条件里引用的 classical 规则集若已由其 sub-rules 链自身的 RULE-03 / RULE-04 修好，SUB-RULE 那条结果在复查中消失，不再记为跳过（实现：`reasonViaChain`）。

## 3. 定位与原文修改

### 3.1 节点定位（`config.Doc.Find`）

`config.Nodes(data) (*Doc, error)` 解析一次 `yaml.Node` 树（剥 BOM 前记下偏移量 `bomLen`）。`Find(path)` 按 `internal/config/config.go` 生成的路径格式走树：`.` 分段、`[i]` 索引；映射键可能含 `.`（如 `sub-rules.a.b[0]`），在映射上取能匹配剩余路径的最长键。复用 `pairs()` 的合并规则，结果为：

```go
type Target struct {
    Node, Key, Parent *yaml.Node // Parent：所在序列或映射
    ViaAlias, ViaMerge, Anchored bool
}
```

`ViaAlias || ViaMerge || Node.Anchor != ""` → 跳过（`shared-node`）。

### 3.2 行列 → 字节偏移

yaml.v3 的 `Line` / `Column` 从 1 开始，`Column` 按字符（rune）计。偏移 = `bomLen` + 该行起点 + 前 `Column-1` 个 rune 的字节数。行切分同时识别 `\n` 与 `\r\n`。

### 3.3 标量区间与校验

`scalarSpan` 返回标量在原文中的 `[start, end)`（不含引号）与样式：

- plain：到行尾，遇到「空白 + `#`」截断，去掉行尾空白与 `\r`。
- 单引号：到不跟着 `'` 的 `'`；双引号：到未转义的 `"`。
- `Literal` / `Folded` 样式、区间跨行 → 跳过（`multiline`）。
- **校验**：区间文本（单引号把 `''` 还原、双引号解转义）必须等于 `Node.Value`；不等即跳过（`layout`）。只有「原文字符与值一一对应」（无转义）时才允许做 RULE-04 的内部插入。

### 3.4 各类修改

| 修改 | 做法 |
|---|---|
| 规则加 no-resolve | 在区间末尾（引号内）插入 `,no-resolve`；规则已含 `no-resolve`（大小写不敏感）则不改 |
| RULE-04 子规则 | `ruleparse` 为每个逻辑子规则记录在顶层 `Raw` 中的 `[Start, End)`（新字段 `model.Rule.Span`，嵌套时相对顶层）；在触发点子规则的 `End` 处（右括号前）插入 `,no-resolve`。触发点子规则由 finding 的 `trigger-entry` 位置的 `Text` 匹配 `Subs` 递归查找；同一文本出现多次时取第一个未带 no-resolve 的 |
| 改键名 | 替换键标量区间；目标键在 `Target.Parent` 中已存在 → 跳过（`key-exists`） |
| 删除 block 列表项 | 删掉整行（含行尾换行符）；要求该行只有这一项（`-` 在 `Column-2` 处且前面只有空白） |
| 删除 flow 列表项 | `[` 与 `]` 必须在同一行，否则跳过（`multiline`）；用剩余项的原文以 `, ` 重新拼接 `[...]` |
| 列表删空 | `nameserver` / `proxy-server-nameserver`：保留第一项所在行，值换成 `https://223.5.5.5/dns-query`（flow：`[https://223.5.5.5/dns-query]`）；`fallback`：block 列表删光所有项并在键的冒号后插入 ` []`，flow 写成 `[]` |

位置文件不是被检查的配置（如规则集文件）→ 跳过（`other-file`）。

### 3.5 差异

`diff.go` 对原文与结果按行做 Myers O(ND) 差异（改动少，D 很小），输出 3 行上下文的 hunk：`Hunk{OldStart, OldLines, NewStart, NewLines, Lines []DiffLine{Op, Text}}`。文本输出与 GUI 共用这一结构；文本模式按 unified diff 渲染，`---`/`+++` 用原文件与输出路径。

## 4. 用例层（`internal/app`）

```go
type FixOutcome struct {
    File, Output string
    Plan         *fix.Plan
    Before       []model.Finding // 原文件检查结果
    After        []model.Finding // 修复结果检查结果
    SourceHash   [32]byte         // 原文 sha256，GUI 保存前比对
}
func PlanFix(file, home string) (FixOutcome, ErrorKind, error)
func DefaultFixOutput(file string) string                     // config.yaml → config.fixed.yaml
func SaveFix(out FixOutcome, dest string, force bool) (ErrorKind, error)
```

- `PlanFix`：读文件 → 已加密 / 解析失败沿用现有 `ErrorKind`；`fix.Build` 的 `CheckFunc` 用与 `RunCheck` 相同的 `LoadEnv` 逻辑（同一 home）。修复结果解析失败或仍有新增 `error` 结果 → `ErrKindVerify`。
- `SaveFix`：`dest` 绝对化；`os.Stat(dest)` 与原文件 `os.SameFile` → `ErrKindSameFile`；`dest` 存在且 `!force` → `ErrKindExists`；在 `dest` 同目录建临时文件、写入、`Sync`、关闭、`os.Rename`（Windows 上目标存在时 `os.Rename` 会替换）；失败删除临时文件 → `ErrKindWrite`。`Plan.Edits` 为空时不写。
- 新 `ErrorKind`：`verify` `same-file` `exists` `write` `changed`（GUI 用），文字在 `report.ErrorText`。

## 5. 输出契约（`internal/report`）

`report.FixResult`（CLI JSON 与 GUI 绑定共用）：

| 字段 | 说明 |
|---|---|
| `file` / `output` | 原文件、输出路径（`--dry-run` 时为将写入的路径） |
| `written` | 是否已写入 |
| `not_written_reason` | `dry-run` / `nothing-to-fix` / ``（已写入） |
| `edits[]` | `{id, line, path, before, after}`；`before`/`after` 为该行修改前后的完整行文本（删除时 `after` 为空） |
| `skipped[]` | `{id, line, path, reason, reason_text}`；`reason` ∈ `shared-node` `multiline` `layout` `key-exists` `other-file` `rename-breaks-load` `pass-limit` |
| `diff[]` | hunk 数组（§3.5） |
| `before` / `after` | 修复前 / 后的 `summary`（各等级计数） |
| `remaining[]` | 修复结果的检查结果，结构同 `CheckResult.findings[]` |

`CheckResult.findings[].auto_fix bool` = `fix.Eligible(f)`。检查文本输出在汇总行后、N > 0 时加一行提示。退出码：`fix` 为 `ExitCode(After)`；错误为 2。

## 6. CLI

`parseArgs` 增加 `-o/--output <path>`、`--force`、`--dry-run`（仅 `fix` 接受，其它子命令出现即参数错误，退出码 2）。`run` 中 `fix` 分支：`app.PlanFix` → 若非 dry-run 且有修改则 `app.SaveFix` → `report.WriteFix` → 退出码。

## 7. GUI

```go
func (a *App) PlanFix() GUIFixResult   // 对最近一次 Check 的配置做 PlanFix；把 SourceHash 存进 a.fixHash（mu 保护）
func (a *App) SaveFix() GUISaveResult  // 重新 PlanFix；hash 与 a.fixHash 不同 → kind "changed"
                                       // saveDialog(ctx, 默认目录/文件名)；取消 → {cancelled:true}
                                       // app.SaveFix(out, path, true)（对话框已确认覆盖）；返回 {path}
```

- 没有参数：写入内容与目标路径都不来自前端（PRD R4.5）。`saveDialog` 为可注入的包级变量（与 `inspectSystem` 相同做法），测试不弹窗。
- 前端：`useFix.ts` 管理预览状态；`FixPreview.vue` 显示修改项、跳过项、差异（`+`/`-` 行用 `--diff-add-*` / `--diff-del-*` 颜色变量，深浅主题各一套）、修复前后汇总；保存成功后调用现有 `useCheck` 的检查入口打开新文件。`SummaryBar` 在 `findings.filter(f => f.auto_fix).length > 0` 时显示按钮。
- 新绑定后 `wails generate module` 并提交生成文件。

## 8. 兼容与回滚

- 所有改动都是新增：`check` 的 JSON 只加字段、文本只在末尾加一行；`trace` / `status` 不变。
- 不写原文件，最坏情况是新文件内容不理想，用户删掉即可。
- 回滚：去掉 `fix` 子命令与 GUI 按钮即可，`internal/fix` 不被其它功能依赖（`auto_fix` 字段一并去掉）。

## 9. 取舍

- **原文最小修改 vs 重新序列化 YAML**：yaml.v3 重新输出会改缩进、引号、折行，订阅配置会出现上百行无关差异。按节点行列做字节修改，配合「区间文本必须等于节点值」的校验，做不到的情况跳过而不是冒险。
- **加 no-resolve vs 调整规则顺序**：加 no-resolve 是局部修改、语义确定；移动规则会改变匹配顺序，影响面不可控。代价：被加上 no-resolve 的 IP 规则不再按 IP 归属分流域名请求（如 `GEOIP,CN,DIRECT` 之后可能出现 RULE-05 提示），这会在输出的剩余结果里体现。
- **多轮迭代**：一条逻辑规则 / 规则集修好一个触发点后可能暴露下一个，用检查器本身判断是否修完，比在修复器里重复实现触发判定更不容易出错。
