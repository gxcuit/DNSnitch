# 执行计划：配置自动修复

依据：`prd.md`、`design.md`、`.trellis/spec/backend/*`、`.trellis/spec/frontend/*`。

## 0. 前置（主会话完成）

- [ ] 从 `main` 新建分支 `feat/config-auto-repair`，`task.py set-branch` 记录。
- [ ] agent shell 需 `export PATH="/c/Program Files/Go/bin:$HOME/go/bin:$PATH"`；本机 Python 为 `/c/ProgramData/miniconda3/python.exe`（`python` 指向应用商店占位）。

## 1. 执行顺序

1. `internal/ruleparse`：逻辑子规则 `Span`（相对顶层 `Raw`，嵌套正确）+ 测试（AND / OR / NOT / SUB-RULE 条件、嵌套、含空格）。
2. `internal/config/nodes.go`：`Nodes` / `Doc.Find` / `Target` + 测试（路径含 `.` 的键、`[i]`、别名、`<<` 合并、锚点、BOM 偏移）。
3. `internal/fix/text.go` + 测试：行列→偏移（含多字节字符、CRLF、BOM）、`scalarSpan` 三种样式与校验、加 no-resolve、子规则插入、改键名、block / flow 列表删除与删空替换、跳过原因。
4. `internal/fix/diff.go` + 测试：Myers 差异、hunk 合并与 3 行上下文、首尾边界、行数变化。
5. `internal/fix/fix.go`：`Eligible`、`Build` 两阶段 + 多轮 + CFG-01 回退 + 测试（用假 `CheckFunc` 覆盖迭代与回退）。
6. `internal/app`：`PlanFix` / `DefaultFixOutput` / `SaveFix` / 新 `ErrorKind` + 测试（同文件别名、已存在 / `--force`、原子写入失败不留临时文件、校验失败注入、原文件不变）。
7. `internal/report`：`FixResult` / `BuildFixResult` / `WriteFix`（文本 + JSON）、`auto_fix`、check 提示行、跳过原因与错误文字进 `messages_zh.go` + 测试（JSON 字段、`TestProseOnlyInMessages`）。
8. CLI：`fix` 子命令与新参数、usage；新夹具 `testdata/ac15-fix-*.yaml`（规则、逻辑规则、classical 规则集、flow / block DNS 列表、全明文 nameserver、键名拼错与目标键已存在、锚点 / 合并、多行标量、CRLF + BOM + 注释 + 引号）；e2e 测试覆盖 AC1–AC10。
9. GUI：`PlanFix` / `SaveFix` 绑定 + 可注入 `saveDialog` + `app_test.go`；`wails generate module`；`useFix.ts`、`FixPreview.vue`、`SummaryBar.vue` 按钮、`zh.ts` 界面标签、深浅主题颜色变量。
10. 文档：README「自动修复」一节与「不改任何文件」措辞；`gui/README.md`；spec：`cli-contract.md`（签名、`FixResult`、`auto_fix`、错误矩阵）、`gui-bindings.md`（两个新绑定与写入约束）、`directory-structure.md`（`internal/fix` 与依赖方向）。

## 2. 验证命令

```bash
# 根模块
gofmt -l . && go vet ./... && go test ./...
GOOS=linux  GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
go build -o dnsnitch.exe ./cmd/dnsnitch
./dnsnitch.exe fix testdata/ac1-geoip-without-no-resolve.yaml --dry-run ; echo "exit=$?"
./dnsnitch.exe fix examples/leaky-config.yaml -o "$TMP/out.yaml" ; echo "exit=$?"
./dnsnitch.exe check "$TMP/out.yaml" ; echo "exit=$?"          # 期望 0
git diff --exit-code examples/ testdata/                          # 原文件未被修改
./dnsnitch.exe fix examples/leaky-config.yaml -o examples/leaky-config.yaml ; echo "exit=$?"   # 期望 2
./dnsnitch.exe fix examples/leaky-config.yaml --format json | python -m json.tool >/dev/null
# GUI
(cd gui && gofmt -l . && go vet ./... && go test ./...)
(cd gui/frontend && npm run build)     # vue-tsc 类型检查 + 构建
```

GUI 验收（AC11）：`wails dev` + 浏览器 `http://localhost:34115`，按 `gui-bindings.md` §6 的方式触发拖入 `examples/leaky-config.yaml`；`saveDialog` 在浏览器模式下无法弹窗，用 `await window.go.main.App.PlanFix()` 核对预览数据，保存流程由 `app_test.go` 覆盖，再在 `wails build` 产物中手动点一次保存确认。

## 3. 风险点与回滚

- `internal/config` 的路径解析与 `config.go` 的路径生成必须一致：`nodes_test.go` 对每个夹具遍历所有 finding 位置，断言 `Find` 都能找到且 `Line` 相同。
- 列表删行最容易出错（缩进、注释、CRLF）：AC3 的逐字节比较是关键门槛。
- 回滚点：步骤 1–7 不改变 `check` 行为（除 `auto_fix` 字段与提示行），可单独提交；步骤 9 的 GUI 改动可独立回退。

## 4. 启动前检查

- [ ] `implement.jsonl` / `check.jsonl` 已填写真实条目。
- [ ] 用户已确认最终规划摘要。
