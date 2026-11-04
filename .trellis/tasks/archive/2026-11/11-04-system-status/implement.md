# 执行计划：系统状态检测

依据：`prd.md`、`design.md`、`research/tun-and-smart-resolution.md`、`.trellis/spec/backend/*`、`.trellis/spec/frontend/*`。

## 0. 前置（主会话完成）

- [ ] 从 `main` 新建分支 `feat/system-status`，`task.py set-branch` 记录。
- [ ] **TUN 采样**：请用户在 mihomo-party 中打开 TUN，主会话只读执行 `Get-NetAdapter` / `Get-NetIPAddress` / `Find-NetRoute 1.1.1.1`，记录 wintun 网卡的名称、描述、IfType、地址与出口；结果写入 research，然后用户可关闭 TUN。
- [ ] agent shell 需 `export PATH="/c/Program Files/Go/bin:$HOME/go/bin:$PATH"`。

## 1. 执行顺序

1. `internal/platform`：`status.go`、`facts.go`、`Decide` + `status_test.go`（全组合，含采样得到的 wintun 网卡数据）+ `readonly_test.go`。
2. `inspect_windows.go` / `inspect_other.go`；在本机运行一次 `Inspect()` 的手动测试程序（放 scratchpad，不入库）确认 Smart = disabled、TUN 与当前客户端状态一致。
3. `internal/report`：`StatusView`、`BuildStatusView`、`WriteStatus`、`StatusExitCode`、`messages_zh.go` 文字；测试。
4. CLI `status` 子命令 + usage + e2e 测试（用可注入的 `inspect` 函数，测试不依赖本机状态）。
5. GUI：`SystemStatus` 绑定 + `wails generate module`；`useSystemStatus.ts`、`SystemStatusBar.vue`；`zh.ts` 只加界面标签。
6. 更新 `gui/README.md`（新增状态区说明）。

## 2. 验证命令

```bash
# 根模块
gofmt -l . && go vet ./... && go test ./...
GOOS=linux  GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
go build -o dnsleak.exe ./cmd/dnsleak && ./dnsleak.exe status ; echo "exit=$?"
./dnsleak.exe status --format json
# GUI
(cd gui && gofmt -l . && go vet ./... && go test ./...)
(cd gui/frontend && npx vue-tsc --noEmit && npm run build)
(cd gui && wails build)
```

界面验收：`wails dev` + 浏览器 `http://localhost:34115`，检查状态区显示、刷新、深浅色；AC2 的 TUN 切换由用户确认。

## 3. 评审关注点

- `internal/platform` 中没有任何写入 / 执行类调用，注册表只用 `QUERY_VALUE`。
- `check` / `trace` 测试不修改即通过；`dnsleak check` 输出不变。
- 所有文字在 `messages_zh.go` / `zh.ts`；`platform` 只输出判定码。
- `GetBestInterfaceEx` 只查路由，不发包。

## 4. 回滚点

新增包与新子命令相互独立；回退 `feat/system-status` 分支即可。
