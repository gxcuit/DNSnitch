# 执行计划：dnsleak 桌面 GUI

依据：`prd.md`、`design.md`、`research/environment-and-wails.md`、`.trellis/spec/backend/*`。

## 0. 前置（`task.py start` 前后由主会话完成）

- [ ] 从 `main` 新建分支 `feat/wails-gui`，并用 `task.py set-branch` 记录，归档时不再需要跳过分支校验。
- [ ] Go 不在 agent shell 的 PATH 里：每条命令前加 `export PATH="/c/Program Files/Go/bin:$HOME/go/bin:$PATH"`。

## 1. 执行顺序

1. **换行符**：`.gitattributes` 增加 `* text=auto eol=lf`（保留已有的 journal `merge=union` 规则），执行 `git add --renormalize .` 并确认没有内容变化之外的差异。
2. **后端重构（根模块）**
   - 新增 `internal/app`：`RunCheck(file, home) CheckOutcome`（design §2）及单元测试。
   - `internal/report`：导出 `CheckResult` / `FindingView` / `Summary` 与 `BuildCheckResult`；`writeCheckJSON` 改为调用它；新增 `ErrKindEncrypted` 文字。
   - `cmd/dnsleak/main.go` 改用 `app.RunCheck`。
   - 门槛：现有全部测试**不修改**即通过；根模块验证命令（见第 2 节 A）全部通过。
3. **GUI 骨架**
   - `go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1`。
   - 在 `gui/` 用 vue-ts 模板初始化（`wails init -n dnsleak-gui -t vue-ts` 生成到临时目录后搬入 `gui/`，或手动建立同等结构），把模块名改为 `dnsleak/gui`，加 `require dnsleak` + `replace dnsleak => ../`。
   - 确认 `wails build` 能产出空壳 exe。
4. **Go 绑定**：`gui/app.go`（ChooseFile / Check / ReadSource + 路径白名单）、`gui/main.go`（窗口标题「dnsleak — mihomo DNS 泄露检查」、默认大小约 1200×800、DragAndDrop、OnFileDrop → EventsEmit）、`gui/app_test.go`。
5. **前端**：`useCheck()` 组合函数；SummaryBar、FindingList、FindingCard、SourceView 组件；`src/i18n/zh.ts`；深色 / 浅色主题；加载与错误状态。
6. **文档与忽略规则**：`gui/README.md`（Windows 构建、开发模式、macOS / Linux 构建前置条件）；`.gitignore` 增加 `gui/build/bin/`、`gui/frontend/dist/`、`gui/frontend/node_modules/`；根 README 不在本期范围。
7. **界面验收**：`wails dev` 后用浏览器访问 `http://localhost:34115`，按第 2 节 C 逐条验证。

## 2. 验证命令

**A. 根模块（CLI，必须与改动前一样通过）**
```bash
gofmt -l .
go vet ./...
go test ./...
GOOS=linux  GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
```

**B. GUI 模块**
```bash
cd gui && gofmt -l . && go vet ./... && go test ./...
cd gui/frontend && npm ci && npx vue-tsc --noEmit && npm run build
cd gui && wails build        # 产出 gui/build/bin/dnsleak-gui.exe
```

**C. 界面验收（`wails dev` + 浏览器）**
- AC1 / AC3 / AC4 / AC5：在页面中调用 `window.go.main.App.Check("<绝对路径>")` 或通过界面状态注入路径，检查汇总、卡片、跳转高亮、错误说明。
- AC6：对同一文件比较 `Check` 返回的 `result` 与 `dnsleak check --format json` 的输出（忽略 `file` 字段的路径写法差异）。
- AC2（拖入）与 AC8（双击 exe 启动）：由用户在真实窗口中确认。

## 3. 评审关注点

- `internal/` 不得出现任何 Wails 依赖；根模块 `go.mod` 不得新增 Wails。
- `ReadSource` 白名单不能被绕过（相对路径、`..`、大小写不同的同一路径）。
- 前端不重新排序、不改写后端给出的问题文字。
- 生成的 `wailsjs/` 绑定不手改。

## 4. 回滚点

- 第 2 步的后端重构单独成一次提交；若 GUI 失败，可只保留或回退这一步。
- `gui/` 是独立目录与模块，整个删除即可回滚 GUI。
