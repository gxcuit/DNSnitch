# dnsnitch GUI（Wails v2 + Vue 3 + TypeScript）

dnsnitch 的桌面窗口：选择或拖入一份 mihomo 配置文件，显示与 `dnsnitch check` 相同的检查结果，并可在右侧对照配置原文；能自动修复的项可以预览差异后另存为新文件（与 `dnsnitch fix` 相同，原配置文件不会被修改）。

## 目录与模块

- `gui/` 是独立的 Go 模块 `dnsnitch/gui`（`replace dnsnitch => ../`），所以根目录的 `go vet ./...`、`go test ./...` 与交叉编译不会碰到 Wails / CGO 依赖。
- 检查逻辑全部来自根模块：`internal/app.RunCheck` 执行检查，`internal/report.BuildCheckResult` 生成结果（与 `dnsnitch check --format json` 同一个函数），所有提示文字都在 `internal/report/messages_zh.go`。
- `app.go`：绑定给前端的方法 `ChooseFile` / `Check` / `ReadSource` / `Labels` / `SystemStatus` / `PlanFix` / `SaveFix`。`ReadSource` 只能读取最近一次 `Check` 的配置文件以及检查结果中引用的文件；相对路径、其他文件都会被拒绝。
- 系统状态区（窗口顶部，`SystemStatusBar.vue` + `useSystemStatus.ts`）：启动时自动检测一次，点击「刷新」重新检测，与是否打开配置文件无关。显示「智能多宿主名称解析」是否已禁用、「TUN 模式」是否实际开启（存在已启用的 wintun 网卡且它是公网出口），以及两者的组合结论；TUN 已开启且未禁用时标红并展开处理方法。数据来自 `SystemStatus` 绑定，与 `dnsnitch status --format json` 是同一个 `report.BuildStatusView`。检测完全只读（`internal/platform`）：处理方法只显示文字，界面上没有任何执行或修改系统设置的按钮。Linux / macOS 显示「暂不支持」。
- 自动修复（`FixPreview.vue` + `useFix.ts`），见下文「自动修复预览」。
- `frontend/src/i18n/zh.ts`：界面自身的按钮、标题等文字。问题说明、等级名、角色名、错误说明都由后端提供，前端不重复、不改写、不重新排序。
- `frontend/wailsjs/`：Wails 生成的绑定与 TS 类型（`wails build` / `wails dev` / `wails generate module` 会重新生成），不要手改。修改 `app.go` 的方法或返回结构后执行 `wails generate module` 并提交结果。

### 自动修复预览

与 `dnsnitch fix` 相同的修复（给触发解析的 IP 规则加 no-resolve、删除明文 DNS、改正拼错的键名），只写到新文件，原配置文件不会被修改。

- 检查结果中有可自动修复的项（`auto_fix` 为 true）时，汇总栏出现「自动修复（N 项）」按钮，N 为这类检查结果的条数。
- 点击后调用 `PlanFix()`：Go 侧对**最近一次 `Check` 的配置**执行 `app.PlanFix`（与 CLI 相同的修复与复查），返回与 `dnsnitch fix --dry-run --format json` 相同的 `report.FixResult`，并把结果保存在 Go 侧。预览显示将修改的项（检查结果 ID、行号、修改前 → 修改后）、未修改的项及原因、带颜色的差异（`@@` 段头、`+` / `-` 行，可横向滚动，深浅主题各一套 `--diff-*` 颜色）、修复前后各等级的数量。
- 「保存修复后的配置…」调用 `SaveFix()`：打开系统保存对话框（默认目录为配置所在目录，默认文件名与 CLI 相同：`config.yaml` → `config.fixed.yaml`），写入 `PlanFix` 时算好的内容（临时文件 + 重命名）。保存成功后界面自动检查新文件并切换到它的结果；取消对话框则什么都不做。
- 前端不能指定写入的内容或路径：两个绑定都没有参数，内容由 Go 侧计算，路径只来自系统保存对话框。
- 拒绝保存的情况（错误显示在预览底部）：预览之后原配置被修改过（提示重新检查）；在对话框里选了原配置文件本身（含大小写不同等别名）；预览之后又检查了别的文件或重新检查（旧预览失效，需重新打开）。对话框已经确认过覆盖，所以选已存在的其他文件会被覆盖。
- 浏览器（`wails dev` 的 <http://localhost:34115>）里也可以打开预览，或在控制台调用 `await window.go.main.App.PlanFix()`；保存对话框会弹在桌面窗口上。保存流程的自动测试在 `app_test.go`（`saveDialog` 可注入）。

### `frontend/dist` 与 `//go:embed`

`main.go` 用 `//go:embed all:frontend/dist` 嵌入构建好的前端。为了在还没构建前端时 `go vet` / `go test` 也能编译：

- `frontend/dist/.gitkeep` 被提交到仓库（`.gitignore` 忽略 `dist/*` 但保留这个文件）；
- `frontend/public/.gitkeep` 会被 Vite 在每次构建时复制到 `dist/`，所以 `vite build` 清空 `dist/` 后它会被重新创建，工作区不会出现删除记录。

只运行 `go vet` / `go test` 时不需要先构建前端；真正运行的程序请用 `wails build` / `wails dev` 构建（它们会先构建前端）。

## 准备（所有平台）

- Go 1.27+、Node.js 20+（含 npm）
- Wails CLI：`go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1`（安装到 `$(go env GOPATH)/bin`，需在 PATH 中）
- `wails doctor` 可检查本机依赖

## Windows

需要 WebView2 运行时（Windows 10/11 一般已自带）。不需要 CGO。

```bash
cd gui
wails build        # 产出 gui/build/bin/dnsnitch-gui.exe（单个 exe）
```

## 开发模式

```bash
cd gui
wails dev
```

- 会打开桌面窗口，并在 <http://localhost:34115> 提供同一个前端。用浏览器打开该地址时，绑定的 Go 方法照常可用（在开发者工具里可直接调用，例如 `window.go.main.App.Check("C:/path/to/config.yaml")`）。
- 在浏览器里不能拖入文件（拖放需要 WebView2 提供文件的绝对路径），请用「选择配置文件」按钮或在控制台调用 `Check`。
- Wails v2.17 的开发服务器会拒绝非 localhost 的 Host。如果日志出现 `Host "wails.localhost:34115" is not an allowed host`（桌面窗口的 Vite 热更新连接），功能不受影响；需要热更新时可设置 `WAILS_DEV_ALLOWED_HOSTS=wails.localhost` 后再运行 `wails dev`。

## 前端单独检查

```bash
cd gui/frontend
npm ci
npx vue-tsc --noEmit   # 类型检查
npm run build          # 类型检查 + vite build
```

## Go 检查

```bash
cd gui
gofmt -l .
go vet ./...
go test ./...
```

## macOS / Linux（需在对应系统上构建，本期未实际产出）

Wails 在 macOS / Linux 上需要 CGO，不能从 Windows 交叉编译 GUI；CLI 不受影响。

- **macOS**：安装 Xcode Command Line Tools（`xcode-select --install`）、Go、Node.js、Wails CLI，然后
  ```bash
  cd gui && wails build        # 产出 gui/build/bin/dnsnitch-gui.app
  ```
- **Linux**（以 Debian / Ubuntu 为例）：
  ```bash
  sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev
  cd gui && wails build -tags webkit2_41   # 产出 gui/build/bin/dnsnitch-gui
  ```
  较旧的发行版只有 `libwebkit2gtk-4.0-dev` 时去掉 `-tags webkit2_41`。
