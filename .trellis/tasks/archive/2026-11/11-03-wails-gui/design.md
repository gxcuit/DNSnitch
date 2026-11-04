# 技术设计：dnsleak 桌面 GUI（Wails v2 + Vue 3 + TS）

需求见 `prd.md`；环境见 `research/environment-and-wails.md`；后端约定见 `.trellis/spec/backend/`。

## 1. 目录与模块边界

```
gui/                          独立 Go 模块：module dnsleak/gui
  go.mod                      require dnsleak + github.com/wailsapp/wails/v2 v2.17.1；replace dnsleak => ../
  wails.json                  Wails 项目配置（name: dnsleak-gui, outputfilename: dnsleak-gui）
  main.go                     wails.Run：窗口、文件拖放、绑定 App
  app.go                      App：暴露给前端的方法
  app_test.go                 App 方法测试（不启动 WebView）
  frontend/                   Vue 3 + TS（Vite）
    src/App.vue               布局：顶部操作栏 + 汇总、左侧问题列表、右侧原文视图
    src/components/…          SummaryBar / FindingList / FindingCard / SourceView
    src/wailsjs/              Wails 自动生成的绑定与 TS 类型（生成物，不手改）
  build/                      Wails 构建资源（图标、Windows manifest）
internal/app/                 新增：check 用例的唯一实现，CLI 与 GUI 共用
```

**为什么 GUI 是独立模块**：Wails 在 macOS / Linux 需要 CGO，`gui/main.go` 还用 `//go:embed` 嵌入 `frontend/dist`。如果 `gui/` 放在根模块内，根目录的 `go vet ./...`、`go test ./...` 以及 `GOOS=linux go build ./...` 会把它一起编译，导致失败（没有 dist、无法交叉编译 CGO）。嵌套模块会被根模块的 `./...` 自动排除，CLI 的全部验证命令保持不变（PRD R4.2、AC7）。

**internal 可见性**：Go 的 internal 规则按导入路径判断。`dnsleak/gui` 位于 `dnsleak/` 路径之下，所以可以导入 `dnsleak/internal/...`（与 gopls 模块导入 `golang.org/x/tools/internal` 的方式相同）。已用最小示例验证（research「已核实」一节）。

## 2. 共用的 check 用例（`internal/app`）

把 `cmd/dnsleak/main.go` 中「加载 → 分析 → 出错分类」的逻辑抽成：

```go
package app

type ErrorKind string // "", "read", "parse", "encrypted"

type CheckOutcome struct {
    File     string
    Findings []model.Finding // 已排序
    ErrKind  ErrorKind
    Err      error
}

func RunCheck(file, home string) CheckOutcome // home 为空时取配置文件所在目录
```

- CLI 改用 `app.RunCheck`；输出与退出码保持逐字节不变（现有 e2e 测试必须不改即通过）。
- `internal/app` 只依赖 `config`、`analyze`、`model`，不依赖 `report`。

## 3. 结果结构（`internal/report`）

把现有未导出的 `jsonCheck` / `jsonFinding` / `jsonSummary` 导出为 `CheckResult` / `FindingView` / `Summary`，新增：

```go
func BuildCheckResult(file string, fs []model.Finding) CheckResult
```

- `writeCheckJSON` 改为 `writeJSON(w, BuildCheckResult(...))`，CLI JSON 输出不变。
- GUI 直接返回 `CheckResult`，Wails 自动生成对应 TS 类型。CLI 与 GUI 用同一个函数生成结果，AC6 由构造保证。
- 错误说明也复用 `report.ErrorText`；新增 `ErrKindEncrypted` 的文字（CLI 对加密文件仍输出 CFG-02 Finding，行为不变）。

## 4. 绑定给前端的方法（`gui/app.go`）

```go
type GUIResult struct {
    Result *report.CheckResult `json:"result,omitempty"`
    Error  *GUIError           `json:"error,omitempty"`
}
type GUIError struct {
    Kind    string `json:"kind"`    // read / parse / encrypted
    Message string `json:"message"` // 中文，来自 report.ErrorText
}
type SourceFile struct {
    Path  string   `json:"path"`
    Lines []string `json:"lines"`
}

func (a *App) ChooseFile() (string, error)          // runtime.OpenFileDialog，筛选 *.yaml;*.yml 与所有文件；取消返回 ""
func (a *App) Check(path string) GUIResult          // app.RunCheck(path, "")；加密时返回 Kind=encrypted
func (a *App) ReadSource(path string) (SourceFile, error)
```

- `ReadSource` 只允许读取「最近一次 Check 的配置文件」以及该次结果中某个 Location 引用的文件，其它路径返回错误（防止前端被诱导读取任意文件）。读取后统一去掉 `\r`。
- 文件拖放：`options.App.DragAndDrop = &options.DragAndDrop{EnableFileDrop: true, DisableWebViewDrop: true}`；在 `startup` 中用 `runtime.OnFileDrop(ctx, func(x, y int, paths []string))` 接收路径，再用 `runtime.EventsEmit(ctx, "file-dropped", paths)` 通知前端；前端收到后调用 `Check(paths[0])`，多于一个时提示「只检查第一个」。API 已在 v2.17.1 源码中核实。
- 检查在 Go 的绑定调用里执行。Wails 的绑定调用是异步 Promise，不阻塞界面；前端在等待期间显示加载状态（R3.2）。

## 5. 前端（Vue 3 + TS）

- 状态：`currentFile`、`result: CheckResult | null`、`error: GUIError | null`、`loading`、`selectedLocation`、`source: SourceFile | null`。用组合式 API + 单个 `useCheck()` 组合函数，不引入 Pinia / Vue Router（只有一个页面）。
- 布局：
  - 顶部：「选择配置文件」「重新检查」按钮、当前文件路径、各等级数量徽标；没有「错误 / 高 / 中」时显示绿色「未发现泄露风险」。
  - 左侧：问题卡片列表，按后端给定顺序显示（不在前端重新排序）。卡片显示等级、ID、说明、修复建议、假设说明、位置列表；受影响位置显示解析器分级（来自 `location.resolver`）。
  - 右侧：原文视图，带行号，选中位置时滚动到该行并高亮。
- 文字：问题内容全部来自后端。界面自身的少量标签（按钮名、空状态提示）集中在 `src/i18n/zh.ts`，与后端「提示文字集中管理」的约定一致。
- 样式：手写 CSS 与 CSS 变量，跟随系统深色 / 浅色（`prefers-color-scheme`），不引入 UI 组件库。
- 等级颜色：错误 / 高 = 红，中 = 橙，低 = 蓝，提示 = 灰；同时显示文字等级，不只靠颜色区分。

## 6. 构建

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1   # 安装到 %USERPROFILE%\go\bin
cd gui && wails build                                         # 产出 gui/build/bin/dnsleak-gui.exe
cd gui && wails dev                                           # 开发模式，同时在 http://localhost:34115 提供可在浏览器访问的前端
```

- macOS / Linux：在对应系统安装 Go、Node、Wails CLI（Linux 另装 `libgtk-3-dev`、`libwebkit2gtk-4.1-dev`，构建加 `-tags webkit2_41`）后执行 `wails build`。写入 `gui/README.md`，本期不实际构建（PRD R4.3）。
- `gui/build/bin/`、`gui/frontend/dist/`、`gui/frontend/node_modules/` 加入 `.gitignore`；`gui/frontend/package-lock.json` 提交。

## 7. 换行符

本机全局 `core.autocrlf=true`，以后检出时 `.go` 文件会被转成 CRLF，导致 `gofmt -l` 报告所有文件。在 `.gitattributes` 增加 `* text=auto eol=lf`（Trellis 已有的 `merge=union` 规则保留），所有文本文件统一用 LF。

## 8. 测试与验证

| 层 | 方式 |
|---|---|
| `internal/app` | 单元测试：正常 / 读取失败 / 解析失败 / 加密四种结果 |
| `internal/report` | `BuildCheckResult` 与 CLI JSON 输出逐字节一致 |
| CLI | 现有全部测试不改即通过；交叉编译不变 |
| `gui/app.go` | `go test`（在 `gui/` 内）：`Check` 四种结果、`ReadSource` 的路径白名单 |
| 前端 | `vue-tsc --noEmit` 类型检查 + `vite build` |
| 界面验收 | `wails dev` 启动后，在浏览器打开 `http://localhost:34115`，通过调用 `Check(path)` 验证 AC1、AC3、AC4、AC5；拖入（AC2）和启动 exe（AC8）需要在真实窗口里人工确认 |

## 9. 风险

- **WebView2 下拖放的实际表现**：API 已核实，但只能在真实窗口里验证（AC2 需人工确认）。如果拖放拿不到路径，AC2 降级为只支持按钮选择，并报告给用户。
- **mihomo 依赖与 Wails 依赖冲突**：两者都会拉入 `golang.org/x/*` 等库，在 `gui/go.mod` 里由 Go 的最小版本选择统一，只影响 GUI 模块，不影响根模块。
