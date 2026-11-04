# 环境与 Wails 版本调研（2026-11-03）

## 本机环境（Windows 11）

| 项 | 状态 |
|---|---|
| Go | 1.27.3，`C:\Program Files\Go\bin`（agent shell 需 `export PATH="/c/Program Files/Go/bin:$PATH"`） |
| Node.js / npm | v24.18.1 / 11.16.0 |
| WebView2 Runtime | 156.0.4314.58（已安装，注册表 `EdgeUpdate\Clients\{F3017226-...}`） |
| Wails CLI | 未安装 |
| Python（Trellis 脚本） | `C:\ProgramData\miniconda3\python.exe` |

## Wails 版本（`go list -m -versions`）

| 版本线 | 最新稳定版 | 发布时间 | 说明 |
|---|---|---|---|
| v2 | v2.17.1 | 2026-11-01 | 成熟，长期使用；单窗口模型 |
| v3 | v3.1.0 | 2026-11-01 | v3.0.0 于 2026-10-26 才发布正式版（此前 beta.0–beta.34）；nightly 仍在快速迭代 |

## 平台约束（两版相同）

- Windows：使用系统 WebView2，不需要 CGO，可在 Windows 本机直接构建。
- macOS / Linux：需要 CGO，必须在对应系统上构建；Linux 需要 webkit2gtk 开发包。所以 GUI 不能像 CLI 那样在 Windows 上一条命令交叉编译。
- 前端用网页技术编写，构建需要 Node.js。

## 已核实（2026-11-03）

- **Wails v2.17.1 源码**（`%USERPROFILE%\go\pkg\mod\github.com\wailsapp\wails\v2@v2.17.1`）：
  - `pkg/options/options.go:203-209`：`DragAndDrop{EnableFileDrop bool; DisableWebViewDrop bool}`，开启后拖入文件可拿到绝对路径。
  - `pkg/runtime/draganddrop.go:9`：`OnFileDrop(ctx, func(x, y int, paths []string))`；`:35` `OnFileDropOff(ctx)`。
  - `pkg/runtime/dialog.go:44`：`OpenFileDialog(ctx, OpenDialogOptions) (string, error)`。
- **嵌套模块导入父模块 internal**：在临时目录建 `module demo`（含 `internal/x`）与嵌套 `module demo/sub`（`replace demo => ../`），`go run .` 成功导入 `demo/internal/x`。因此 `gui/`（`module dnsleak/gui`）可以直接导入 `dnsleak/internal/...`。

## 仍需在实现时确认

- Go 方法绑定生成的 TS 类型对嵌套结构体（`report.CheckResult` → `model.Location` → `ResolverInfo`）的支持情况。
