# 执行计划：mihomo 配置 DNS 泄露静态检查 (P1)

依据：`prd.md`（需求与验收）、`design.md`（结构与算法）、`research/mihomo-dns-semantics.md`（mihomo 行为）。

## 0. 前置条件（由用户在 `task.py start` 前完成）

- [ ] 安装 Go（最新稳定版），`go version` 可用。
- [ ] 项目根目录 `git init`（Phase 3.4 提交需要）。

## 1. 执行顺序

每一步结束时 `go build ./...` 与 `go test ./...` 必须通过，再进入下一步。

1. **初始化与依赖验证**
   - `go mod init dnsleak`（模块名暂定，可在评审时改）；添加 GPL-3.0 `LICENSE`。
   - 引入 `github.com/metacubex/mihomo`，版本固定到提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` 的伪版本；写一个测试：用 `trie` 构建域名集合 → `WriteBin` → zstd 包装成 mrs → 用本项目的读取函数读回并匹配。ipcidr 同理用 `cidr`。
   - 若无法编译：按 design 第 13 节退路，把所需文件复制到 `internal/third_party/mihomo/` 并保留版权声明，然后继续。
2. **model**：Location、Severity、Finding、Rule、RuleProvider、Policy、DNSServer。
3. **config**：读文件、age 检测、yaml.v3 Node → model（含锚点 / 合并键、行号）、键名白名单与相近键建议（CFG-01 / CFG-02）。
4. **ruleparse**：普通规则、classical 条目、逻辑规则括号嵌套、`no-resolve` / `src`。用 research 第 1 节中的规则类型全集做表驱动测试。
5. **policy**：节点与策略组展开、分类、环检测、CFG-03。
6. **dnsserver**：地址解析（含无 scheme、IPv6、`#名称&k=v` 片段）、分级、`knownservers.go`。
7. **ruledata**：yaml / text / mrs 规则集读取；缓存路径查找（含 md5 文件名）；GeoSite.dat 的 protowire 解码与匹配。
8. **analyze**：触发分类（design 9.1）→ 规则链扫描（9.2）→ 解析器推断（9.3）→ 独立检查（9.4）→ 等级合成。
9. **trace**：design 第 10 节。
10. **report + CLI**：中文文本、JSON、排序与汇总、`check` / `trace` 子命令、`--format`、`--home`、退出码。
11. **验收用例**：`testdata/` 下为 AC1–AC12、AC14 各准备一份配置（及所需规则集缓存文件 / 测试中生成的 mrs），写端到端测试断言 Finding 的 ID、等级、行号与退出码。GeoSite.dat 测试数据在测试中用 protowire 生成，不提交真实的大文件。

## 2. 验证命令

```bash
gofmt -l .                  # 输出必须为空
go vet ./...
go test ./...
GOOS=linux  GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
GOOS=windows GOARCH=amd64 go build -o dnsleak.exe ./cmd/dnsleak
./dnsleak.exe check testdata/ac1-geoip-without-no-resolve.yaml ; echo "exit=$?"
./dnsleak.exe trace testdata/ac1-geoip-without-no-resolve.yaml www.youtube.com
```

## 3. 评审关注点

- 触发分类必须与 research 第 1 节逐条一致（尤其是 classical 的 `Except`、AND 的 `Guard`、RULE-SET 的 `no-resolve` 覆盖整个集合）。
- 解析器推断不得使用 `direct-nameserver`；fallback 必须与 nameserver 一起计入。
- 所有面向用户的文字都在 `messages_zh.go`，其它文件里没有中文提示字符串。
- 不出现操作系统相关代码或硬编码路径分隔符。

## 4. 风险文件与回滚点

- `go.mod` / `go.sum`：引入 mihomo 依赖是唯一的外部风险点（第 1 步）。失败时按退路处理，不要因此跳过 `.mrs` 支持（AC14）。
- 本期只新增文件；任何一步出问题，回退该步新增的包即可。
