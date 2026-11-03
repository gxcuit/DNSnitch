package report

import (
	"fmt"
	"strings"

	"dnsleak/internal/model"
)

// All user-facing prose lives in this file, keyed by finding ID / note key /
// code, so that an English messages_en.go can be added later.

var severityZh = map[model.Severity]string{
	model.Error:  "错误",
	model.High:   "高",
	model.Medium: "中",
	model.Low:    "低",
	model.Info:   "提示",
}

var roleZh = map[string]string{
	model.RoleTrigger:      "触发规则",
	model.RoleTriggerEntry: "触发条目",
	model.RoleAffected:     "受影响",
	model.RoleResolver:     "解析器",
	model.RoleConfig:       "配置项",
	model.RoleRelated:      "相关",
}

// levelZh names a resolver level (matrix column).
var levelZh = map[string]string{
	"plain":   "明文 DNS",
	"cn":      "国内加密 DNS",
	"foreign": "国外或未知的加密 DNS",
	"safe":    "经代理或安全的 DNS",
}

// serverZh names a single server grade (dnsserver.ServerCode).
var serverZh = map[string]string{
	"plain":       "明文",
	"enc-cn":      "加密·国内",
	"enc-foreign": "加密·国外",
	"enc-unknown": "加密·未知",
	"proxy":       "经代理",
	"rules":       "经代理（respect-rules）",
	"safe":        "安全（不向外查询）",
}

var sourceZh = map[string]string{
	"system":        "系统 DNS（mihomo DNS 未启用）",
	"policy":        "nameserver-policy",
	"fallback-only": "fallback（命中 fallback-filter）",
	"default":       "nameserver ∪ fallback",
}

var classZh = map[string]string{
	"proxy":    "代理",
	"direct":   "直连",
	"reject":   "拒绝",
	"pass":     "PASS",
	"sub-rule": "子规则",
}

var reasonZh = map[string]string{
	"not-defined":     "rule-providers 中没有定义该规则集",
	"no-file":         "本地缓存文件不存在",
	"no-source":       "规则集既没有 payload，也没有 path / url",
	"read-error":      "规则集文件无法读取",
	"parse-error":     "规则集文件无法解析",
	"bad-format":      "规则集格式与 behavior 不匹配或不受支持",
	"bad-behavior":    "规则集 behavior 无效",
	"geosite-missing": "GeoSite.dat 不存在",
	"geosite-error":   "GeoSite.dat 无法读取或已损坏",
	"geosite-no-list": "GeoSite.dat 中没有该分类",
	"ip-assumed":      "解析出的 IP 无法静态得知，按不命中继续",
	"no-resolve":      "带 no-resolve，域名请求不做匹配",
	"conn-info":       "取决于进程、端口等连接信息，按不命中继续",
	"regex":           "正则表达式无法解析",
	"depth-limit":     "嵌套过深",
}

var sectionZh = map[string]string{
	"":                    "顶层",
	"dns":                 "dns 段",
	"dns.fallback-filter": "dns.fallback-filter 段",
}

func zh(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return k
}

// scopeZh describes which domains get resolved.
func scopeZh(a model.Args) string {
	rules := fmt.Sprintf("其后指向代理的域名规则（%s 条）所匹配的域名", a["count"])
	unknown := fmt.Sprintf("未被前面规则匹配、由 %q 兜底走代理的域名", a["match"])
	switch a["scope"] {
	case "unknown":
		return unknown
	case "both":
		return rules + "，以及" + unknown
	default:
		return rules
	}
}

// sendToZh says where the resolved domains' queries go. When the affected
// locations reach resolvers of different levels the worst case is named
// explicitly; each location carries its own resolver in the report.
func sendToZh(a model.Args) string {
	if a["mixed"] == "true" {
		return "会先在本地解析，其中最差的情况会发给" + zh(levelZh, a["level"])
	}
	return "会先发给" + zh(levelZh, a["level"])
}

func safeSuffix(a model.Args) string {
	if a["level"] == "safe" {
		return "解析经代理或不向外发出，不构成泄露，但属于多余解析。"
	}
	return ""
}

func unknownReason(a model.Args) string {
	s := zh(reasonZh, a["reason"])
	if a["file"] != "" {
		s += "：" + a["file"]
	}
	return s
}

type findingText struct {
	msg func(a model.Args) string
	fix func(a model.Args) string
}

var findingsZh = map[string]findingText{
	"CFG-01": {
		msg: func(a model.Args) string {
			s := fmt.Sprintf("%s出现未知键 %q，mihomo 会静默忽略它", zh(sectionZh, a["section"]), a["key"])
			switch {
			case a["suggest"] != "":
				s += fmt.Sprintf("；它很可能是 %q 的笔误，这项设置实际没有生效", a["suggest"])
			case a["anchor"] == "true":
				s += "；它定义了 YAML 锚点，通常是供后文引用的辅助键"
			}
			return s + "。"
		},
		fix: func(a model.Args) string {
			if a["suggest"] != "" {
				return fmt.Sprintf("把 %q 改为 %q。", a["key"], a["suggest"])
			}
			if a["anchor"] == "true" {
				return "如果只是锚点辅助键，可以忽略这条提示。"
			}
			return "确认键名拼写；不需要的话删除该键。"
		},
	},
	"CFG-02": {
		msg: func(model.Args) string { return "配置文件已用 age 加密，无法分析。" },
		fix: func(model.Args) string { return "先用 mihomo 或客户端解密，再对明文配置运行检查。" },
	},
	"CFG-03": {
		msg: func(a model.Args) string {
			switch a["kind"] {
			case "sub-rule":
				return fmt.Sprintf("SUB-RULE 引用的 sub-rules %q 不存在，mihomo 会加载失败。", a["name"])
			case "rule-set":
				return fmt.Sprintf("RULE-SET 引用的规则集 %q 没有在 rule-providers 中定义，mihomo 会加载失败。", a["name"])
			case "group-member":
				return fmt.Sprintf("策略组成员 %q 不存在，mihomo 会加载失败。", a["name"])
			}
			return fmt.Sprintf("规则引用的策略 %q 不存在，mihomo 会加载失败。", a["name"])
		},
		fix: func(model.Args) string {
			return "修正名称拼写，或在 proxies / proxy-groups / rule-providers / sub-rules 中补上定义。"
		},
	},
	"DNS-01": {
		msg: func(a model.Args) string {
			if a["kind"] == "missing" {
				return "配置中没有 dns 段，mihomo 内置 DNS 未启用：规则触发的解析会交给系统 DNS（明文）。"
			}
			return "dns.enable 不是 true，mihomo 内置 DNS 未启用：规则触发的解析会交给系统 DNS（明文）。"
		},
		fix: func(model.Args) string {
			return "启用 dns（enable: true），nameserver 使用加密 DNS（DoH / DoT）或经代理的服务器。"
		},
	},
	"DNS-02": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("nameserver / fallback 中有明文 DNS：%s。mihomo 会同时向组内所有服务器查询，同组的加密服务器挡不住明文查询被看到。", a["servers"])
		},
		fix: func(model.Args) string {
			return "删除这些明文服务器；需要国内直连解析时改用加密地址（如 https://223.5.5.5/dns-query）。"
		},
	},
	"DNS-04": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("nameserver-policy 把代理类域名集 %q 交给%s 解析，这些本应走代理的域名会被它看到。", a["key"], zh(levelZh, a["level"]))
		},
		fix: func(model.Args) string {
			return "让该域名集使用经代理的加密 DNS（如 https://1.1.1.1/dns-query#代理组），或从 nameserver-policy 中删除该项。"
		},
	},
	"DNS-05": {
		msg: func(a model.Args) string {
			s := "使用了 fallback：未命中 fallback-filter 的域名会同时发给 nameserver 与 fallback"
			if a["lazy"] == "true" {
				s += "（已设置 fallback-lazy-query，fallback 只在需要回退时查询）"
			}
			return s + "。"
		},
		fix: func(model.Args) string { return "改用 nameserver-policy 按域名集分流 DNS。" },
	},
	"DNS-06": {
		msg: func(model.Args) string {
			return "respect-rules: true 但没有配置 proxy-server-nameserver，mihomo 会加载失败。"
		},
		fix: func(model.Args) string {
			return "添加 proxy-server-nameserver（如 https://223.5.5.5/dns-query），或关闭 respect-rules。"
		},
	},
	"DNS-07": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("DNS 服务器 %q 的 #%s 指向不存在的策略，查询会失败。", a["server"], a["name"])
		},
		fix: func(model.Args) string {
			return "修正 # 后面的策略名，使它与 proxies / proxy-groups 中的名称一致。"
		},
	},
	"DNS-08": {
		msg: func(a model.Args) string {
			if a["kind"] == "empty" {
				return "default-nameserver 是空列表，mihomo 会加载失败。"
			}
			return fmt.Sprintf("default-nameserver 中的 %q 不是纯 IP，mihomo 会加载失败。", a["server"])
		},
		fix: func(model.Args) string {
			return "default-nameserver 只能写 IP（可以带加密协议，如 tls://223.5.5.5）或 system。"
		},
	},
	"DNS-09": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("proxy-server-nameserver 含明文 DNS：%s，代理节点的域名会被明文查询。", a["servers"])
		},
		fix: func(model.Args) string { return "改用加密 DNS，如 https://223.5.5.5/dns-query。" },
	},
	"RULE-01": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("规则 %q 没有 no-resolve，会对所有走到这里的域名做本地 DNS 解析：%s，在走代理之前%s。%s",
				a["trigger"], scopeZh(a), sendToZh(a), safeSuffix(a))
		},
		fix: func(a model.Args) string {
			return fmt.Sprintf("给该规则加上 no-resolve（%q），或把它移到所有域名规则之后。", a["trigger"]+",no-resolve")
		},
	},
	"RULE-02": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("规则 %q 没有 no-resolve，会对所有走到这里的域名做本地 DNS 解析：%s%s。%s",
				a["trigger"], scopeZh(a), sendToZh(a), safeSuffix(a))
		},
		fix: func(a model.Args) string {
			return fmt.Sprintf("给该规则加上 no-resolve（%q）；如需按 IP 分流未知域名，请让 nameserver 只使用经代理的加密 DNS。", a["trigger"]+",no-resolve")
		},
	},
	"RULE-03": {
		msg: func(a model.Args) string {
			switch a["kind"] {
			case "unknown":
				return fmt.Sprintf("规则集 %q 的内容无法读取（%s），无法判断规则 %q 是否会触发本地 DNS 解析。", a["set"], unknownReason(a), a["trigger"])
			case "conditional":
				return fmt.Sprintf("规则集 %q 内的条目 %q 只对满足 %s 的域名触发本地 DNS 解析；这些域名最终是否走代理无法静态确定，解析会发给%s。%s",
					a["set"], a["entry"], a["guard"], zh(levelZh, a["level"]), safeSuffix(a))
			}
			return fmt.Sprintf("classical 规则集 %q 内的 IP 条目 %q 没有 no-resolve，引用它的规则 %q 也没有 no-resolve：匹配到该条目时会做本地 DNS 解析，%s%s。集合内排在它前面的域名条目不受影响。%s",
				a["set"], a["entry"], a["trigger"], scopeZh(a), sendToZh(a), safeSuffix(a))
		},
		fix: func(a model.Args) string {
			if a["kind"] == "unknown" {
				return "把规则集缓存文件放到 mihomo 目录下（或用 --home 指定目录）后重新检查；也可以在引用处加 no-resolve。"
			}
			return fmt.Sprintf("在引用处加 no-resolve（%q），或把规则集拆成 domain 与 ipcidr 两个，IP 部分放到所有域名规则之后。", a["trigger"]+",no-resolve")
		},
	},
	"RULE-04": {
		msg: func(a model.Args) string {
			switch a["kind"] {
			case "unknown":
				return fmt.Sprintf("逻辑规则 %q 引用的规则集 %q 内容无法读取（%s），无法判断是否会触发本地 DNS 解析。", a["trigger"], a["set"], unknownReason(a))
			case "conditional":
				return fmt.Sprintf("逻辑规则 %q 中的 IP 子规则 %q 只对满足 %s 的域名触发本地 DNS 解析；这些域名最终是否走代理无法静态确定，解析会发给%s。%s",
					a["trigger"], a["entry"], a["guard"], zh(levelZh, a["level"]), safeSuffix(a))
			}
			return fmt.Sprintf("逻辑规则 %q 中的 IP 子规则 %q 没有 no-resolve，会对走到这里的域名做本地 DNS 解析：%s%s。%s",
				a["trigger"], a["entry"], scopeZh(a), sendToZh(a), safeSuffix(a))
		},
		fix: func(a model.Args) string {
			if a["kind"] == "unknown" {
				return "把规则集缓存文件放到 mihomo 目录下（或用 --home 指定目录）后重新检查。"
			}
			return fmt.Sprintf("给 IP 子规则加 no-resolve（如 %q），或把这条逻辑规则移到所有域名规则之后。", "("+a["entry"]+",no-resolve)")
		},
	},
	"RULE-05": {
		msg: func(a model.Args) string {
			return fmt.Sprintf("%q 带 no-resolve 且位于所有域名规则之后，作为兜底时对域名请求永远不会命中（只对直接用 IP 访问的连接有效）。", a["rule"])
		},
		fix: func(model.Args) string {
			return "如果想按 IP 归属分流域名请求，去掉 no-resolve，并确保 nameserver 不含明文 DNS；否则可以删除这条规则。"
		},
	},
	"RULE-06": {
		msg: func(a model.Args) string {
			if a["kind"] == "default" {
				return "规则列表没有 MATCH，mihomo 对未匹配的连接默认直连（白名单模式）：未被规则覆盖的域名都会在本地解析，其中可能有本应走代理的域名。"
			}
			return fmt.Sprintf("%q 以直连兜底（白名单模式）：未被规则覆盖的域名都会在本地解析，其中可能有本应走代理的域名。", a["rule"])
		},
		fix: func(model.Args) string {
			return "如需避免，改用 MATCH,代理组 兜底，并用 GEOSITE,cn 等域名规则覆盖需要直连的域名。"
		},
	},
}

var notesZh = map[string]func(a model.Args) string{
	"group-assumed-proxy": func(a model.Args) string {
		return fmt.Sprintf("策略组 %q 同时包含代理与 DIRECT / REJECT 等成员，按代理处理（假设）。", a["group"])
	},
	"dns-disabled": func(model.Args) string { return "mihomo DNS 未启用，解析器按系统 DNS（明文）计。" },
	"policy-static": func(model.Args) string {
		return "nameserver-policy 按名称静态对应（geosite / rule-set 名、域名后缀），名称不同但内容重叠的情况识别不到；可用 trace 查看具体域名。"
	},
	"fallback-included": func(a model.Args) string {
		if a["lazy"] == "true" {
			return "设置了 fallback-lazy-query，fallback 只在需要回退时查询；按最坏情况计入。"
		}
		return "fallback 与 nameserver 会被同时查询，已一并计入。"
	},
	"respect-rules-proxy": func(model.Args) string {
		return "respect-rules: true，没有写 #策略 的服务器按经代理处理（假设规则会把它们导向代理）。"
	},
	"system-proxy-scope": func(model.Args) string { return "按系统代理 / mixed-port 场景分析，未考虑 TUN。" },
	"classical-except": func(a model.Args) string {
		return fmt.Sprintf("规则集 %q 中排在触发条目之前的 %s 条条目（%s）命中的域名会提前返回，不受影响。", a["set"], a["count"], a["entries"])
	},
	"or-except": func(a model.Args) string {
		return fmt.Sprintf("OR 中排在 IP 子规则之前的 %s 个条件（%s）命中的域名会提前返回，不受影响。", a["count"], a["entries"])
	},
	"after-entries": func(a model.Args) string {
		return fmt.Sprintf("该规则内部触发点之后的 %s 个域名条目（%s）要等解析之后才会被匹配，同样受影响。", a["count"], a["entries"])
	},
	"and-guard": func(a model.Args) string {
		return fmt.Sprintf("AND 只在前面的条件（%s）满足时才执行 IP 子规则。", a["guard"])
	},
	"sub-rule-guard": func(a model.Args) string {
		return fmt.Sprintf("只有满足条件（%s）的域名才会进入 sub-rules %q；它们在其中被解析后，若没有命中任何子规则，会带着解析结果回到主规则链继续匹配。对 sub-rules 内部规则的影响（如有）单独报告。", a["guard"], a["sub"])
	},
	"proxy-set-builtin": func(a model.Args) string {
		return fmt.Sprintf("%q 是常见的境外域名集，规则中没有引用它，按代理类处理。", a["key"])
	},
	"trace-ip-assumed": func(model.Args) string {
		return "IP 规则是否命中无法静态得知，一律按「不命中」继续；实际的最终策略可能不同。"
	},
	"trace-conn-assumed": func(model.Args) string {
		return "进程、端口等连接条件无法从域名得知，一律按「不命中」继续。"
	},
	"trace-policy-uncertain": func(a model.Args) string {
		return fmt.Sprintf("以下 nameserver-policy / fallback-filter 项因数据缺失无法判断，按不命中处理：%s。", a["keys"])
	},
}

func findingMessage(f model.Finding) string {
	if t, ok := findingsZh[f.ID]; ok {
		return t.msg(f.Args)
	}
	return f.ID
}

func findingFix(f model.Finding) string {
	if t, ok := findingsZh[f.ID]; ok && t.fix != nil {
		return t.fix(f.Args)
	}
	return ""
}

func noteText(n model.Note) string {
	if fn, ok := notesZh[n.Key]; ok {
		return fn(n.Args)
	}
	return n.Key
}

// Labels used by the text renderers.
var (
	labelLocations   = "位置："
	labelFix         = "修复："
	labelNotes       = "说明："
	labelSummary     = "汇总："
	labelNoFindings  = "未发现问题。"
	labelCheckHeader = "检查配置："
	labelMore        = "… 另有 %d 处"
	labelUnknownLine = "行号未知"
)

func summaryText(counts map[model.Severity]int) string {
	var parts []string
	for _, s := range model.Severities {
		parts = append(parts, fmt.Sprintf("%s %d", severityZh[s], counts[s]))
	}
	return labelSummary + strings.Join(parts, "，")
}

// ---- trace ----

var traceOutcomeZh = map[string]string{
	"match":            "命中",
	"no-match":         "不命中",
	"unknown":          "未知",
	"assumed-no-match": "不命中（假设）",
	"pass":             "命中（PASS，继续）",
}

var verdictZh = map[string]string{
	"leak":            "泄露：该域名最终走代理，但在此之前已被本地 DNS 解析。",
	"redundant":       "无泄露：该域名在走代理之前被解析过，但查询经代理或不向外发出（多余解析）。",
	"proxy":           "无泄露：该域名直接交给代理，本地不做 DNS 解析。",
	"direct":          "直连：该域名不走代理，由直连出站正常解析，不属于泄露。",
	"reject":          "拒绝：该连接被拒绝，不会建立。",
	"hosts-proxy":     "无泄露：hosts 已给出地址，不发 DNS 查询，最终走代理。",
	"resolved-direct": "直连：匹配过程中做了本地解析，最终直连，不属于泄露。",
}

var impactZh = map[string]string{
	"before-resolution": "缺失的数据出现在触发解析之前：如果这些步骤实际命中，就不会发生本地解析，结论可能不同。",
	"same-class":        "缺失的数据出现在触发解析之后，且这些步骤若命中也会走同类策略，不影响泄露结论。",
	"may-differ":        "缺失的数据出现在触发解析之后：解析已经发生，但最终策略可能不同。",
	"no-resolution":     "这些步骤若命中，最终策略可能不同。",
}

var (
	labelTraceHeader    = "模拟匹配：%s（配置：%s）"
	labelHostsHit       = "hosts 中有 %q（%s），解析结果直接取自 hosts，不发 DNS 查询。"
	labelResolution     = "↳ 触发本地 DNS 解析，查询发往 %s："
	labelResolutionHost = "↳ 触发解析，但 hosts 已给出地址，不发 DNS 查询。"
	labelLevel          = "解析器分级：%s"
	labelIfMatched      = "；若命中将走 %s（%s）"
	labelStepTarget     = "  → %s（%s）"
	labelStepReason     = "  —— %s"
	labelStepDataFile   = "（%s）"
	labelNamedReason    = "%s：%s"
	labelListSep        = "；"
	labelVerdict        = "结论："
	labelSeverity       = "泄露等级：%s"
	labelFinal          = "最终规则：%s → %s（%s）"
	labelFinalDefault   = "最终规则：无规则命中，mihomo 默认 DIRECT（直连）"
	labelUncertain      = "不确定：以下步骤数据缺失 —— %s"
	labelStepRef        = "第 %d 步（%s）"
	labelSubRuleEnter   = "  → 进入 sub-rules %q"
	labelPolicyKey      = "（nameserver-policy 项 %q）"
)

// ---- command line ----

// UsageText is the command-line help.
func UsageText() string {
	return `dnsleak —— mihomo 配置文件 DNS 泄露静态检查（离线，不运行 mihomo）

用法：
  dnsleak check [--format text|json] [--home 目录] <配置文件>
  dnsleak trace [--format text|json] [--home 目录] <配置文件> <域名>

参数：
  --format   输出格式，text（默认）或 json
  --home     mihomo 主目录，用于查找规则集缓存（rules/）与 GeoSite.dat；默认为配置文件所在目录

退出码：
  0  没有「错误 / 高 / 中」结果
  1  有「错误 / 高 / 中」结果（trace：泄露等级为中及以上）
  2  配置无法读取、无法解析或已加密；参数错误
`
}

// CLI error kinds.
const (
	ErrKindArgs   = "args"
	ErrKindFormat = "format"
	ErrKindRead   = "read"
	ErrKindParse  = "parse"
	// ErrKindEncrypted is used by the GUI; the CLI reports CFG-02 instead.
	ErrKindEncrypted = "encrypted"
	// GUI source view: path not allowed / unreadable or too large / binary.
	ErrKindSource       = "source"
	ErrKindSourceRead   = "source-read"
	ErrKindSourceBinary = "source-binary"
)

// ErrorText renders a command-line / GUI error.
func ErrorText(kind, detail string) string {
	switch kind {
	case ErrKindFormat:
		return fmt.Sprintf("错误：不支持的输出格式 %q，只能是 text 或 json。", detail)
	case ErrKindRead:
		return "错误：无法读取配置文件：" + detail
	case ErrKindParse:
		return "错误：无法解析配置文件（YAML 格式错误）：" + detail
	case ErrKindEncrypted:
		f := model.Finding{ID: "CFG-02"}
		return "错误：" + findingMessage(f) + findingFix(f)
	case ErrKindSource:
		return "无法显示该文件：只能查看当前检查的配置文件及检查结果中引用的文件。" + detail
	case ErrKindSourceRead:
		return "无法读取该文件：" + detail
	case ErrKindSourceBinary:
		return "该文件是二进制格式（如 .mrs 规则集、GeoSite.dat），无法显示原文。" + detail
	}
	return "错误：参数不正确。" + detail + "\n\n" + UsageText()
}

// resolverSourceZh names model.ResolverInfo.Source codes.
var resolverSourceZh = map[string]string{
	model.ResolverSystem:             "系统 DNS",
	model.ResolverPolicy:             "nameserver-policy",
	model.ResolverFallback:           "fallback",
	model.ResolverNameserver:         "nameserver",
	model.ResolverNameserverFallback: "nameserver ∪ fallback",
}

// resolverAnnotZh renders the resolver of an affected location, e.g.
// "→ 明文 DNS（nameserver-policy: geosite:geolocation-!cn）".
func resolverAnnotZh(r *model.ResolverInfo) string {
	src := zh(resolverSourceZh, r.Source)
	if r.PolicyKey != "" {
		src += ": " + r.PolicyKey
	}
	return "→ " + zh(levelZh, r.Level) + "（" + src + "）"
}

// ---- GUI ----

// GUIWindowTitle is the title of the desktop window.
const GUIWindowTitle = "dnsleak — mihomo DNS 泄露检查"

// Labels of the native open-file dialog.
const (
	GUIDialogTitle  = "选择 mihomo 配置文件"
	GUIFilterConfig = "mihomo 配置（*.yaml, *.yml）"
	GUIFilterAll    = "所有文件（*.*）"
)

// GUILabels returns the display names of the codes that appear in a
// CheckResult, so the GUI does not repeat backend prose.
func GUILabels() Labels {
	l := Labels{
		Severity:       map[string]string{},
		Role:           map[string]string{},
		Level:          map[string]string{},
		ResolverSource: map[string]string{},
		Text: map[string]string{
			LabelTextUnknownLine: labelUnknownLine,
		},
	}
	for s, name := range severityZh {
		l.Severity[s.String()] = name
	}
	for k, v := range roleZh {
		l.Role[k] = v
	}
	for k, v := range levelZh {
		l.Level[k] = v
	}
	for k, v := range resolverSourceZh {
		l.ResolverSource[k] = v
	}
	return l
}
