package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"dnsnitch/internal/platform"
)

func mihomo() platform.Adapter {
	return platform.Adapter{Name: "Mihomo", Description: "Meta Tunnel", IfIndex: 21, IfType: 53, Up: true,
		IPv4: []string{"198.18.0.1/30"}, Wintun: true, MatchedBy: platform.MatchedByComponentID}
}

func wlan() platform.Adapter {
	return platform.Adapter{Name: "WLAN", Description: "Intel(R) Wi-Fi", IfIndex: 12, IfType: 71, Up: true,
		IPv4: []string{"192.168.1.20/24"}}
}

var (
	tunOn      = platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{wlan(), mihomo()}, EgressIfIndex: 21}
	tunOff     = platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{wlan()}, EgressIfIndex: 12}
	tunNoRoute = platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{wlan(), mihomo()}, EgressIfIndex: 12}
	tunUnknown = platform.Facts{OS: platform.OSWindows, NetErr: "boom"}

	smartDisabled = platform.SmartFacts{Present: true, IsDWORD: true, Value: 1}
	smartZero     = platform.SmartFacts{Present: true, IsDWORD: true, Value: 0}
	smartMissing  = platform.SmartFacts{}
	smartWrong    = platform.SmartFacts{Present: true, Type: "REG_SZ"}
)

func view(tun platform.Facts, smart platform.SmartFacts) StatusView {
	tun.Smart = smart
	return BuildStatusView(platform.Decide(tun))
}

func TestStatusConclusions(t *testing.T) {
	for _, c := range []struct {
		name       string
		tun        platform.Facts
		smart      platform.SmartFacts
		code       string
		exit       int
		fix        bool
		conclusion string
	}{
		{"on + missing", tunOn, smartMissing, ConclusionRisk, 1, true, "必然发生 DNS 泄露"},
		{"on + 0", tunOn, smartZero, ConclusionRisk, 1, true, "必然发生 DNS 泄露"},
		{"on + 1", tunOn, smartDisabled, ConclusionProtected, 0, false, "TUN 已开启，智能多宿主名称解析已禁用"},
		{"on + wrong type", tunOn, smartWrong, ConclusionUnknown, 0, true, "无法确定智能多宿主名称解析"},
		{"off + missing", tunOff, smartMissing, ConclusionTUNOff, 0, true, "开启 TUN 前请先"},
		{"off + 1", tunOff, smartDisabled, ConclusionProtected, 0, false, "开启 TUN 时不会"},
		{"off + wrong type", tunOff, smartWrong, ConclusionTUNOff, 0, true, "无法确定它是否已禁用"},
		{"not egress + 0", tunNoRoute, smartZero, ConclusionTUNOff, 0, true, "TUN 未开启"},
		{"unknown + missing", tunUnknown, smartMissing, ConclusionUnknown, 0, true, "无法确定 TUN 是否开启"},
		{"unknown + 1", tunUnknown, smartDisabled, ConclusionProtected, 0, false, "已禁用"},
		{"unknown + wrong", tunUnknown, smartWrong, ConclusionUnknown, 0, true, "无法确定 TUN 状态"},
		{"linux", platform.Facts{OS: "linux"}, smartMissing, ConclusionUnsupported, 0, false, "暂不支持"},
	} {
		v := view(c.tun, c.smart)
		if v.ConclusionCode != c.code || StatusExitCode(v) != c.exit || (len(v.Fix) > 0) != c.fix ||
			!strings.Contains(v.Conclusion, c.conclusion) || v.Risk != (c.exit == 1) {
			t.Errorf("%s: code %s exit %d fix %d conclusion %q", c.name, v.ConclusionCode, StatusExitCode(v), len(v.Fix), v.Conclusion)
		}
	}
}

func TestStatusText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteStatus(&buf, FormatText, view(tunOn, smartDisabled)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"智能多宿主名称解析：已禁用",
		`注册表：HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		"DisableSmartNameResolution = 1（REG_DWORD）",
		"TUN 模式：已开启",
		"wintun 虚拟网卡：Mihomo（Meta Tunnel），IPv4：198.18.0.1/30",
		"识别依据：网卡驱动 ComponentId 为 Wintun",
		"公网出口网卡（到 1.1.1.1 的路由）：Mihomo（Meta Tunnel）",
		"结论：TUN 已开启",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "处理方法") || strings.Contains(out, "\r") {
		t.Errorf("unexpected fix / CR:\n%s", out)
	}

	buf.Reset()
	if err := WriteStatus(&buf, FormatText, view(tunOn, smartMissing)); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	for _, want := range []string{
		"智能多宿主名称解析：未禁用",
		"未设置 DisableSmartNameResolution（Windows 默认：未禁用）",
		"结论：高风险",
		"处理方法（仅供参考，本工具不会执行）：",
		"计算机配置 → 管理模板 → 网络 → DNS 客户端",
		"     " + `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f` + "\n",
		"重启系统",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := WriteStatus(&buf, FormatText, view(tunNoRoute, smartDisabled)); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	for _, want := range []string{
		"TUN 模式：未开启",
		"wintun 虚拟网卡：Mihomo",
		"公网出口网卡（到 1.1.1.1 的路由）：WLAN（Intel(R) Wi-Fi），IPv4：192.168.1.20/24",
		"注意：检测到虚拟网卡但流量未经过它（可能未开启 auto-route）",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
}

func TestStatusDetailCases(t *testing.T) {
	fallback := mihomo()
	fallback.MatchedBy = platform.MatchedByFallback
	for _, c := range []struct {
		name string
		v    StatusView
		item func(StatusView) StatusItem
		want string
	}{
		{"wrong type", view(tunOff, smartWrong), smartItem, "DisableSmartNameResolution 的类型是 REG_SZ"},
		{"unexpected", view(tunOff, platform.SmartFacts{Present: true, IsDWORD: true, Value: 2}), smartItem, "DisableSmartNameResolution = 2（预期为 0 或 1）"},
		{"read error", view(tunOff, platform.SmartFacts{Err: "Access is denied."}), smartItem, "无法读取注册表：Access is denied."},
		{"smart linux", view(platform.Facts{OS: "linux"}, smartMissing), smartItem, "当前系统：linux"},
		{"no adapter", view(tunOff, smartDisabled), tunItem, "未发现已启用的 wintun 虚拟网卡"},
		{"net error", view(tunUnknown, smartDisabled), tunItem, "无法读取网卡列表：boom"},
		{"egress error", view(platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{mihomo()}, EgressErr: "no route"}, smartDisabled), tunItem, "无法查询公网出口网卡：no route"},
		{"no route", view(platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{wlan()}}, smartDisabled), tunItem, "无（可能未联网）"},
		{"fallback", view(platform.Facts{OS: platform.OSWindows, Adapters: []platform.Adapter{fallback}, EgressIfIndex: 21}, smartDisabled), tunItem, "按备用规则判断"},
		{"tun linux", view(platform.Facts{OS: "linux"}, smartMissing), tunItem, "目前只支持在 Windows 上检测"},
	} {
		if d := strings.Join(c.item(c.v).Detail, "\n"); !strings.Contains(d, c.want) {
			t.Errorf("%s: detail lacks %q:\n%s", c.name, c.want, d)
		}
	}
	lin := view(platform.Facts{OS: "linux"}, smartMissing)
	if lin.Smart.Label != "仅适用于 Windows" || lin.TUN.Label != "暂不支持" {
		t.Errorf("unsupported labels: %q %q", lin.Smart.Label, lin.TUN.Label)
	}
}

func smartItem(v StatusView) StatusItem { return v.Smart }
func tunItem(v StatusView) StatusItem   { return v.TUN }

func TestStatusJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteStatus(&buf, FormatJSON, view(tunOn, smartMissing)); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	for _, k := range []string{"os", "smart", "tun", "risk", "conclusion_code", "conclusion", "fix"} {
		if _, ok := out[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	smart := out["smart"].(map[string]any)
	tun := out["tun"].(map[string]any)
	for _, k := range []string{"title", "state", "label", "reason", "detail", "note"} {
		if _, ok := smart[k]; !ok {
			t.Errorf("smart missing key %s", k)
		}
	}
	if smart["state"] != "enabled" || tun["state"] != "on" || out["risk"] != true || out["conclusion_code"] != "risk" {
		t.Errorf("json = %s", buf.String())
	}
	fix := out["fix"].([]any)
	if len(fix) != 3 || fix[1].(map[string]any)["command"] != `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f` {
		t.Errorf("fix = %v", fix)
	}

	buf.Reset()
	if err := WriteStatus(&buf, FormatJSON, view(tunOff, smartDisabled)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"fix": []`) {
		t.Errorf("fix must be an empty array:\n%s", buf.String())
	}
}
