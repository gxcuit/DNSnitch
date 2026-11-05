package dnsserver

import (
	"net/netip"
	"strings"

	"dnsnitch/internal/model"
)

// cnServers are well-known DNS services operated in mainland China.
var cnServers = []string{
	// AliDNS
	"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1", "dns.alidns.com",
	// DNSPod / Tencent
	"119.29.29.29", "119.28.28.28", "1.12.12.12", "120.53.53.53", "2402:4e00::",
	"doh.pub", "dot.pub", "dns.pub", "sm2.doh.pub",
	// 114DNS
	"114.114.114.114", "114.114.115.115",
	// Baidu
	"180.76.76.76", "2400:da00::6666",
	// ByteDance / Volcengine
	"180.184.1.1", "180.184.2.2",
	// CNNIC
	"1.2.4.8", "210.2.4.8",
	// 360
	"101.226.4.6", "218.30.118.6", "doh.360.cn", "dot.360.cn",
}

// foreignServers are well-known DNS services operated outside mainland China.
var foreignServers = []string{
	// Cloudflare
	"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
	"cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
	// Google
	"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844", "dns.google", "dns.google.com",
	// Quad9
	"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9", "dns.quad9.net",
	// OpenDNS
	"208.67.222.222", "208.67.220.220", "doh.opendns.com", "dns.opendns.com",
	// AdGuard
	"94.140.14.14", "94.140.15.15", "dns.adguard.com", "dns.adguard-dns.com",
	// DNS.SB
	"185.222.222.222", "45.11.45.11", "dns.sb", "doh.dns.sb",
	// TWNIC
	"101.101.101.101", "dns.twnic.tw",
	// NextDNS
	"dns.nextdns.io",
}

var knownRegion = func() map[string]model.Region {
	m := map[string]model.Region{}
	for _, h := range cnServers {
		m[normalizeHost(h)] = model.RegionCN
	}
	for _, h := range foreignServers {
		m[normalizeHost(h)] = model.RegionForeign
	}
	return m
}()

func normalizeHost(h string) string {
	h = strings.ToLower(strings.Trim(h, "[]"))
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.Unmap().String()
	}
	return h
}

func regionOf(host string) model.Region {
	if host == "" {
		return model.RegionUnknown
	}
	return knownRegion[normalizeHost(host)]
}
