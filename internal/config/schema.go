package config

import "strings"

// Valid keys per research §6 (RawConfig / RawDNS / RawFallbackFilter yaml tags
// at mihomo 3f27ef39).
var topLevelKeys = fields(`port socks-port redir-port tproxy-port mixed-port ss-config vmess-config inbound-tfo inbound-mptcp authentication skip-auth-prefixes lan-allowed-ips lan-disallowed-ips allow-lan bind-address mode unified-delay log-level ipv6 external-controller external-controller-routing-mark external-controller-pipe external-controller-unix external-controller-tls external-controller-cors external-ui external-ui-url external-ui-name external-doh-server secret interface-name routing-mark tunnels geo-auto-update geo-update-interval geodata-mode geodata-loader geosite-matcher tcp-concurrent find-process-mode global-client-fingerprint global-ua etag-support keep-alive-idle keep-alive-interval disable-keep-alive proxy-providers rule-providers proxies proxy-groups rules sub-rules listeners hosts dns ntp tun tuic-server iptables experimental profile geox-url sniffer tls clash-for-android`)

var dnsKeys = fields(`enable prefer-h3 ipv6 ipv6-timeout use-hosts use-system-hosts respect-rules nameserver fallback fallback-filter fallback-lazy-query listen listen-routing-mark enhanced-mode fake-ip-range fake-ip-range6 fake-ip-filter fake-ip-filter-mode fake-ip-ttl default-nameserver cache-algorithm cache-max-size nameserver-policy proxy-server-nameserver proxy-server-nameserver-policy direct-nameserver direct-nameserver-follow-policy`)

var fallbackFilterKeys = fields(`geoip geoip-code ipcidr domain geosite`)

func fields(s string) []string { return strings.Fields(s) }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Suggest returns the closest valid key within edit distance 2 (adjacent
// transpositions count as one edit), or "". Short keys need a closer match
// (distance < half the key length) so that helper keys such as "u" or "pr"
// are not mistaken for typos of "tun" or "port".
func Suggest(key string, valid []string) string {
	best, bestD := "", 3
	lk := strings.ToLower(key)
	for _, v := range valid {
		if d := editDistance(lk, v); d < bestD {
			best, bestD = v, d
		}
	}
	if best != "" && bestD*2 >= len([]rune(lk)) {
		return ""
	}
	return best
}

// editDistance is the optimal string alignment distance (Levenshtein plus
// adjacent transpositions).
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

// TopLevelKeys returns the valid top-level keys.
func TopLevelKeys() []string { return append([]string{}, topLevelKeys...) }

// DNSKeys returns the valid keys of the dns section.
func DNSKeys() []string { return append([]string{}, dnsKeys...) }

// FallbackFilterKeys returns the valid keys of dns.fallback-filter.
func FallbackFilterKeys() []string { return append([]string{}, fallbackFilterKeys...) }
