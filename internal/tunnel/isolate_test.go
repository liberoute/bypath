package tunnel

import (
	"strings"
	"testing"
)

func TestIsolateConfigStripsInertDirectOutbound(t *testing.T) {
	in := `{
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 19001}],
  "outbounds": [
    {"type": "shadowsocks", "tag": "proxy", "server": "10.20.30.200", "server_port": 18389},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "proxy"},
  "dns": {"servers": [{"tag": "dns-direct", "type": "udp", "server": "1.1.1.1"}]}
}`
	out, err := IsolateConfig([]byte(in))
	if err != nil {
		t.Fatalf("IsolateConfig: %v", err)
	}
	if strings.Contains(string(out), `"type": "direct"`) {
		t.Fatalf("inert direct outbound was kept:\n%s", out)
	}
	if !strings.Contains(string(out), `"tag": "proxy"`) {
		t.Fatalf("proxy outbound was lost:\n%s", out)
	}
}

func TestIsolateConfigKeepsReferencedDirectOutbound(t *testing.T) {
	cases := map[string]string{
		"route rule":  `{"outbounds":[{"type":"vless","tag":"proxy"},{"type":"direct","tag":"direct"}],"route":{"rules":[{"domain_suffix":["ir"],"outbound":"direct"}],"final":"proxy"}}`,
		"route final": `{"outbounds":[{"type":"vless","tag":"proxy"},{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`,
		"dns detour":  `{"outbounds":[{"type":"vless","tag":"proxy"},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"},"dns":{"servers":[{"tag":"dns-direct","type":"https","server":"1.1.1.1","detour":"direct"}]}}`,
		"xray rule":   `{"outbounds":[{"protocol":"vless","tag":"proxy"},{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"type":"field","outboundTag":"direct"}]}}`,
		"chain":       `{"outbounds":[{"type":"vless","tag":"proxy","detour":"direct"},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := IsolateConfig([]byte(in))
			if err != nil {
				t.Fatalf("IsolateConfig: %v", err)
			}
			if !strings.Contains(string(out), `"direct"`) && !strings.Contains(string(out), `"freedom"`) {
				t.Fatalf("referenced direct path was stripped:\n%s", out)
			}
		})
	}
}

func TestIsolateConfigStripsXrayFreedom(t *testing.T) {
	in := `{"outbounds":[{"protocol":"vless","tag":"proxy"},{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}]}`
	out, err := IsolateConfig([]byte(in))
	if err != nil {
		t.Fatalf("IsolateConfig: %v", err)
	}
	if strings.Contains(string(out), `"freedom"`) {
		t.Fatalf("freedom outbound was kept:\n%s", out)
	}
	if !strings.Contains(string(out), `"blackhole"`) {
		t.Fatalf("blackhole outbound was lost:\n%s", out)
	}
}

func TestIsolateConfigLeavesCleanAndInvalidInputsAlone(t *testing.T) {
	clean := []byte(`{"outbounds":[{"type":"vless","tag":"proxy"}],"route":{"final":"proxy"}}`)
	out, err := IsolateConfig(clean)
	if err != nil {
		t.Fatalf("IsolateConfig: %v", err)
	}
	if string(out) != string(clean) {
		t.Fatalf("clean config changed:\n%s", out)
	}
	if _, err := IsolateConfig([]byte(`{`)); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}
