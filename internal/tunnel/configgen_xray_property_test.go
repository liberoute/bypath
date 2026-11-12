package tunnel

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
	"pgregory.net/rapid"
)

// parseXrayConfig generates an xray config for link and parses the JSON output.
func parseXrayConfig(t *rapid.T, cg *ConfigGenerator, link *profile.Link) map[string]interface{} {
	configFile, err := cg.generateXray(link)
	if err != nil {
		t.Fatalf("generateXray failed: %v", err)
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return cfg
}

func getXrayFirstOutbound(cfg map[string]interface{}) (map[string]interface{}, bool) {
	raw, ok := cfg["outbounds"]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, false
	}
	m, ok := arr[0].(map[string]interface{})
	return m, ok
}

func getXrayFirstInbound(cfg map[string]interface{}) (map[string]interface{}, bool) {
	raw, ok := cfg["inbounds"]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]interface{})
	if !ok || len(arr) == 0 {
		return nil, false
	}
	m, ok := arr[0].(map[string]interface{})
	return m, ok
}

// Property 3: Xray config generation produces valid config for supported protocols.
// For any vmess or vless link, generateXray produces valid JSON with the outbound
// protocol field matching the link protocol.
func TestProperty3_XrayConfigValidForSupportedProtocols(t *testing.T) {
	tmpDir := t.TempDir()

	genSupportedLink := rapid.Custom(func(t *rapid.T) *profile.Link {
		protocol := rapid.SampledFrom([]string{"vmess", "vless"}).Draw(t, "protocol")
		address := genAddress.Draw(t, "address")
		port := genPort.Draw(t, "port")
		uuid := genUUID.Draw(t, "uuid")
		network := genNetwork.Draw(t, "network")
		tls := rapid.Bool().Draw(t, "tls")
		sni := ""
		if tls {
			sni = address
		}
		path, host := "", ""
		if network == "ws" {
			path = "/" + rapid.StringMatching(`[a-z]{2,8}`).Draw(t, "path")
			host = address
		}
		return &profile.Link{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			UUID:     uuid,
			Network:  network,
			TLS:      tls,
			SNI:      sni,
			Path:     path,
			Host:     host,
			Remark:   "test",
		}
	})

	rapid.Check(t, func(t *rapid.T) {
		link := genSupportedLink.Draw(t, "link")
		cg := NewConfigGenerator(tmpDir)
		cfg := parseXrayConfig(t, cg, link)

		outbound, ok := getXrayFirstOutbound(cfg)
		if !ok {
			t.Fatal("expected outbounds array with at least one entry")
		}
		if outbound["protocol"] != link.Protocol {
			t.Fatalf("outbound protocol: expected %q, got %v", link.Protocol, outbound["protocol"])
		}
		if outbound["tag"] != "proxy" {
			t.Fatalf("outbound tag: expected \"proxy\", got %v", outbound["tag"])
		}
	})
}

// Property 4: Xray config generation never errors for any protocol.
// Protocols unknown to xray fall back gracefully — valid JSON is always produced,
// outbounds and inbounds keys are always present, and the first outbound is tagged "proxy".
func TestProperty4_XrayConfigNoErrorForAnyProtocol(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		cg := NewConfigGenerator(tmpDir)
		cfg := parseXrayConfig(t, cg, link)

		if _, ok := cfg["inbounds"]; !ok {
			t.Fatal("expected inbounds key in xray config")
		}
		if _, ok := cfg["outbounds"]; !ok {
			t.Fatal("expected outbounds key in xray config")
		}
		outbound, ok := getXrayFirstOutbound(cfg)
		if !ok {
			t.Fatal("expected at least one outbound")
		}
		if outbound["tag"] != "proxy" {
			t.Fatalf("outbound tag: expected \"proxy\", got %v", outbound["tag"])
		}
	})
}

// Property 5: Stream settings mapping preserves transport and TLS configuration.
// For vmess/vless links with ws network and TLS, the generated xray config preserves
// wsSettings.path, wsSettings.host, and tlsSettings.serverName from the link.
func TestProperty5_XrayStreamSettingsPreservesTransportAndTLS(t *testing.T) {
	tmpDir := t.TempDir()

	genWSLink := rapid.Custom(func(t *rapid.T) *profile.Link {
		protocol := rapid.SampledFrom([]string{"vmess", "vless"}).Draw(t, "protocol")
		address := genAddress.Draw(t, "address")
		port := genPort.Draw(t, "port")
		uuid := genUUID.Draw(t, "uuid")
		path := "/" + rapid.StringMatching(`[a-z]{2,8}`).Draw(t, "path")
		return &profile.Link{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			UUID:     uuid,
			Network:  "ws",
			TLS:      true,
			SNI:      address,
			Path:     path,
			Host:     address,
			Remark:   "ws-tls-test",
		}
	})

	rapid.Check(t, func(t *rapid.T) {
		link := genWSLink.Draw(t, "link")
		cg := NewConfigGenerator(tmpDir)
		cfg := parseXrayConfig(t, cg, link)

		outbound, ok := getXrayFirstOutbound(cfg)
		if !ok {
			t.Fatal("expected outbounds in config")
		}
		stream, ok := outbound["streamSettings"].(map[string]interface{})
		if !ok {
			t.Fatal("expected streamSettings in outbound")
		}

		ws, ok := stream["wsSettings"].(map[string]interface{})
		if !ok {
			t.Fatal("expected wsSettings for ws transport")
		}
		if ws["path"] != link.Path {
			t.Fatalf("wsSettings.path: expected %q, got %v", link.Path, ws["path"])
		}
		if ws["host"] != link.Host {
			t.Fatalf("wsSettings.host: expected %q, got %v", link.Host, ws["host"])
		}

		tls, ok := stream["tlsSettings"].(map[string]interface{})
		if !ok {
			t.Fatal("expected tlsSettings for TLS link")
		}
		if tls["serverName"] != link.SNI {
			t.Fatalf("tlsSettings.serverName: expected %q, got %v", link.SNI, tls["serverName"])
		}
	})
}

// Property 6: Port consistency — SOCKSPort set on ConfigGenerator appears in the xray
// inbound port, matching the same port used by the sing-box inbound for the same link.
func TestProperty6_XrayPortConsistency(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		socksPort := rapid.IntRange(1024, 60000).Draw(t, "socksPort")

		cg := NewConfigGenerator(tmpDir)
		cg.SOCKSPort = socksPort

		xrayCfg := parseXrayConfig(t, cg, link)
		inbound, ok := getXrayFirstInbound(xrayCfg)
		if !ok {
			t.Fatal("expected inbounds in xray config")
		}
		portVal, ok := inbound["port"].(float64)
		if !ok {
			t.Fatalf("inbound port not a number: %T %v", inbound["port"], inbound["port"])
		}
		if int(portVal) != socksPort {
			t.Fatalf("xray inbound port: expected %d, got %d", socksPort, int(portVal))
		}

		// sing-box inbound port must match
		sbCfg := parseSingBoxConfig(t, cg, link)
		sbInbounds, ok := getInboundsFromConfig(sbCfg)
		if !ok {
			t.Fatal("expected inbounds in sing-box config")
		}
		for _, ib := range sbInbounds {
			if ib["type"] == "mixed" || ib["type"] == "socks" {
				sbPort, ok := ib["listen_port"].(float64)
				if ok && int(sbPort) != socksPort {
					t.Fatalf("sing-box inbound listen_port: expected %d, got %d", socksPort, int(sbPort))
				}
			}
		}
	})
}
