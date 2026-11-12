package app

import (
	"encoding/json"
	"fmt"
	"strings"
)

// auditIsolatedConfig proves construction (L1) for a test instance: the
// generated config must not contain a reachable DIRECT path, a TUN inbound or
// auto-routing. It parses the JSON generically because the generator emits
// sing-box and xray shapes depending on the link.
func auditIsolatedConfig(data []byte) error {
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("config is not valid JSON: %w", err)
	}
	var walk func(v interface{}, path string) error
	walk = func(v interface{}, path string) error {
		switch node := v.(type) {
		case map[string]interface{}:
			for key, child := range node {
				here := path + "." + key
				if key == "auto_route" {
					if b, ok := child.(bool); ok && b {
						return fmt.Errorf("%s enables auto_route", here)
					}
				}
				if s, ok := child.(string); ok {
					switch key {
					case "type":
						if s == "tun" || s == "direct" {
							return fmt.Errorf("%s declares a %q outbound/inbound", here, s)
						}
					case "protocol":
						if s == "freedom" || s == "direct" {
							return fmt.Errorf("%s declares protocol %q", here, s)
						}
					case "outbound", "outboundTag", "detour":
						if s == "direct" || s == "freedom" {
							return fmt.Errorf("%s routes to %q", here, s)
						}
					case "final":
						if s == "direct" || s == "freedom" {
							return fmt.Errorf("%s routes unmatched traffic to %q", here, s)
						}
					}
					if key == "type" {
						// Counted later from the outbound lists only, so an
						// inbound type can never mask a missing proxy outbound.
						_ = s
					}
				}
				if err := walk(child, here); err != nil {
					return err
				}
			}
		case []interface{}:
			for i, child := range node {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(doc, "$"); err != nil {
		return err
	}
	// An outbound list without any non-direct proxy means the test would run
	// against a local direct dial, which proves nothing.
	var outboundList []interface{}
	collectOutbounds(doc, &outboundList)
	nonDirect := 0
	for _, ob := range outboundList {
		m, ok := ob.(map[string]interface{})
		if !ok {
			continue
		}
		kind := ""
		if s, ok := m["type"].(string); ok {
			kind = s
		}
		if s, ok := m["protocol"].(string); ok {
			kind = s
		}
		switch strings.ToLower(kind) {
		case "", "direct", "freedom", "block", "blackhole":
		default:
			nonDirect++
		}
	}
	if nonDirect == 0 {
		return fmt.Errorf("no non-direct outbound in the generated config")
	}
	return nil
}

func collectOutbounds(v interface{}, out *[]interface{}) {
	switch node := v.(type) {
	case map[string]interface{}:
		for key, child := range node {
			if key == "outbounds" {
				if list, ok := child.([]interface{}); ok {
					*out = append(*out, list...)
				}
			}
			collectOutbounds(child, out)
		}
	case []interface{}:
		for _, child := range node {
			collectOutbounds(child, out)
		}
	}
}
