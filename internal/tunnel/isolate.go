package tunnel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// IsolateConfig removes outbound entries that could carry traffic outside the
// link a benchmark or test instance is meant to prove. The generator always
// emits a "direct" (sing-box) or "freedom" (xray) outbound for DNS bootstrap
// and for rule-based bypasses; in a proxy-only instance nothing references it,
// so it is inert but makes the isolated-config audit refuse the run.
//
// An outbound is removed only when no route rule, route final, DNS server or
// outbound chain references its tag. A referenced direct path is left in place:
// the caller's audit then reports the config as not isolated instead of this
// function silently changing where traffic would go.
func IsolateConfig(data []byte) ([]byte, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("isolate: %w", err)
	}
	outbounds, _ := doc["outbounds"].([]interface{})
	if len(outbounds) == 0 {
		return data, nil
	}

	directTags := map[string]bool{}
	nonDirect := 0
	for _, raw := range outbounds {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		switch outboundKind(m) {
		case "direct", "freedom":
			if tag, _ := m["tag"].(string); tag != "" {
				directTags[tag] = true
			}
		default:
			nonDirect++
		}
	}
	if len(directTags) == 0 || nonDirect == 0 {
		return data, nil
	}
	if directReference(doc, directTags) != "" {
		return data, nil
	}

	kept := make([]interface{}, 0, len(outbounds))
	for _, raw := range outbounds {
		if m, ok := raw.(map[string]interface{}); ok {
			if kind := outboundKind(m); kind == "direct" || kind == "freedom" {
				continue
			}
		}
		kept = append(kept, raw)
	}
	doc["outbounds"] = kept
	return json.MarshalIndent(doc, "", "  ")
}

func outboundKind(m map[string]interface{}) string {
	kind, _ := m["type"].(string)
	if kind == "" {
		kind, _ = m["protocol"].(string)
	}
	return strings.ToLower(kind)
}

// directReference reports the first JSON path whose value names one of the
// direct outbound tags, or "" when no structure references them.
func directReference(doc map[string]interface{}, directTags map[string]bool) string {
	// Fields that name an outbound in sing-box and xray respectively.
	refKeys := map[string]bool{
		"outbound": true, "outboundtag": true, "detour": true,
		"proxytag": true, "final": true, "finaloutbound": true,
	}
	var walk func(v interface{}, path string) string
	walk = func(v interface{}, path string) string {
		switch node := v.(type) {
		case map[string]interface{}:
			for key, child := range node {
				here := path + "." + key
				if refKeys[strings.ToLower(key)] {
					if s, ok := child.(string); ok && directTags[s] {
						return here + " = " + s
					}
				}
				if ref := walk(child, here); ref != "" {
					return ref
				}
			}
		case []interface{}:
			for i, child := range node {
				if ref := walk(child, fmt.Sprintf("%s[%d]", path, i)); ref != "" {
					return ref
				}
			}
		}
		return ""
	}
	return walk(doc, "$")
}
