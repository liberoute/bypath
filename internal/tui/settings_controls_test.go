package tui

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

func TestSettingsSeparatesManagementAndProxyAccess(t *testing.T) {
	m := &Menu{settings: app.Settings{Listen: "127.0.0.1", SOCKSListen: "127.0.0.1", SOCKSPort: 35001}}
	proxyFound, apiFound := false, false
	for _, row := range m.settingRows() {
		if row.kind == "toggle-lan" || row.kind == "text-listen" {
			t.Fatalf("proxy UI exposes a management binding mutation: %+v", row)
		}
		if row.label == "Internal API bind" {
			apiFound = row.value == "127.0.0.1" && row.kind == "readonly-api"
		}
		if row.label == "SOCKS proxy endpoint" {
			proxyFound = strings.Contains(row.value, "35001") && !strings.Contains(row.value, "2801")
		}
	}
	if !proxyFound || !apiFound {
		t.Fatalf("proxy and management controls not independently displayed: %+v", m.settingRows())
	}
}
