package tunnel

import (
	"encoding/json"
	"github.com/liberoute/bypath/internal/profile"
	"os"
	"strings"
	"testing"
)

func TestSpecificLANMixedInboundPreservesNativeTUNAndLoopback(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.SOCKSListen = "192.168.10.2"
	cg.SOCKSPort = 2901
	in := cg.singboxInboundsGateway(&profile.Link{})
	if len(in) != 3 || in[0]["type"] != "tun" || in[1]["listen"] != "192.168.10.2" || in[2]["listen"] != "127.0.0.1" {
		t.Fatal(in)
	}
	if in[1]["listen_port"] != 2901 || in[2]["listen_port"] != 2901 {
		t.Fatal("loopback port differs")
	}
	for _, host := range []string{"127.0.0.1", "0.0.0.0"} {
		cg.SOCKSListen = host
		if len(cg.singboxInbounds(&profile.Link{})) != 1 {
			t.Fatal("duplicate wildcard/loopback inbound")
		}
	}
}
func TestSpecificLANXrayAddsSamePortLoopback(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.SOCKSListen = "192.168.10.2"
	cg.SOCKSPort = 2901
	path, err := cg.generateXray(&profile.Link{Protocol: "vless", Address: "example.com", Port: 443, UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   int    `json:"port"`
		} `json:"inbounds"`
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 2 || cfg.Inbounds[0].Listen != "192.168.10.2" || cfg.Inbounds[1].Listen != "127.0.0.1" || cfg.Inbounds[1].Port != 2901 {
		t.Fatal(cfg)
	}
}
func TestSpecificLANSSHForwardsLoopbackAndFailsClosed(t *testing.T) {
	cmd, err := BuildSSHCommand(&profile.Link{Protocol: "ssh", Address: "example.com", Port: 22, SSHUser: "user", SSHPassword: "test"}, SSHOptions{SSHPath: "/usr/bin/ssh", SSHPassPath: "/usr/bin/sshpass", ListenAddr: "192.168.10.2", ListenPort: 2901})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(cmd.Args, " ")
	for _, expected := range []string{"-D 192.168.10.2:2901", "-D 127.0.0.1:2901", "ExitOnForwardFailure=yes"} {
		if !strings.Contains(args, expected) {
			t.Fatalf("missing %s in %s", expected, args)
		}
	}
}
