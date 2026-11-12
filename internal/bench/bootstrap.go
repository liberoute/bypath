package bench

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type AttemptError struct {
	Category string
	Err      error
}

func (e *AttemptError) Error() string { return e.Category + ": " + e.Err.Error() }
func (e *AttemptError) Unwrap() error { return e.Err }

// HostBootstrapResolver reads the HOST mount's resolver, not the gateway mount
// inherited by nsenter -n. It never writes resolv.conf or alters DefaultResolver.
// This resolver is exclusively for endpoint bootstrap and direct host controls.
func HostBootstrapResolver() (*net.Resolver, error) {
	if runtime.GOOS != "linux" {
		return net.DefaultResolver, nil
	}
	return hostBootstrapResolver("/proc/1/root")
}

// hostBootstrapResolver discovers a usable resolver under hostRoot's /etc.
// Once the gateway owns /etc/resolv.conf it points at the gateway's own loopback
// listener, which is useless before a tunnel exists. The DHCP-assigned original
// recorded before takeover is then the only bootstrap resolver on the host.
func hostBootstrapResolver(hostRoot string) (*net.Resolver, error) {
	config, ok := hostBootstrapConfig(hostRoot)
	if !ok {
		return nil, fmt.Errorf("host has no usable bootstrap resolver (gateway-only resolver rejected)")
	}
	return ResolverFromHostConfig(config)
}

func hostBootstrapConfig(hostRoot string) (string, bool) {
	for _, name := range []string{"etc/resolv.conf", "etc/resolv.conf.bypath-backup"} {
		data, err := os.ReadFile(filepath.Join(hostRoot, name))
		if err != nil {
			continue
		}
		if _, err := ResolverFromHostConfig(string(data)); err == nil {
			return string(data), true
		}
	}
	return "", false
}
func ResolverFromHostConfig(config string) (*net.Resolver, error) {
	var servers []string
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(fields[1])
		// 127.0.0.1 is the gateway dns2socks address; host systemd's 127.0.0.53 is valid.
		if ip == nil || ip.IsUnspecified() || ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.ParseIP("::1")) {
			continue
		}
		servers = append(servers, net.JoinHostPort(ip.String(), "53"))
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("host has no usable bootstrap resolver (gateway-only resolver rejected)")
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var last error
		for _, server := range servers {
			conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, server)
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}}, nil
}

// PinServer resolves ONLY the remote server name; SNI, WS Host, gRPC authority
// and destination DNS remain untouched. IP literals need no bootstrap lookup.
func PinServer(ctx context.Context, server string, lookup func(context.Context, string) ([]net.IPAddr, error)) (map[string]string, error) {
	if ip := net.ParseIP(server); ip != nil {
		return map[string]string{server: ip.String()}, nil
	}
	if lookup == nil {
		return nil, fmt.Errorf("server hostname bootstrap unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := lookup(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("server hostname bootstrap failed")
	}
	for _, a := range addresses {
		if a.IP.To4() != nil {
			return map[string]string{server: a.IP.String()}, nil
		}
	}
	for _, a := range addresses {
		if a.IP != nil {
			return map[string]string{server: a.IP.String()}, nil
		}
	}
	return nil, fmt.Errorf("server hostname has no usable IP address")
}
