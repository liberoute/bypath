package profile

// IsCDNPattern checks if a link's configuration matches the CDN relay pattern.
// CDN links have: port 443, WebSocket transport, TLS enabled, and a host field
// that differs from the address (indicating CDN fronting).
func IsCDNPattern(link *Link) bool {
	// Reality connections are direct, not CDN
	if link.Security == "reality" {
		return false
	}
	// Must be port 443 + ws + TLS
	if link.Port != 443 || link.Network != "ws" || !link.TLS {
		return false
	}
	// Host must be set and differ from address (CDN fronting indicator)
	if link.Host == "" || link.Host == link.Address {
		return false
	}
	return true
}

// MarkCDNDetected sets the CDNDetected field on a link based on IsCDNPattern.
func MarkCDNDetected(link *Link) {
	link.CDNDetected = IsCDNPattern(link)
}
