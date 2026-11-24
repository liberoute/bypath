package bench

// Attempt categories name the stage that failed, so a caller can tell a
// name-resolution problem from a dead port, a TLS mismatch and an HTTPS
// refusal without reading an untrusted error string. The values are stable;
// "handshake_failure" keeps its long-standing spelling so existing stored
// results and clients keep parsing.
const (
	CategoryDNSBootstrap   = "dns_bootstrap_failure"
	CategoryTCP            = "tcp_connection_failure"
	CategoryTransport      = "handshake_failure"
	CategoryHTTPS          = "https_failure"
	CategoryInfrastructure = "test_infrastructure_failure"
	CategoryUnsupported    = "unsupported_configuration"
)
