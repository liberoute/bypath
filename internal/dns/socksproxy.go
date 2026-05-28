package dns

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// SOCKSProxy is a DNS-over-SOCKS5 proxy.
// It listens for DNS queries on a local UDP port and forwards them
// through a SOCKS5 proxy to upstream DNS servers.
// This replaces the external dns2socks binary.
type SOCKSProxy struct {
	listenAddr string // e.g., "127.0.0.1:53"
	socksAddr  string // e.g., "127.0.0.1:2801"
	upstream   string // e.g., "1.1.1.1:53"
	conn       *net.UDPConn
	mu         sync.Mutex
	running    bool
	stopCh     chan struct{}
}

// NewSOCKSProxy creates a new DNS-over-SOCKS5 proxy.
func NewSOCKSProxy(listenAddr, socksAddr, upstream string) *SOCKSProxy {
	return &SOCKSProxy{
		listenAddr: listenAddr,
		socksAddr:  socksAddr,
		upstream:   upstream,
		stopCh:     make(chan struct{}),
	}
}

// Start begins listening for DNS queries.
func (p *SOCKSProxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("resolving listen address: %w", err)
	}

	p.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", p.listenAddr, err)
	}

	p.mu.Lock()
	p.running = true
	p.mu.Unlock()

	log.Printf("🔀 DNS-over-SOCKS started: %s → SOCKS5(%s) → %s", p.listenAddr, p.socksAddr, p.upstream)

	go p.serve()
	return nil
}

// Stop shuts down the proxy.
func (p *SOCKSProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return
	}

	p.running = false
	close(p.stopCh)
	if p.conn != nil {
		p.conn.Close()
	}
}

// serve handles incoming DNS queries.
func (p *SOCKSProxy) serve() {
	buf := make([]byte, 4096)

	for {
		select {
		case <-p.stopCh:
			return
		default:
		}

		p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			p.mu.Lock()
			running := p.running
			p.mu.Unlock()
			if !running {
				return
			}
			continue
		}

		// Handle each query in a goroutine
		query := make([]byte, n)
		copy(query, buf[:n])
		go p.handleQuery(query, clientAddr)
	}
}

// handleQuery forwards a DNS query through SOCKS5 to the upstream DNS server.
func (p *SOCKSProxy) handleQuery(query []byte, clientAddr *net.UDPAddr) {
	// Connect to upstream DNS via SOCKS5 (TCP)
	response, err := p.forwardViaSocks(query)
	if err != nil {
		log.Printf("⚠️  DNS proxy error: %v", err)
		return
	}

	// Send response back to client
	p.conn.WriteToUDP(response, clientAddr)
}

// forwardViaSocks sends a DNS query through SOCKS5 proxy via TCP.
func (p *SOCKSProxy) forwardViaSocks(query []byte) ([]byte, error) {
	// Connect to SOCKS5 proxy
	socksConn, err := net.DialTimeout("tcp", p.socksAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to SOCKS5: %w", err)
	}
	defer socksConn.Close()

	socksConn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 handshake (no auth)
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	_, err = socksConn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 handshake write: %w", err)
	}

	// Read response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, resp); err != nil {
		return nil, fmt.Errorf("SOCKS5 handshake read: %w", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 handshake failed: %x", resp)
	}

	// SOCKS5 connect request to upstream DNS
	host, port, err := parseHostPort(p.upstream)
	if err != nil {
		return nil, err
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	connectReq := []byte{0x05, 0x01, 0x00}

	// Check if host is IP or domain
	ip := net.ParseIP(host)
	if ip != nil && ip.To4() != nil {
		// IPv4
		connectReq = append(connectReq, 0x01)
		connectReq = append(connectReq, ip.To4()...)
	} else if ip != nil {
		// IPv6
		connectReq = append(connectReq, 0x04)
		connectReq = append(connectReq, ip.To16()...)
	} else {
		// Domain
		connectReq = append(connectReq, 0x03)
		connectReq = append(connectReq, byte(len(host)))
		connectReq = append(connectReq, []byte(host)...)
	}

	// Port (big-endian)
	connectReq = append(connectReq, byte(port>>8), byte(port&0xff))

	if _, err := socksConn.Write(connectReq); err != nil {
		return nil, fmt.Errorf("SOCKS5 connect write: %w", err)
	}

	// Read connect response (at least 10 bytes for IPv4)
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(socksConn, connectResp); err != nil {
		return nil, fmt.Errorf("SOCKS5 connect read: %w", err)
	}
	if connectResp[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 connect failed: status %d", connectResp[1])
	}

	// Now we have a TCP connection to the upstream DNS through SOCKS5.
	// DNS over TCP uses a 2-byte length prefix.
	dnsReq := make([]byte, 2+len(query))
	dnsReq[0] = byte(len(query) >> 8)
	dnsReq[1] = byte(len(query) & 0xff)
	copy(dnsReq[2:], query)

	if _, err := socksConn.Write(dnsReq); err != nil {
		return nil, fmt.Errorf("DNS write: %w", err)
	}

	// Read DNS response length
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(socksConn, lenBuf); err != nil {
		return nil, fmt.Errorf("DNS response length read: %w", err)
	}

	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if respLen > 4096 {
		return nil, fmt.Errorf("DNS response too large: %d bytes", respLen)
	}

	// Read DNS response
	dnsResp := make([]byte, respLen)
	if _, err := io.ReadFull(socksConn, dnsResp); err != nil {
		return nil, fmt.Errorf("DNS response read: %w", err)
	}

	return dnsResp, nil
}

// parseHostPort splits a host:port string.
func parseHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		// Maybe no port specified, default to 53
		return addr, 53, nil
	}

	port := 0
	for _, ch := range portStr {
		if ch >= '0' && ch <= '9' {
			port = port*10 + int(ch-'0')
		}
	}

	return host, port, nil
}
