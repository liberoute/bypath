package gateway

import (
	"fmt"
	"log"
	"net"

	"github.com/liberoute/bypath/internal/config"
	"github.com/miekg/dns"
)

// DNSServer is a simple forwarding DNS server.
// It intercepts DNS queries from LAN clients and forwards them
// to upstream DNS servers (through the tunnel if not whitelisted).
type DNSServer struct {
	config    *config.Config
	server    *dns.Server
	upstreams []string
}

// NewDNSServer creates a new DNS server.
func NewDNSServer(cfg *config.Config) *DNSServer {
	return &DNSServer{
		config:    cfg,
		upstreams: cfg.Gateway.DNSUpstream,
	}
}

// Start begins listening for DNS queries.
func (d *DNSServer) Start() error {
	addr := fmt.Sprintf("%s:%d", d.config.Server.Listen, d.config.Server.DNSPort)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", d.handleQuery)

	d.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	// Also listen on TCP
	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: mux,
	}

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("⚠️  DNS TCP server error: %v", err)
		}
	}()

	go func() {
		if err := d.server.ListenAndServe(); err != nil {
			log.Printf("⚠️  DNS UDP server error: %v", err)
		}
	}()

	return nil
}

// Stop shuts down the DNS server.
func (d *DNSServer) Stop() {
	if d.server != nil {
		d.server.Shutdown()
	}
}

// handleQuery forwards DNS queries to upstream servers.
func (d *DNSServer) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = false

	// Forward to upstream
	for _, upstream := range d.upstreams {
		upstreamAddr := net.JoinHostPort(upstream, "53")
		client := &dns.Client{}
		resp, _, err := client.Exchange(r, upstreamAddr)
		if err != nil {
			continue
		}

		// Got a response, send it back
		resp.SetReply(r)
		w.WriteMsg(resp)
		return
	}

	// All upstreams failed
	msg.Rcode = dns.RcodeServerFailure
	w.WriteMsg(msg)
}
