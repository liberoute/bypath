package health

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusUnknown   Status = "unknown"
)

// CheckResult holds the result of a health check.
type CheckResult struct {
	Status    Status    `json:"status"`
	Latency   int64     `json:"latency_ms"`
	ExitIP    string    `json:"exit_ip,omitempty"`
	Country   string    `json:"country,omitempty"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Checker performs periodic health checks on tunnel connections.
type Checker struct {
	interval    time.Duration
	proxyAddr   string // SOCKS5 proxy address to check through
	checkURL    string
	results     []CheckResult
	maxResults  int
	onUnhealthy func() // callback when unhealthy
	mu          sync.RWMutex
	cancel      context.CancelFunc
}

// Config for the health checker.
type Config struct {
	Interval    time.Duration
	ProxyAddr   string // e.g., "socks5://127.0.0.1:2801"
	CheckURL    string // e.g., "http://ip-api.com/json"
	MaxHistory  int
	OnUnhealthy func()
}

// NewChecker creates a new health checker.
func NewChecker(cfg Config) *Checker {
	if cfg.CheckURL == "" {
		cfg.CheckURL = "http://ip-api.com/json"
	}
	if cfg.Interval == 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.MaxHistory == 0 {
		cfg.MaxHistory = 100
	}

	return &Checker{
		interval:    cfg.Interval,
		proxyAddr:   cfg.ProxyAddr,
		checkURL:    cfg.CheckURL,
		results:     make([]CheckResult, 0, cfg.MaxHistory),
		maxResults:  cfg.MaxHistory,
		onUnhealthy: cfg.OnUnhealthy,
	}
}

// Start begins periodic health checking.
func (c *Checker) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)

	go func() {
		// Initial check after short delay
		time.Sleep(5 * time.Second)
		c.performCheck()

		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.performCheck()
			}
		}
	}()
}

// Stop stops the health checker.
func (c *Checker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// GetLatest returns the most recent health check result.
func (c *Checker) GetLatest() *CheckResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.results) == 0 {
		return nil
	}
	return &c.results[len(c.results)-1]
}

// GetHistory returns recent health check results.
func (c *Checker) GetHistory(limit int) []CheckResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 || limit > len(c.results) {
		limit = len(c.results)
	}

	start := len(c.results) - limit
	result := make([]CheckResult, limit)
	copy(result, c.results[start:])
	return result
}

// performCheck executes a single health check.
func (c *Checker) performCheck() {
	start := time.Now()
	result := CheckResult{Timestamp: start}

	// Create HTTP client (optionally through proxy)
	client := &http.Client{Timeout: 10 * time.Second}

	// TODO: If proxyAddr is set, configure SOCKS5 transport
	// For now, direct check (validates internet connectivity)

	resp, err := client.Get(c.checkURL)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = err.Error()
		result.Latency = time.Since(start).Milliseconds()
		c.addResult(result)

		log.Printf("❌ Health check failed: %v", err)
		if c.onUnhealthy != nil {
			c.onUnhealthy()
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Status = StatusUnhealthy
		result.Error = fmt.Sprintf("reading response: %v", err)
		result.Latency = time.Since(start).Milliseconds()
		c.addResult(result)
		return
	}

	result.Latency = time.Since(start).Milliseconds()

	// Parse ip-api.com response
	var apiResp struct {
		Query   string `json:"query"`
		Country string `json:"country"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(body, &apiResp); err == nil && apiResp.Status == "success" {
		result.ExitIP = apiResp.Query
		result.Country = apiResp.Country
		result.Status = StatusHealthy
		log.Printf("✅ Health check OK: %s (%s) [%dms]", result.ExitIP, result.Country, result.Latency)
	} else {
		result.Status = StatusUnhealthy
		result.Error = "unexpected response format"
		log.Printf("⚠️  Health check: unexpected response")
		if c.onUnhealthy != nil {
			c.onUnhealthy()
		}
	}

	c.addResult(result)
}

func (c *Checker) addResult(result CheckResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results = append(c.results, result)
	if len(c.results) > c.maxResults {
		c.results = c.results[1:]
	}
}
