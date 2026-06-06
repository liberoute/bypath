package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// GatewayUp is 1 when the gateway is running, 0 otherwise.
	GatewayUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "bypath_gateway_up",
		Help: "1 if the gateway tunnel is running, 0 if stopped.",
	})

	// ActiveEngine is a label gauge that reports the active engine (sing-box/xray).
	ActiveEngine = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bypath_active_engine",
		Help: "Active tunnel engine (1 = current engine).",
	}, []string{"engine"})

	// TunnelRestarts counts how many times the tunnel engine was restarted.
	TunnelRestarts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "bypath_tunnel_restarts_total",
		Help: "Total number of tunnel engine restarts.",
	})

	// ConfigReloads counts config reload operations.
	ConfigReloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "bypath_config_reloads_total",
		Help: "Total number of config reloads triggered.",
	})

	// SubUpdateDuration tracks subscription update latency.
	SubUpdateDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "bypath_sub_update_duration_seconds",
		Help:    "Duration of subscription update operations.",
		Buckets: prometheus.DefBuckets,
	})

	// WhitelistIPs tracks how many IPs are in the whitelist per country.
	WhitelistIPs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bypath_whitelist_ips",
		Help: "Number of whitelisted IP ranges per country.",
	}, []string{"country"})
)

// SetActiveEngine updates the active engine gauge labels.
func SetActiveEngine(name string) {
	ActiveEngine.Reset()
	if name != "" {
		ActiveEngine.WithLabelValues(name).Set(1)
	}
}
