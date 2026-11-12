package serviceop

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"

	"github.com/liberoute/bypath/internal/config"
)

func verifyStatus(ctx context.Context, j Job, cfg *config.Config) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", j.ControlSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://control/api/v1/app/status", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("control status unavailable")
	}
	var st struct {
		State       string `json:"state"`
		ActiveID    string `json:"active_id"`
		SelectedID  string `json:"selected_id"`
		SOCKSPort   int    `json:"socks_port"`
		GatewayMode bool   `json:"gateway_mode"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return err
	}
	if st.State != "CONNECTED" || st.ActiveID != j.ServingID || st.SelectedID != j.SelectedID || st.SOCKSPort != cfg.Server.SOCKSPort || st.GatewayMode != cfg.Gateway.Enabled {
		return errors.New("daemon has not preserved the serving identity and proxy configuration")
	}
	active, err := os.ReadFile(j.ActivePath)
	if j.ActiveExists && (err != nil || string(active) != string(j.OldActive)) {
		return errors.New("saved selection changed")
	}
	return nil
}
