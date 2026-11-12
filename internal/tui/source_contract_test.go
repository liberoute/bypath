package tui

import (
	"context"

	"github.com/liberoute/bypath/internal/app"
)

// Subscription-specific addition to the shared frontend contract fixture.
func (s *stubService) OrganizeSubscription(_ context.Context, bucket, rawURL, name string) (app.Subscription, error) {
	return app.Subscription{Group: bucket, URL: rawURL, LayerGroupID: "g_organized", LayerGroup: name}, nil
}
