package tunnel

// bypath reserves its own routing table and rule index for sing-box's
// auto_route. Pinning them makes native routing deterministic: ownership is
// recorded before the engine starts, and cleanup can remove exactly the rules
// and routes that reference this table instead of guessing sing-box defaults.
// The values are unlikely to collide with host configuration and are validated
// as unused before every native start.
const (
	NativeRouteTable = 20220
	NativeRuleIndex  = 9200
)
