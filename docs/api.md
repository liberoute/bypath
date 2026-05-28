# Bypath — REST API Reference

Base URL: `http://localhost:8080/api/v1`

## Status

### `GET /status`
Returns overall system status.

**Response:**
```json
{
  "version": "2.0.0",
  "tunnels": { "default-hop-0": "running" },
  "chains": {
    "default": {
      "name": "default",
      "status": "running",
      "hops": [
        { "name": "default-hop-0", "protocol": "vmess", "engine": "sing-box", "status": "running" }
      ]
    }
  },
  "whitelist": { "ir": 15420, "custom": 12 }
}
```

---

## Profiles

### `GET /profiles/groups`
List all profile groups.

### `GET /profiles/groups/{name}`
Get group details with all links.

### `POST /profiles/groups`
Create a new group.

**Body:**
```json
{ "name": "my-servers", "type": "basic" }
```

### `DELETE /profiles/groups/{name}`
Delete a group.

---

## Links

### `POST /profiles/links`
Add a link (auto-parsed from URI).

**Body:**
```json
{
  "group": "default",
  "uri": "vmess://eyJ2IjoiMiIsInBzIjoibXktc2VydmVyIi..."
}
```

**Response:**
```json
{ "message": "link added", "remark": "my-server", "protocol": "vmess" }
```

### `DELETE /profiles/links/{group}/{remark}`
Delete a link by group and remark name.

---

## Tunnels

### `GET /tunnels`
List all active tunnels and their status.

### `POST /tunnels/start`
Start a tunnel manually.

**Body:**
```json
{ "name": "manual-tun", "profile": "my-server", "engine": "sing-box", "isolate": true }
```

### `POST /tunnels/{name}/stop`
Stop a running tunnel.

---

## Chains

### `GET /chains`
List all chains and their hop status.

---

## Whitelist

### `GET /whitelist/stats`
Get whitelist statistics (CIDRs per country).

### `GET /whitelist/check/{ip}`
Check if an IP is whitelisted.

**Response:**
```json
{ "ip": "5.160.0.1", "whitelisted": true }
```

---

## Subscriptions

### `POST /subscriptions/update/{group}`
Fetch and update all subscriptions for a group.

**Response:**
```json
{ "message": "subscriptions updated", "links": 42 }
```

---

## Engines

### `GET /engines`
List available engines and their status (system/local/downloaded).
