// Package control owns the local Unix-domain socket used by the TUI and CLI
// to reach the running daemon.
//
// The socket removes the need to read /etc/bypath/config.yaml: the daemon's
// management API can require a token, but an operator never needs the token or
// the root-owned config. Access is granted by the socket's filesystem
// permissions (root:<group> 0660 inside a 0750 directory); the kernel refuses
// to connect on behalf of anyone else.
//
// Membership in GroupName is a root-equivalent privilege, not a limited one.
// The daemon runs as root and the socket exposes the same management surface:
// connections, routes, credentials and engine configuration. Treat the group
// like the sudo or docker group and add only trusted administrators.
package control

// GroupName is the system group that may use the control socket. The installer
// creates it; operators add their account with usermod -aG bypath <user>.
const GroupName = "bypath"
