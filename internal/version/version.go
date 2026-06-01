// Package version is the single source of truth for the node's release version.
// All version-bearing surfaces — the startup banner, the P2P handshake
// user-agent, and the JSON-RPC subversion field — derive from Number so they
// cannot drift apart.
package version

// Number is the semantic release version of the node software.
const Number = "0.2.0"

// UserAgent is the BIP-14 style software string sent in P2P version messages
// and reported as the JSON-RPC "subversion" field.
const UserAgent = "/Malairted:" + Number + "/"
