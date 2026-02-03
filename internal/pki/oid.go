// Package pki implements GHOSTWIRE's Public Key Infrastructure including
// certificate authority operations, custom X.509 extensions, and node enrollment.
package pki

import "encoding/asn1"

// GHOSTWIRE OID namespace
// Using a private OID arc: 1.3.6.1.4.1.99999.1.x
// In production, register a PEN with IANA and replace 99999
var (
	// OIDGhostwireRoot is the root OID for all GHOSTWIRE extensions
	OIDGhostwireRoot = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	// OIDGhostwireNodeID identifies the node within the mesh
	OIDGhostwireNodeID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

	// OIDGhostwireRoles contains the node's authorized roles
	OIDGhostwireRoles = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}

	// OIDGhostwireAllowedNetworks contains network access permissions
	OIDGhostwireAllowedNetworks = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}

	// OIDGhostwireMeshID uniquely identifies the mesh (hash of root CA)
	OIDGhostwireMeshID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 4}

	// OIDGhostwireCompartment identifies the node's compartment for segmentation
	OIDGhostwireCompartment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 5}

	// OIDGhostwireWGPubKey embeds the X25519 WireGuard public key
	OIDGhostwireWGPubKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 6}
)

// Role constants for access control
const (
	RoleAdmin    = "admin"    // Full mesh access, can issue certificates
	RoleRelay    = "relay"    // Can relay traffic for other nodes
	RoleOperator = "operator" // Standard user node
	RoleSensor   = "sensor"   // Limited, typically egress-only
	RoleEndpoint = "endpoint" // Network endpoint, receives traffic
)

// ValidRoles returns the list of valid role names
func ValidRoles() []string {
	return []string{RoleAdmin, RoleRelay, RoleOperator, RoleSensor, RoleEndpoint}
}

// IsValidRole checks if a role name is valid
func IsValidRole(role string) bool {
	for _, r := range ValidRoles() {
		if r == role {
			return true
		}
	}
	return false
}
