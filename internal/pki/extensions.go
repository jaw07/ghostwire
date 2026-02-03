package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/netip"
)

// NetworkDirection specifies traffic direction constraints
type NetworkDirection int

const (
	// DirectionBidirectional allows both ingress and egress
	DirectionBidirectional NetworkDirection = 0
	// DirectionEgressOnly allows only outbound traffic
	DirectionEgressOnly NetworkDirection = 1
	// DirectionIngressOnly allows only inbound traffic
	DirectionIngressOnly NetworkDirection = 2
)

// AllowedNetwork represents a network permission with direction constraint
type AllowedNetwork struct {
	Prefix    netip.Prefix
	Direction NetworkDirection
}

// GhostwireExtensions holds all custom certificate extension data
type GhostwireExtensions struct {
	NodeID          string
	Roles           []string
	AllowedNetworks []AllowedNetwork
	MeshID          [32]byte
	Compartment     string   // optional
	WireGuardPubKey [32]byte // X25519 public key
}

// asn1NetworkSpec is the ASN.1 structure for network specifications
type asn1NetworkSpec struct {
	Network   []byte
	PrefixLen int
	Direction int
}

// BuildExtensions creates X.509 extensions from GhostwireExtensions
func (ext *GhostwireExtensions) BuildExtensions() ([]pkix.Extension, error) {
	var extensions []pkix.Extension

	// Node ID extension
	nodeIDExt, err := marshalNodeIDExtension(ext.NodeID)
	if err != nil {
		return nil, fmt.Errorf("marshal node ID: %w", err)
	}
	extensions = append(extensions, nodeIDExt)

	// Roles extension (critical - required for access control)
	rolesExt, err := marshalRolesExtension(ext.Roles)
	if err != nil {
		return nil, fmt.Errorf("marshal roles: %w", err)
	}
	extensions = append(extensions, rolesExt)

	// Allowed networks extension (critical)
	if len(ext.AllowedNetworks) > 0 {
		networksExt, err := marshalAllowedNetworksExtension(ext.AllowedNetworks)
		if err != nil {
			return nil, fmt.Errorf("marshal allowed networks: %w", err)
		}
		extensions = append(extensions, networksExt)
	}

	// Mesh ID extension
	meshIDExt, err := marshalMeshIDExtension(ext.MeshID)
	if err != nil {
		return nil, fmt.Errorf("marshal mesh ID: %w", err)
	}
	extensions = append(extensions, meshIDExt)

	// Compartment extension (optional)
	if ext.Compartment != "" {
		compartmentExt, err := marshalCompartmentExtension(ext.Compartment)
		if err != nil {
			return nil, fmt.Errorf("marshal compartment: %w", err)
		}
		extensions = append(extensions, compartmentExt)
	}

	// WireGuard public key extension
	var zeroKey [32]byte
	if ext.WireGuardPubKey != zeroKey {
		wgExt, err := marshalWireGuardPubKeyExtension(ext.WireGuardPubKey)
		if err != nil {
			return nil, fmt.Errorf("marshal WireGuard key: %w", err)
		}
		extensions = append(extensions, wgExt)
	}

	return extensions, nil
}

func marshalNodeIDExtension(nodeID string) (pkix.Extension, error) {
	value, err := asn1.Marshal(nodeID)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDGhostwireNodeID,
		Critical: false,
		Value:    value,
	}, nil
}

func marshalRolesExtension(roles []string) (pkix.Extension, error) {
	value, err := asn1.Marshal(roles)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDGhostwireRoles,
		Critical: true, // Roles are critical for access control
		Value:    value,
	}, nil
}

func marshalAllowedNetworksExtension(networks []AllowedNetwork) (pkix.Extension, error) {
	specs := make([]asn1NetworkSpec, len(networks))
	for i, n := range networks {
		addr := n.Prefix.Addr()
		var netBytes []byte
		if addr.Is4() {
			a4 := addr.As4()
			netBytes = a4[:]
		} else {
			a16 := addr.As16()
			netBytes = a16[:]
		}
		specs[i] = asn1NetworkSpec{
			Network:   netBytes,
			PrefixLen: n.Prefix.Bits(),
			Direction: int(n.Direction),
		}
	}

	value, err := asn1.Marshal(specs)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDGhostwireAllowedNetworks,
		Critical: true,
		Value:    value,
	}, nil
}

func marshalMeshIDExtension(meshID [32]byte) (pkix.Extension, error) {
	value, err := asn1.Marshal(meshID[:])
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDGhostwireMeshID,
		Critical: true,
		Value:    value,
	}, nil
}

func marshalCompartmentExtension(compartment string) (pkix.Extension, error) {
	value, err := asn1.Marshal(compartment)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDGhostwireCompartment,
		Critical: false,
		Value:    value,
	}, nil
}

func marshalWireGuardPubKeyExtension(pubKey [32]byte) (pkix.Extension, error) {
	value, err := asn1.Marshal(pubKey[:])
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       OIDGhostwireWGPubKey,
		Critical: false,
		Value:    value,
	}, nil
}

// ParseExtensions extracts GhostwireExtensions from an X.509 certificate
func ParseExtensions(extensions []pkix.Extension) (*GhostwireExtensions, error) {
	ext := &GhostwireExtensions{}

	for _, e := range extensions {
		switch {
		case e.Id.Equal(OIDGhostwireNodeID):
			var nodeID string
			if _, err := asn1.Unmarshal(e.Value, &nodeID); err != nil {
				return nil, fmt.Errorf("parse node ID: %w", err)
			}
			ext.NodeID = nodeID

		case e.Id.Equal(OIDGhostwireRoles):
			var roles []string
			if _, err := asn1.Unmarshal(e.Value, &roles); err != nil {
				return nil, fmt.Errorf("parse roles: %w", err)
			}
			ext.Roles = roles

		case e.Id.Equal(OIDGhostwireAllowedNetworks):
			var specs []asn1NetworkSpec
			if _, err := asn1.Unmarshal(e.Value, &specs); err != nil {
				return nil, fmt.Errorf("parse allowed networks: %w", err)
			}
			for _, spec := range specs {
				var addr netip.Addr
				switch len(spec.Network) {
				case 4:
					addr = netip.AddrFrom4([4]byte(spec.Network))
				case 16:
					addr = netip.AddrFrom16([16]byte(spec.Network))
				default:
					return nil, fmt.Errorf("invalid network address length: %d", len(spec.Network))
				}
				prefix := netip.PrefixFrom(addr, spec.PrefixLen)
				ext.AllowedNetworks = append(ext.AllowedNetworks, AllowedNetwork{
					Prefix:    prefix,
					Direction: NetworkDirection(spec.Direction),
				})
			}

		case e.Id.Equal(OIDGhostwireMeshID):
			var meshID []byte
			if _, err := asn1.Unmarshal(e.Value, &meshID); err != nil {
				return nil, fmt.Errorf("parse mesh ID: %w", err)
			}
			if len(meshID) == 32 {
				copy(ext.MeshID[:], meshID)
			}

		case e.Id.Equal(OIDGhostwireCompartment):
			var compartment string
			if _, err := asn1.Unmarshal(e.Value, &compartment); err != nil {
				return nil, fmt.Errorf("parse compartment: %w", err)
			}
			ext.Compartment = compartment

		case e.Id.Equal(OIDGhostwireWGPubKey):
			var pubKey []byte
			if _, err := asn1.Unmarshal(e.Value, &pubKey); err != nil {
				return nil, fmt.Errorf("parse WireGuard key: %w", err)
			}
			if len(pubKey) == 32 {
				copy(ext.WireGuardPubKey[:], pubKey)
			}
		}
	}

	return ext, nil
}
