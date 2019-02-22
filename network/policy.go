// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
)

type CNIPolicyType string

const (
	NetworkPolicy     CNIPolicyType = "NetworkPolicy"
	EndpointPolicy    CNIPolicyType = "EndpointPolicy"
	OutBoundNatPolicy CNIPolicyType = "OutBoundNatPolicy"
)

type Policy struct {
	Type CNIPolicyType
	Data json.RawMessage
}

// GetPortMappingPolicy creates an HCN PortMappingPolicy and stores it in CNI Policy.
func GetPortMappingPolicyV2(externalPort int, internalPort int, protocol string) Policy {
	var protocolInt uint32
	switch strings.ToLower(protocol) {
	case "TCP":
		protocolInt = 6
		break
	case "UDP":
		protocolInt = 17
		break
	case "ICMPv4":
		protocolInt = 1
		break
	case "ICMPv6":
		protocolInt = 58
		break
	case "IGMP":
		protocolInt = 2
		break
	default:
		panic(fmt.Errorf("invalid protocol supplied to port mapping policy"))
	}

	portMappingPolicy := hcn.PortMappingPolicySetting{
		ExternalPort: uint16(externalPort),
		InternalPort: uint16(internalPort),
		Protocol:     protocolInt,
	}
	rawPolicy, _ := json.Marshal(portMappingPolicy)
	endpointPolicy := hcn.EndpointPolicy{
		Type:     hcn.PortMapping,
		Settings: rawPolicy,
	}

	rawData, _ := json.Marshal(endpointPolicy)
	return Policy{
		Type: EndpointPolicy,
		Data: rawData,
	}
}

func GetPortMappingPolicy(externalPort int, internalPort int, protocol string) Policy {
	portMappingPolicy := hcsshim.NatPolicy{
		Type:         hcsshim.Nat,
		Protocol:     strings.ToUpper(protocol),
		ExternalPort: uint16(externalPort),
		InternalPort: uint16(internalPort),
	}

	rawData, _ := json.Marshal(portMappingPolicy)
	return Policy{
		Type: EndpointPolicy,
		Data: rawData,
	}
}
