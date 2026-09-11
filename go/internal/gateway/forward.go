// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"errors"
	"fmt"

	"github.com/EasyTier/EasyTier/go/internal/acl"
)

var ErrNotForwardable = errors.New("packet is not TCP or UDP")

// EvaluateForward parses a TCP or UDP packet and evaluates it against policy.
func EvaluateForward(policy *acl.Policy, packet []byte, direction acl.Direction) (acl.Decision, error) {
	if policy == nil {
		return acl.Decision{}, fmt.Errorf("%w: nil ACL policy", ErrInvalidPacket)
	}
	meta, err := ParsePacket(packet, direction)
	if err != nil {
		return acl.Decision{}, err
	}
	if meta.Protocol != acl.ProtocolTCP && meta.Protocol != acl.ProtocolUDP {
		return acl.Decision{}, fmt.Errorf("%w: protocol %d", ErrNotForwardable, meta.Protocol)
	}
	return policy.Evaluate(meta), nil
}

// ShouldForward reports whether policy allows a TCP or UDP packet to be
// forwarded in direction.
func ShouldForward(policy *acl.Policy, packet []byte, direction acl.Direction) (bool, error) {
	decision, err := EvaluateForward(policy, packet, direction)
	if err != nil {
		return false, err
	}
	return decision.Action == acl.ActionAllow, nil
}
