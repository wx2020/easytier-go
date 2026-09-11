// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package gateway

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrInvalidCIDRMapping = errors.New("invalid CIDR mapping")
)

// CIDRMapping translates addresses from Source to Mapped while preserving
// the host bits. Both prefixes must describe equally sized networks.
type CIDRMapping struct {
	Source netip.Prefix
	Mapped netip.Prefix
}

// NewCIDRMapping validates and constructs a subnet mapping.
func NewCIDRMapping(source, mapped netip.Prefix) (CIDRMapping, error) {
	if !source.IsValid() || !mapped.IsValid() {
		return CIDRMapping{}, fmt.Errorf("%w: prefix is invalid", ErrInvalidCIDRMapping)
	}
	if source.Addr().BitLen() != mapped.Addr().BitLen() {
		return CIDRMapping{}, fmt.Errorf("%w: address families differ", ErrInvalidCIDRMapping)
	}
	sourceBits := source.Bits()
	mappedBits := mapped.Bits()
	if sourceBits != mappedBits {
		return CIDRMapping{}, fmt.Errorf("%w: prefix lengths %d and %d differ", ErrInvalidCIDRMapping, sourceBits, mappedBits)
	}
	return CIDRMapping{Source: source.Masked(), Mapped: mapped.Masked()}, nil
}

// ParseCIDRMapping parses two CIDR strings and constructs a subnet mapping.
func ParseCIDRMapping(source, mapped string) (CIDRMapping, error) {
	sourcePrefix, err := netip.ParsePrefix(source)
	if err != nil {
		return CIDRMapping{}, fmt.Errorf("%w: source: %v", ErrInvalidCIDRMapping, err)
	}
	mappedPrefix, err := netip.ParsePrefix(mapped)
	if err != nil {
		return CIDRMapping{}, fmt.Errorf("%w: mapped: %v", ErrInvalidCIDRMapping, err)
	}
	return NewCIDRMapping(sourcePrefix, mappedPrefix)
}

// Translate maps an address in Source into the corresponding address in
// Mapped. The second result is false when the address is not in Source.
func (m CIDRMapping) Translate(address netip.Addr) (netip.Addr, bool) {
	if !m.Source.IsValid() || !m.Mapped.IsValid() || !m.Source.Contains(address) {
		return netip.Addr{}, false
	}
	bits := m.Source.Bits()
	source := addressBytes(address)
	target := addressBytes(m.Mapped.Addr())
	for bit := bits; bit < len(source)*8; bit++ {
		byteIndex := bit / 8
		mask := byte(1 << (7 - bit%8))
		target[byteIndex] = (target[byteIndex] &^ mask) | (source[byteIndex] & mask)
	}
	return addressFromBytes(target), true
}

// TranslateAddress is an explicit spelling of Translate for call sites that
// handle several address transformations.
func (m CIDRMapping) TranslateAddress(address netip.Addr) (netip.Addr, bool) {
	return m.Translate(address)
}

func addressBytes(address netip.Addr) []byte {
	if address.Is4() {
		value := address.As4()
		return value[:]
	}
	value := address.As16()
	return value[:]
}

func addressFromBytes(value []byte) netip.Addr {
	if len(value) == 4 {
		var address [4]byte
		copy(address[:], value)
		return netip.AddrFrom4(address)
	}
	var address [16]byte
	copy(address[:], value)
	return netip.AddrFrom16(address)
}
