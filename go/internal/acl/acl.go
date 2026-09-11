// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package acl evaluates ordered network access-control rules.
package acl

import (
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"
)

// Direction identifies the path a packet takes through the local node.
type Direction uint8

const (
	DirectionInbound Direction = iota + 1
	DirectionOutbound
	DirectionForward
)

// Protocol identifies the packet's network protocol.
type Protocol uint8

const (
	ProtocolAny Protocol = iota
	ProtocolTCP
	ProtocolUDP
	ProtocolICMP
	ProtocolICMPv6
)

// Action is the result assigned by a matching rule or policy default.
type Action uint8

const (
	ActionAllow Action = iota + 1
	ActionDrop
)

// PortRange matches every port from Start through End, inclusive.
type PortRange struct {
	Start uint16
	End   uint16
}

// Rule describes one packet filter. Empty prefix and port lists match all
// addresses and ports respectively.
type Rule struct {
	Name                string
	Priority            uint32
	Direction           Direction
	Protocol            Protocol
	SourcePrefixes      []netip.Prefix
	DestinationPrefixes []netip.Prefix
	SourcePorts         []PortRange
	DestinationPorts    []PortRange
	Action              Action
}

// PacketMeta contains the parsed packet fields needed for policy evaluation.
type PacketMeta struct {
	Direction       Direction
	Protocol        Protocol
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

// Decision is the result of an evaluation. Rule is nil when the default was used.
type Decision struct {
	Action Action
	Rule   *Rule
}

// Policy is an immutable, priority-ordered set of ACL rules.
type Policy struct {
	rules         []Rule
	defaultAction Action
	evaluations   atomic.Uint64
	defaultHits   [2]atomic.Uint64
	ruleHits      []atomic.Uint64
}

// RuleStats is a point-in-time counter snapshot for one rule.
type RuleStats struct {
	Name     string
	Priority uint32
	Action   Action
	Matches  uint64
}

// Stats is the runtime ACL evaluation snapshot. Rule counters count the first
// matching rule only; default counters count evaluations with no match.
type Stats struct {
	Evaluations   uint64
	DefaultAllows uint64
	DefaultDrops  uint64
	Rules         []RuleStats
}

// Rules returns a copy of the rules in evaluation order.
func (p *Policy) Rules() []Rule {
	if p == nil {
		return []Rule{}
	}
	rules := make([]Rule, len(p.rules))
	for i, rule := range p.rules {
		rules[i] = cloneRule(rule)
	}
	return rules
}

// DefaultAction returns the policy action used when no rule matches.
func (p *Policy) DefaultAction() Action {
	if p == nil {
		return 0
	}
	return p.defaultAction
}

// NewPolicy validates rules, orders them by ascending priority while retaining
// insertion order for equal priorities, and copies all caller-owned slices.
func NewPolicy(defaultAction Action, rules []Rule) (*Policy, error) {
	if !defaultAction.valid() {
		return nil, fmt.Errorf("invalid default action %d", defaultAction)
	}

	ordered := make([]Rule, len(rules))
	for i, rule := range rules {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		ordered[i] = cloneRule(rule)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].Priority < ordered[j].Priority
	})

	return &Policy{rules: ordered, defaultAction: defaultAction, ruleHits: make([]atomic.Uint64, len(ordered))}, nil
}

// Validate confirms a rule has valid selectors and an action.
func (r Rule) Validate() error {
	if !r.Direction.valid() {
		return fmt.Errorf("invalid direction %d", r.Direction)
	}
	if !r.Protocol.valid() {
		return fmt.Errorf("invalid protocol %d", r.Protocol)
	}
	if !r.Action.valid() {
		return fmt.Errorf("invalid action %d", r.Action)
	}
	if err := validatePrefixes("source prefix", r.SourcePrefixes); err != nil {
		return err
	}
	if err := validatePrefixes("destination prefix", r.DestinationPrefixes); err != nil {
		return err
	}
	if err := validatePortRanges("source port range", r.SourcePorts); err != nil {
		return err
	}
	return validatePortRanges("destination port range", r.DestinationPorts)
}

// Evaluate returns the first matching rule or the policy's default action.
func (p *Policy) Evaluate(packet PacketMeta) Decision {
	if p == nil {
		return Decision{Action: ActionDrop}
	}
	p.evaluations.Add(1)
	for i := range p.rules {
		rule := &p.rules[i]
		if rule.matches(packet) {
			p.ruleHits[i].Add(1)
			matched := cloneRule(*rule)
			return Decision{Action: rule.Action, Rule: &matched}
		}
	}
	if p.defaultAction == ActionAllow {
		p.defaultHits[0].Add(1)
	} else {
		p.defaultHits[1].Add(1)
	}
	return Decision{Action: p.defaultAction}
}

// StatsSnapshot returns counters collected by Evaluate without exposing
// mutable policy state.
func (p *Policy) StatsSnapshot() Stats {
	if p == nil {
		return Stats{}
	}
	result := Stats{
		Evaluations:   p.evaluations.Load(),
		DefaultAllows: p.defaultHits[0].Load(),
		DefaultDrops:  p.defaultHits[1].Load(),
		Rules:         make([]RuleStats, len(p.rules)),
	}
	for i, rule := range p.rules {
		result.Rules[i] = RuleStats{Name: rule.Name, Priority: rule.Priority, Action: rule.Action, Matches: p.ruleHits[i].Load()}
	}
	return result
}

func (r Rule) matches(packet PacketMeta) bool {
	return packet.Direction.valid() &&
		packet.Protocol.valid() &&
		r.Direction == packet.Direction &&
		(r.Protocol == ProtocolAny || r.Protocol == packet.Protocol) &&
		matchesPrefix(r.SourcePrefixes, packet.Source) &&
		matchesPrefix(r.DestinationPrefixes, packet.Destination) &&
		matchesPort(r.SourcePorts, packet.SourcePort) &&
		matchesPort(r.DestinationPorts, packet.DestinationPort)
}

func (d Direction) valid() bool {
	return d == DirectionInbound || d == DirectionOutbound || d == DirectionForward
}

func (p Protocol) valid() bool {
	return p >= ProtocolAny && p <= ProtocolICMPv6
}

func (a Action) valid() bool {
	return a == ActionAllow || a == ActionDrop
}

func validatePrefixes(name string, prefixes []netip.Prefix) error {
	for i, prefix := range prefixes {
		if !prefix.IsValid() {
			return fmt.Errorf("%s %d is invalid", name, i)
		}
	}
	return nil
}

func validatePortRanges(name string, ranges []PortRange) error {
	for i, portRange := range ranges {
		if portRange.Start > portRange.End {
			return fmt.Errorf("%s %d has start greater than end", name, i)
		}
	}
	return nil
}

func matchesPrefix(prefixes []netip.Prefix, address netip.Addr) bool {
	if len(prefixes) == 0 {
		return true
	}
	if !address.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func matchesPort(ranges []PortRange, port uint16) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, portRange := range ranges {
		if portRange.Start <= port && port <= portRange.End {
			return true
		}
	}
	return false
}

func cloneRule(rule Rule) Rule {
	rule.SourcePrefixes = append([]netip.Prefix(nil), rule.SourcePrefixes...)
	rule.DestinationPrefixes = append([]netip.Prefix(nil), rule.DestinationPrefixes...)
	rule.SourcePorts = append([]PortRange(nil), rule.SourcePorts...)
	rule.DestinationPorts = append([]PortRange(nil), rule.DestinationPorts...)
	return rule
}
