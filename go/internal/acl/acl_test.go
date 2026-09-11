// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package acl

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestPolicyEvaluateMatchesAllSelectorsAndInclusivePorts(t *testing.T) {
	rule := Rule{
		Name:                "allow-web",
		Priority:            10,
		Direction:           DirectionInbound,
		Protocol:            ProtocolTCP,
		SourcePrefixes:      []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")},
		SourcePorts:         []PortRange{{Start: 1024, End: 65535}},
		DestinationPorts:    []PortRange{{Start: 443, End: 443}},
		Action:              ActionAllow,
	}
	policy, err := NewPolicy(ActionDrop, []Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	decision := policy.Evaluate(PacketMeta{
		Direction:       DirectionInbound,
		Protocol:        ProtocolTCP,
		Source:          netip.MustParseAddr("10.20.1.9"),
		Destination:     netip.MustParseAddr("192.0.2.10"),
		SourcePort:      1024,
		DestinationPort: 443,
	})
	if decision.Action != ActionAllow || decision.Rule == nil || decision.Rule.Name != "allow-web" {
		t.Fatalf("decision = %#v, want matching allow rule", decision)
	}

	for _, packet := range []PacketMeta{
		{Direction: DirectionOutbound, Protocol: ProtocolTCP, Source: netip.MustParseAddr("10.20.1.9"), Destination: netip.MustParseAddr("192.0.2.10"), SourcePort: 1024, DestinationPort: 443},
		{Direction: DirectionInbound, Protocol: ProtocolUDP, Source: netip.MustParseAddr("10.20.1.9"), Destination: netip.MustParseAddr("192.0.2.10"), SourcePort: 1024, DestinationPort: 443},
		{Direction: DirectionInbound, Protocol: ProtocolTCP, Source: netip.MustParseAddr("10.21.1.9"), Destination: netip.MustParseAddr("192.0.2.10"), SourcePort: 1024, DestinationPort: 443},
		{Direction: DirectionInbound, Protocol: ProtocolTCP, Source: netip.MustParseAddr("10.20.1.9"), Destination: netip.MustParseAddr("192.0.2.10"), SourcePort: 1023, DestinationPort: 443},
		{Direction: DirectionInbound, Protocol: ProtocolTCP, Source: netip.MustParseAddr("10.20.1.9"), Destination: netip.MustParseAddr("192.0.2.10"), SourcePort: 65535, DestinationPort: 442},
	} {
		if got := policy.Evaluate(packet); got.Action != ActionDrop || got.Rule != nil {
			t.Fatalf("packet %#v decision = %#v, want default drop", packet, got)
		}
	}
}

func TestPolicyEvaluateOrdersPriorityStably(t *testing.T) {
	policy, err := NewPolicy(ActionDrop, []Rule{
		{Name: "later", Priority: 20, Direction: DirectionForward, Protocol: ProtocolAny, Action: ActionAllow},
		{Name: "first-tie", Priority: 10, Direction: DirectionForward, Protocol: ProtocolAny, Action: ActionDrop},
		{Name: "second-tie", Priority: 10, Direction: DirectionForward, Protocol: ProtocolAny, Action: ActionAllow},
	})
	if err != nil {
		t.Fatal(err)
	}

	decision := policy.Evaluate(PacketMeta{Direction: DirectionForward, Protocol: ProtocolUDP})
	if decision.Action != ActionDrop || decision.Rule == nil || decision.Rule.Name != "first-tie" {
		t.Fatalf("decision = %#v, want first equal-priority rule", decision)
	}
}

func TestPolicyEvaluateAnyProtocolAndMultiplePrefixes(t *testing.T) {
	policy, err := NewPolicy(ActionDrop, []Rule{
		{
			Name:                "v6-any",
			Direction:           DirectionOutbound,
			Protocol:            ProtocolAny,
			SourcePrefixes:      []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48"), netip.MustParsePrefix("2001:db8:2::/48")},
			DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8:ffff::/48")},
			Action:              ActionAllow,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	decision := policy.Evaluate(PacketMeta{
		Direction:   DirectionOutbound,
		Protocol:    ProtocolICMPv6,
		Source:      netip.MustParseAddr("2001:db8:2::1"),
		Destination: netip.MustParseAddr("2001:db8:ffff::1"),
	})
	if decision.Action != ActionAllow || decision.Rule == nil || decision.Rule.Name != "v6-any" {
		t.Fatalf("decision = %#v, want allow", decision)
	}
}

func TestPolicyEvaluateSupportsDirectionsAndProtocols(t *testing.T) {
	directions := []Direction{DirectionInbound, DirectionOutbound, DirectionForward}
	protocols := []Protocol{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolICMPv6}
	for _, direction := range directions {
		for _, protocol := range protocols {
			t.Run(fmt.Sprintf("direction-%d/protocol-%d", direction, protocol), func(t *testing.T) {
				policy, err := NewPolicy(ActionDrop, []Rule{{
					Direction: direction,
					Protocol:  protocol,
					Action:    ActionAllow,
				}})
				if err != nil {
					t.Fatal(err)
				}

				decision := policy.Evaluate(PacketMeta{Direction: direction, Protocol: protocol})
				if decision.Action != ActionAllow || decision.Rule == nil {
					t.Fatalf("decision = %#v, want matching allow rule", decision)
				}
			})
		}
	}
}

func TestPolicyEvaluateUsesDefaultForInvalidPacketMetadata(t *testing.T) {
	policy, err := NewPolicy(ActionDrop, []Rule{{
		Direction: DirectionInbound,
		Protocol:  ProtocolAny,
		Action:    ActionAllow,
	}})
	if err != nil {
		t.Fatal(err)
	}

	for _, packet := range []PacketMeta{
		{Direction: 0, Protocol: ProtocolTCP},
		{Direction: DirectionInbound, Protocol: 99},
	} {
		if got := policy.Evaluate(packet); got.Action != ActionDrop || got.Rule != nil {
			t.Fatalf("packet %#v decision = %#v, want default drop", packet, got)
		}
	}
}

func TestPolicyCopiesRulesAndDecision(t *testing.T) {
	rules := []Rule{{
		Name:           "original",
		Direction:      DirectionInbound,
		Protocol:       ProtocolTCP,
		SourcePrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Action:         ActionAllow,
	}}
	policy, err := NewPolicy(ActionDrop, rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Action = ActionDrop
	rules[0].SourcePrefixes[0] = netip.MustParsePrefix("192.0.2.0/24")

	packet := PacketMeta{Direction: DirectionInbound, Protocol: ProtocolTCP, Source: netip.MustParseAddr("10.1.2.3")}
	decision := policy.Evaluate(packet)
	if decision.Action != ActionAllow {
		t.Fatalf("decision after source mutation = %#v, want allow", decision)
	}
	decision.Rule.Action = ActionDrop
	decision.Rule.SourcePrefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	if got := policy.Evaluate(packet); got.Action != ActionAllow {
		t.Fatalf("decision after returned rule mutation = %#v, want allow", got)
	}
}

func TestNewPolicyRejectsInvalidConfiguration(t *testing.T) {
	valid := Rule{Direction: DirectionInbound, Protocol: ProtocolTCP, Action: ActionAllow}
	tests := []struct {
		name          string
		defaultAction Action
		rule          Rule
		want          string
	}{
		{name: "default action", defaultAction: 0, rule: valid, want: "default action"},
		{name: "direction", defaultAction: ActionAllow, rule: Rule{Protocol: ProtocolTCP, Action: ActionAllow}, want: "invalid direction"},
		{name: "protocol", defaultAction: ActionAllow, rule: Rule{Direction: DirectionInbound, Protocol: 99, Action: ActionAllow}, want: "invalid protocol"},
		{name: "action", defaultAction: ActionAllow, rule: Rule{Direction: DirectionInbound, Protocol: ProtocolTCP}, want: "invalid action"},
		{name: "prefix", defaultAction: ActionAllow, rule: Rule{Direction: DirectionInbound, Protocol: ProtocolTCP, Action: ActionAllow, SourcePrefixes: []netip.Prefix{{}}}, want: "source prefix"},
		{name: "source ports", defaultAction: ActionAllow, rule: Rule{Direction: DirectionInbound, Protocol: ProtocolTCP, Action: ActionAllow, SourcePorts: []PortRange{{Start: 2, End: 1}}}, want: "source port range"},
		{name: "destination ports", defaultAction: ActionAllow, rule: Rule{Direction: DirectionInbound, Protocol: ProtocolTCP, Action: ActionAllow, DestinationPorts: []PortRange{{Start: 2, End: 1}}}, want: "destination port range"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewPolicy(test.defaultAction, []Rule{test.rule})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewPolicy error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestPolicyStatsSnapshotTracksRuleAndDefaultHits(t *testing.T) {
	policy, err := NewPolicy(ActionDrop, []Rule{{Name: "allow-web", Priority: 1, Direction: DirectionInbound, Protocol: ProtocolTCP, Action: ActionAllow}})
	if err != nil {
		t.Fatal(err)
	}
	packet := PacketMeta{Direction: DirectionInbound, Protocol: ProtocolTCP}
	if got := policy.Evaluate(packet); got.Action != ActionAllow {
		t.Fatalf("allowed decision = %#v", got)
	}
	if got := policy.Evaluate(PacketMeta{Direction: DirectionOutbound, Protocol: ProtocolTCP}); got.Action != ActionDrop {
		t.Fatalf("default decision = %#v", got)
	}
	snapshot := policy.StatsSnapshot()
	if snapshot.Evaluations != 2 || snapshot.DefaultDrops != 1 || len(snapshot.Rules) != 1 || snapshot.Rules[0].Matches != 1 {
		t.Fatalf("ACL stats = %#v", snapshot)
	}
}
