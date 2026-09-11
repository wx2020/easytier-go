// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package route

import (
	"bytes"
	"reflect"
	"testing"
)

func TestAdvertisementDeterministicEncoding(t *testing.T) {
	first := Advertisement{
		Origin:     2,
		Version:    7,
		Peers:      []PeerCost{{Peer: 4, Cost: 9}, {Peer: 1, Cost: 3}},
		ProxyCIDRs: []string{"10.0.0.0/8", "fd00::/8"},
		Timestamp:  123,
	}
	second := Advertisement{
		Origin:     2,
		Version:    7,
		Peers:      []PeerCost{{Peer: 1, Cost: 3}, {Peer: 4, Cost: 9}},
		ProxyCIDRs: []string{"fd00::/8", "10.0.0.0/8"},
		Timestamp:  123,
	}
	encodedFirst, err := first.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encodedSecond, err := second.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodedFirst, encodedSecond) {
		t.Fatalf("encodings differ:\n%x\n%x", encodedFirst, encodedSecond)
	}
	decoded, err := ParseAdvertisement(encodedFirst)
	if err != nil {
		t.Fatal(err)
	}
	want := Advertisement{
		Origin:     2,
		Version:    7,
		Peers:      []PeerCost{{Peer: 1, Cost: 3}, {Peer: 4, Cost: 9}},
		ProxyCIDRs: []string{"10.0.0.0/8", "fd00::/8"},
		Timestamp:  123,
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded advertisement = %#v, want %#v", decoded, want)
	}
}

func TestAdvertisementRejectsMalformedBounds(t *testing.T) {
	tests := [][]byte{
		make([]byte, advertisementHeaderSize-1),
		make([]byte, MaxAdvertisementSize+1),
	}
	for _, data := range tests {
		if _, err := ParseAdvertisement(data); err == nil {
			t.Fatalf("ParseAdvertisement accepted malformed payload of %d bytes", len(data))
		}
	}

	valid, err := (Advertisement{Origin: 1, ProxyCIDRs: []string{"10.0.0.0/8"}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	peerCountOffset := 4 + 2 + 4 + 8 + 8
	valid[peerCountOffset] = 0xff
	valid[peerCountOffset+1] = 0xff
	valid[peerCountOffset+2] = 0xff
	valid[peerCountOffset+3] = 0xff
	if _, err := ParseAdvertisement(valid); err == nil {
		t.Fatal("ParseAdvertisement accepted an excessive peer count")
	}
}

func TestConvergenceTableRejectsOldVersion(t *testing.T) {
	table := NewConvergenceTable(1)
	newer := Advertisement{Origin: 2, Version: 2, Peers: []PeerCost{{Peer: 1, Cost: 4}}}
	older := newer
	older.Version = 1
	if !table.Accept(newer) {
		t.Fatal("table rejected newer advertisement")
	}
	if table.Accept(older) {
		t.Fatal("table accepted old advertisement")
	}
	if got := routeTo(table.Snapshot(), 2); got.Cost != 4 {
		t.Fatalf("route after old advertisement = %#v", got)
	}
}

func TestConvergenceTableThreeNodeConvergence(t *testing.T) {
	advertisements := []Advertisement{
		{Origin: 1, Version: 1, Peers: []PeerCost{{Peer: 2, Cost: 3}}},
		{Origin: 2, Version: 1, Peers: []PeerCost{{Peer: 1, Cost: 3}, {Peer: 3, Cost: 4}}},
		{Origin: 3, Version: 1, Peers: []PeerCost{{Peer: 2, Cost: 4}}},
	}
	want := []Route{
		{Destination: 2, NextHop: 2, Cost: 3},
		{Destination: 3, NextHop: 2, Cost: 7},
	}
	for _, order := range [][]int{{0, 1, 2}, {2, 0, 1}, {1, 2, 0}} {
		table := NewConvergenceTable(1)
		for _, index := range order {
			if !table.Accept(advertisements[index]) {
				t.Fatalf("table rejected advertisement %d", index)
			}
		}
		if got := table.Snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("Snapshot() = %#v, want %#v", got, want)
		}
	}
}
