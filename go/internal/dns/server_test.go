// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package dns

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestServerAnswersAAndAAAA(t *testing.T) {
	server := newTestServer(t, map[string][]netip.Addr{
		"node.et.net": {netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("2001:db8::4")},
	})
	defer server.Close()
	result := serve(t, server)

	for _, test := range []struct {
		typeCode uint16
		want     netip.Addr
	}{
		{typeA, netip.MustParseAddr("192.0.2.4")},
		{typeAAAA, netip.MustParseAddr("2001:db8::4")},
	} {
		response := exchange(t, server.Address().String(), query(0x1234, "NoDe.Et.NeT", test.typeCode, 1))
		if got := binary.BigEndian.Uint16(response[2:]) & 0x000f; got != 0 {
			t.Fatalf("rcode = %d, want 0", got)
		}
		if binary.BigEndian.Uint16(response[2:])&0x0400 == 0 {
			t.Fatal("successful in-zone response is not authoritative")
		}
		if got := binary.BigEndian.Uint16(response[6:]); got != 1 {
			t.Fatalf("answer count = %d, want 1", got)
		}
		if got := answerAddress(t, response); got != test.want {
			t.Fatalf("answer address = %s, want %s", got, test.want)
		}
	}
	stop(t, server, result)
}

func TestServerReturnsNXDOMAINAndRefused(t *testing.T) {
	server := newTestServer(t, nil)
	defer server.Close()
	result := serve(t, server)

	for _, test := range []struct {
		name              string
		wantRcode         uint16
		wantAuthoritative bool
	}{
		{"missing.et.net", rcodeNameError, true},
		{"example.com", rcodeRefused, false},
	} {
		response := exchange(t, server.Address().String(), query(1, test.name, typeA, 1))
		flags := binary.BigEndian.Uint16(response[2:])
		if got := flags & 0x000f; got != test.wantRcode {
			t.Fatalf("%s rcode = %d, want %d", test.name, got, test.wantRcode)
		}
		if got := flags&0x0400 != 0; got != test.wantAuthoritative {
			t.Fatalf("%s authoritative = %t, want %t", test.name, got, test.wantAuthoritative)
		}
	}
	stop(t, server, result)
}

func TestServerRejectsInvalidAndMultiQuestion(t *testing.T) {
	server := newTestServer(t, nil)
	defer server.Close()
	result := serve(t, server)

	invalid := []byte{0x12, 0x34, 0x01}
	if response := exchange(t, server.Address().String(), invalid); response != nil {
		t.Fatalf("response to too-short packet = %x, want none", response)
	}
	multi := query(2, "node.et.net", typeA, 2)
	response := exchange(t, server.Address().String(), multi)
	if response == nil {
		t.Fatal("multi-question query received no response")
	}
	if got := binary.BigEndian.Uint16(response[2:]) & 0x000f; got != rcodeFormatError {
		t.Fatalf("multi-question rcode = %d, want FORMERR", got)
	}
	stop(t, server, result)
}

func TestServerContextCancellationClosesSocket(t *testing.T) {
	server := newTestServer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}
}

func TestServerExpiresRecordsAndForwardsOutsideZone(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buffer := make([]byte, maxDatagram)
		n, remote, err := upstream.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		response := append([]byte(nil), buffer[:n]...)
		binary.BigEndian.PutUint16(response[2:], binary.BigEndian.Uint16(response[2:])|0x8000)
		_, _ = upstream.WriteToUDP(response, remote)
	}()

	server, err := NewServer(Config{
		Address:         "127.0.0.1:0",
		Zone:            "et.net",
		TTL:             1,
		Upstreams:       []string{upstream.LocalAddr().String()},
		UpstreamTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetRecordWithTTL("short.et.net", 1, netip.MustParseAddr("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	if got := len(server.Records()); got != 1 {
		t.Fatalf("records before expiry = %d, want 1", got)
	}
	time.Sleep(1100 * time.Millisecond)
	if got := len(server.Records()); got != 0 {
		t.Fatalf("records after expiry = %d, want 0", got)
	}
	result := serve(t, server)
	response := exchange(t, server.Address().String(), query(9, "example.com", typeA, 1))
	if response == nil || binary.BigEndian.Uint16(response) != 9 || binary.BigEndian.Uint16(response[2:])&0x8000 == 0 {
		t.Fatalf("upstream response = %x", response)
	}
	stop(t, server, result)
}

func TestStatusReportsTTLAndUpstreamHealth(t *testing.T) {
	server, err := NewServer(Config{Address: "127.0.0.1:0", Zone: "et.net", TTL: 30, Upstreams: []string{"127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetRecordWithTTL("node.et.net", 2, netip.MustParseAddr("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	records := server.Records()
	if len(records) != 1 || records[0].TTL == 0 || records[0].ExpiresAt.IsZero() {
		t.Fatalf("records = %#v", records)
	}
	status := server.Status()
	if status.Zone != "et.net" || status.TTL != 30 || len(status.Upstreams) != 1 || status.Upstreams[0].State != "unknown" {
		t.Fatalf("DNS status = %#v", status)
	}
}

func newTestServer(t *testing.T, records map[string][]netip.Addr) *Server {
	t.Helper()
	server, err := NewServer(Config{Address: "127.0.0.1:0", Zone: "et.net", TTL: 30, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func serve(t *testing.T, server *Server) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- server.Serve(context.Background()) }()
	return result
}

func stop(t *testing.T, server *Server, result <-chan error) {
	t.Helper()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after Close")
	}
}

func query(id uint16, name string, typeCode uint16, count uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet, id)
	binary.BigEndian.PutUint16(packet[2:], 0x0100)
	binary.BigEndian.PutUint16(packet[4:], count)
	for _, label := range stringsSplit(name) {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0)
	packet = appendUint16(packet, typeCode)
	packet = appendUint16(packet, classIN)
	return packet
}

func stringsSplit(name string) []string {
	var labels []string
	start := 0
	for i := range name {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return append(labels, name[start:])
}

func exchange(t *testing.T, address string, request []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, maxDatagram)
	n, err := conn.Read(response)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil
		}
		t.Fatal(err)
	}
	return response[:n]
}

func answerAddress(t *testing.T, response []byte) netip.Addr {
	t.Helper()
	_, end, err := parseName(response, 12)
	if err != nil {
		t.Fatal(err)
	}
	offset := end + 4
	if response[offset] != 0xc0 || response[offset+1] != 0x0c {
		t.Fatalf("answer name = %x, want compression pointer", response[offset:offset+2])
	}
	rdLength := int(binary.BigEndian.Uint16(response[offset+10:]))
	address, ok := netip.AddrFromSlice(response[offset+12 : offset+12+rdLength])
	if !ok {
		t.Fatal("invalid answer address")
	}
	return address
}
