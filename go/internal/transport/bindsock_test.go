// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package transport

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
)

// loopbackDeviceName returns the loopback interface name for this host.
func loopbackDeviceName(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Skip("no loopback interface found")
	return ""
}

// bindDeviceSupported reports whether the platform can bind sockets to a
// device without privileges. Linux SO_BINDTODEVICE needs CAP_NET_RAW.
func bindDeviceSupported() bool {
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	case "linux":
		return os.Geteuid() == 0
	default:
		return false
	}
}

func TestResolveBindDevice(t *testing.T) {
	if got := resolveBindDevice("", "127.0.0.1:8080"); got != "" {
		t.Fatalf("empty device must stay disabled, got %q", got)
	}
	if got := resolveBindDevice("eth7", "127.0.0.1:8080"); got != "eth7" {
		t.Fatalf("custom device must pass through, got %q", got)
	}
	if got := resolveBindDevice("auto", "0.0.0.0:11010"); got != "" {
		t.Fatalf("auto on unspecified address must disable binding, got %q", got)
	}
	if got := resolveBindDevice("auto", "239.1.2.3:11010"); got != "" {
		t.Fatalf("auto on multicast address must disable binding, got %q", got)
	}
}

func TestBindDeviceUnknownInterfaceFails(t *testing.T) {
	_, err := ListenUDP("127.0.0.1:0", BindDevice("no-such-device-xyz"))
	if err == nil {
		t.Fatal("binding to an unknown interface must fail")
	}
}

func TestBindDeviceLoopbackUDP(t *testing.T) {
	if !bindDeviceSupported() {
		t.Skipf("bind-to-device is privileged on %s", runtime.GOOS)
	}
	dev := loopbackDeviceName(t)
	svc, err := ListenUDP("127.0.0.1:0", BindDevice(dev))
	if err != nil {
		t.Fatalf("listen UDP bound to %s: %v", dev, err)
	}
	defer svc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go svc.Serve(ctx)
	acceptDone := make(chan error, 1)
	go func() {
		sess, err := svc.Accept(ctx)
		if err != nil {
			acceptDone <- err
			return
		}
		pkt, err := sess.Receive(ctx)
		if err != nil {
			acceptDone <- err
			return
		}
		if string(pkt.Payload) != "bound" {
			acceptDone <- nil
			return
		}
		acceptDone <- sess.Send(ctx, protocol.Packet{
			Header:  protocol.PeerManagerHeader{FromPeerID: 2, ToPeerID: 1, PacketType: protocol.PacketTypeData},
			Payload: []byte("ok"),
		})
	}()

	session, err := DialUDP(ctx, svc.Address().String(), BindDevice(dev))
	if err != nil {
		t.Fatalf("dial UDP bound to %s: %v", dev, err)
	}
	defer session.Close()
	if err := session.Send(ctx, protocol.Packet{
		Header:  protocol.PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: protocol.PacketTypeData},
		Payload: []byte("bound"),
	}); err != nil {
		t.Fatal(err)
	}
	pkt, err := session.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "ok" {
		t.Fatalf("payload = %q, want ok", pkt.Payload)
	}
	select {
	case err := <-acceptDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server side timed out")
	}
}

func TestBindDeviceTCPLoopback(t *testing.T) {
	if !bindDeviceSupported() {
		t.Skipf("bind-to-device is privileged on %s", runtime.GOOS)
	}
	dev := loopbackDeviceName(t)
	ln, err := ListenPacketChannelWithContext(context.Background(), "tcp", "127.0.0.1:0", 0, BindDevice(dev))
	if err != nil {
		t.Fatalf("listen TCP bound to %s: %v", dev, err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialPacketChannel(ctx, "tcp", ln.Address().String(), 0, BindDevice(dev))
	if err != nil {
		t.Fatalf("dial TCP bound to %s: %v", dev, err)
	}
	if closer, ok := client.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	server, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if closer, ok := server.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	packet := protocol.Packet{Payload: []byte("tcp-bound")}
	if err := client.Send(ctx, packet); err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got.Payload), "tcp-bound") {
		t.Fatalf("payload = %q", got.Payload)
	}
}
