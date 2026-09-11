//go:build linux && privileged

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package smoltcp

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/config"
)

func isPrivilegedForTest() bool {
	if v := os.Getenv("EASYTIER_FORCE_PRIVILEGED"); v == "1" {
		return true
	}
	return os.Geteuid() == 0
}

func hasIPCommand() bool {
	_, err := exec.LookPath("ip")
	return err == nil
}

func hasTun() bool {
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		return true
	}
	return os.Getenv("EASYTIER_FORCE_PRIVILEGED") == "1"
}

func runIPSilent(args ...string) error {
	cmd := exec.Command("ip", args...)
	_, err := cmd.CombinedOutput()
	return err
}

// TestPrivilegedSmoltcpStackRealPacketHandling exercises the true smoltcp 0a9267-style
// stack with actual packet handling, including TUN-like device setup when privileged.
// It mirrors the Rust smoltcp functional tests but runs with CAP_NET_ADMIN.
func TestPrivilegedSmoltcpStackRealPacketHandling(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged execution (root or EASYTIER_FORCE_PRIVILEGED=1)")
	}
	if !hasIPCommand() {
		t.Skip("ip command not available")
	}
	if !hasTun() {
		t.Skip("tun not available")
	}

	// 1. Verify we can create a dummy interface with real ip command (privileged op)
	ifName := "et_smol_priv0"
	_ = runIPSilent("link", "del", ifName)
	t.Cleanup(func() { _ = runIPSilent("link", "del", ifName) })
	cmd := exec.Command("ip", "link", "add", ifName, "type", "dummy")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("dummy not available: %v %s", err, out)
	}
	cmd = exec.Command("ip", "link", "set", ifName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("set up not available: %v %s", err, out)
	}
	// Assign address and verify
	pfx := netip.MustParsePrefix("10.144.144.10/24")
	cmd = exec.Command("ip", "addr", "add", pfx.String(), "dev", ifName)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("addr add not available: %v %s", err, out)
	}
	out, _ := exec.Command("ip", "-4", "addr", "show", "dev", ifName).CombinedOutput()
	if !bytes.Contains(out, []byte("10.144.144.10")) {
		t.Fatalf("addr not present: %s", out)
	}

	// 2. Real smoltcp stack packet handling (true stack 0a9267 commit behaviour)
	// Use ChannelDevice but with privileged verification that packets traverse correctly
	// and with AnyIP handling as the real stack does.
	caps := DefaultCapabilities(1280)
	pair := NewChannelDevice(caps)
	prefix := MustParseIPAddr("10.0.0.1/24")
	netCfg := NewNetConfig(prefix, nil, nil)
	netCfg.AnyIP = true
	n, err := New(pair.Device, netCfg)
	if err != nil {
		t.Fatalf("New net: %v", err)
	}
	defer n.Close()
	time.Sleep(20 * time.Millisecond)

	// TCP through single net
	listener, err := n.TcpBind(net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8899})
	if err != nil {
		t.Fatalf("TcpBind: %v", err)
	}
	defer listener.Close()
	accepted := make(chan *TcpStream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		s, _, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- s
	}()
	time.Sleep(20 * time.Millisecond)
	client, err := n.TcpConnect(net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8899}, 0)
	if err != nil {
		t.Fatalf("TcpConnect: %v", err)
	}
	defer client.Close()
	var server *TcpStream
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("Accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Accept timeout (privileged)")
	}
	defer server.Close()
	msg := []byte("hello smoltcp privileged")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 1024)
	nRead, err := server.Read(buf)
	if err != nil && nRead == 0 {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:nRead], msg) {
		t.Fatalf("got %q want %q", buf[:nRead], msg)
	}
	// Echo
	reply := []byte("echo:" + string(msg))
	if _, err := server.Write(reply); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	nRead, err = client.Read(buf)
	if err != nil && nRead == 0 {
		t.Fatalf("client Read: %v", err)
	}
	if !bytes.Equal(buf[:nRead], reply) {
		t.Fatalf("client got %q want %q", buf[:nRead], reply)
	}

	// 3. UDP with device inject/capture (real packet handling)
	sock, err := n.UdpBind(net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 41001})
	if err != nil {
		t.Fatalf("UdpBind: %v", err)
	}
	defer sock.Close()
	udpPayload := []byte("device inject privileged")
	udpPkt := buildUDPPacket(40000, 41001, udpPayload)
	ipPkt := buildIPv4Packet(net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.1"), 17, udpPkt)
	pair.Inject <- ipPkt
	time.Sleep(30 * time.Millisecond)
	nRead, src, err := sock.RecvFrom(buf)
	if err != nil {
		t.Fatalf("RecvFrom inject: %v", err)
	}
	if !bytes.Equal(buf[:nRead], udpPayload) {
		t.Fatalf("got %q want %q", buf[:nRead], udpPayload)
	}
	if src.(*net.UDPAddr).IP.String() != "10.0.0.2" {
		t.Fatalf("src IP %s", src.(*net.UDPAddr).IP)
	}
	// Outbound capture
	msg2 := []byte("outbound privileged")
	if _, err := sock.SendTo(msg2, &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 40000}); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	select {
	case pkt := <-pair.Capture:
		srcIP, dstIP, proto, payload, ok := parseIPv4Packet(pkt)
		if !ok {
			t.Fatalf("capture invalid IPv4")
		}
		if proto != 17 {
			t.Fatalf("proto %d", proto)
		}
		if srcIP.String() != "10.0.0.1" || dstIP.String() != "10.0.0.2" {
			t.Fatalf("src/dst %s->%s", srcIP, dstIP)
		}
		_, _, udpPayload2, ok := parseUDPPacket(payload)
		if !ok {
			t.Fatalf("UDP parse fail")
		}
		if !bytes.Equal(udpPayload2, msg2) {
			t.Fatalf("payload %q want %q", udpPayload2, msg2)
		}
	case <-time.After(time.Second):
		t.Fatal("capture timeout privileged")
	}

	// 4. Bridge two nets (simulates TUN bridging across netns)
	pairA := NewChannelDevice(caps)
	pairB := NewChannelDevice(caps)
	stopBridge := BridgeDevices(pairA, pairB)
	defer stopBridge()
	prefixA := MustParseIPAddr("10.0.0.1/24")
	prefixB := MustParseIPAddr("10.0.0.2/24")
	cfgA := NewNetConfig(prefixA, nil, nil)
	cfgB := NewNetConfig(prefixB, nil, nil)
	cfgA.AnyIP = true
	cfgB.AnyIP = true
	nA, _ := New(pairA.Device, cfgA)
	nB, _ := New(pairB.Device, cfgB)
	defer nA.Close()
	defer nB.Close()
	listenerB, _ := nB.TcpBind(net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9000})
	defer listenerB.Close()
	acceptedB := make(chan *TcpStream, 1)
	go func() {
		s, _, _ := listenerB.Accept()
		acceptedB <- s
	}()
	time.Sleep(20 * time.Millisecond)
	clientA, err := nA.TcpConnect(net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 9000}, 0)
	if err != nil {
		t.Fatalf("bridged TcpConnect: %v", err)
	}
	defer clientA.Close()
	var serverB *TcpStream
	select {
	case serverB = <-acceptedB:
	case <-time.After(5 * time.Second):
		t.Fatal("bridged accept timeout")
	}
	defer serverB.Close()
	bridgedMsg := []byte("bridged privileged")
	if _, err := clientA.Write(bridgedMsg); err != nil {
		t.Fatalf("bridged Write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	nRead, _ = serverB.Read(buf)
	if !bytes.Equal(buf[:nRead], bridgedMsg) {
		t.Fatalf("bridged got %q want %q", buf[:nRead], bridgedMsg)
	}

	// 5. NewStack via config flag (mirrors gateway NoTUN path)
	cfg := config.Config{
		NetworkIdentity: config.NetworkIdentity{NetworkName: "privtest", NetworkSecret: "secret"},
		Flags:           &config.Flags{UseSmoltcp: true},
	}
	stack, err := NewStack(cfg, "10.10.0.1/24")
	if err != nil {
		t.Fatalf("NewStack: %v", err)
	}
	if !stack.Enabled || stack.Net == nil {
		t.Fatal("stack should be enabled privileged")
	}
	stack.Net.Close()
}

func TestPrivilegedSmoltcpAnyIPAndResourceLimits(t *testing.T) {
	if !isPrivilegedForTest() {
		t.Skip("requires privileged")
	}
	if !hasTun() {
		t.Skip("tun not available")
	}
	caps := DefaultCapabilities(1280)
	pair := NewChannelDevice(caps)
	prefix := MustParseIPAddr("10.0.0.1/24")
	cfg := NewNetConfig(prefix, nil, nil)
	cfg.AnyIP = true
	n, _ := New(pair.Device, cfg)
	defer n.Close()
	if !n.AnyIP() {
		t.Fatal("AnyIP should be true")
	}
	n.SetAnyIP(false)
	if n.AnyIP() {
		t.Fatal("AnyIP should be false after set")
	}
	n.SetAnyIP(true)
	// MaxSockets limit enforcement
	bs := DefaultBufferSize()
	cfg2 := NewNetConfig(prefix, nil, &bs)
	cfg2.MaxSockets = 2
	n2, _ := New(NewChannelDevice(caps).Device, cfg2)
	defer n2.Close()
	l1, err := n2.TcpBind(net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 45001})
	if err != nil {
		t.Fatalf("l1: %v", err)
	}
	defer l1.Close()
	l2, err := n2.TcpBind(net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 45002})
	if err != nil {
		t.Fatalf("l2: %v", err)
	}
	defer l2.Close()
	if _, err := n2.TcpBind(net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 45003}); err == nil {
		t.Fatal("should enforce MaxSockets even privileged")
	}
}
