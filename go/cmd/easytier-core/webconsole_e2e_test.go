// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"time"

	configpb "github.com/EasyTier/EasyTier/go/internal/proto/api_config"
	instancepb "github.com/EasyTier/EasyTier/go/internal/proto/api_instance"
	managepb "github.com/EasyTier/EasyTier/go/internal/proto/api_manage"
	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	webpb "github.com/EasyTier/EasyTier/go/internal/proto/web"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/transport"
	"github.com/EasyTier/EasyTier/go/internal/webconsole"
	"google.golang.org/protobuf/proto"
)

// e2eConsole plays the console side of the config-server link: it answers
// GetFeature/Heartbeat and drives the daemon's WebClientService.
type e2eConsole struct{}

func (e2eConsole) ServiceName() string { return webconsole.ServiceWebServer }

func (e2eConsole) HandleMethod(methodIndex uint32, _ context.Context, _ uint32, _ []byte) ([]byte, error) {
	switch methodIndex {
	case webconsole.MethodGetFeature:
		return proto.Marshal(&webpb.GetFeatureResponse{SupportEncryption: false})
	case webconsole.MethodHeartbeat:
		return proto.Marshal(&webpb.HeartbeatResponse{})
	default:
		return nil, nil
	}
}

// TestRunWebConsoleDrivesInstances runs the real `-w` daemon path against a
// console test harness over a real UDP tunnel: no local configuration, every
// WebClientService method the console uses, and real instance side effects.
func TestRunWebConsoleDrivesInstances(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a daemon and a real tunnel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	listener, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() { _ = listener.Serve(ctx) }()

	address := listener.Address().String()
	daemonCtx, stopDaemon := context.WithCancel(ctx)
	defer stopDaemon()
	daemonDone := make(chan int, 1)
	go func() {
		daemonDone <- runWebConsole(daemonCtx, options{
			configServer: "udp://" + address + "/e2e-token",
			machineID:    "44444444-5555-4666-8777-888888888888",
			hostname:     "e2e-machine",
		}, io.Discard, io.Discard)
	}()

	channel, err := listener.Accept(ctx)
	if err != nil {
		t.Fatalf("accept daemon: %v", err)
	}
	session, err := webconsole.Serve(ctx, channel, e2eConsole{})
	if err != nil {
		t.Fatalf("serve console session: %v", err)
	}
	defer func() { _ = session.Close() }()

	instID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	instUUID := uuidMessage(t, instID)

	// The daemon reuses the probe session when no upgrade is needed, so the
	// instance methods go to the same session the client is heartbeating on.
	validate := &managepb.ValidateConfigResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodValidateConfig, &managepb.ValidateConfigRequest{
		Config: &managepb.NetworkConfig{
			NetworkName:      proto.String("e2e-network"),
			NetworkSecret:    proto.String("e2e-secret"),
			NetworkingMethod: managepb.NetworkingMethod_Standalone.Enum(),
		},
	}, validate, 10*time.Second); err != nil {
		t.Fatalf("ValidateConfig: %v", err)
	}
	if validate.GetTomlConfig() == "" {
		t.Fatal("ValidateConfig returned empty TOML")
	}

	run := &managepb.RunNetworkInstanceResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodRunNetworkInstance, &managepb.RunNetworkInstanceRequest{
		InstId: instUUID,
		Config: &managepb.NetworkConfig{
			InstanceId:       proto.String(instID),
			Hostname:         proto.String("e2e-machine"),
			NetworkName:      proto.String("e2e-network"),
			NetworkSecret:    proto.String("e2e-secret"),
			VirtualIpv4:      proto.String("10.99.0.1"),
			NetworkLength:    proto.Int32(24),
			NetworkingMethod: managepb.NetworkingMethod_Standalone.Enum(),
			ListenerUrls:     []string{"tcp://127.0.0.1:0"},
			NoTun:            proto.Bool(true),
		},
		Source: managepb.ConfigSource_ConfigSourceUser,
	}, run, 30*time.Second); err != nil {
		t.Fatalf("RunNetworkInstance: %v", err)
	}
	if run.GetInstId() == nil {
		t.Fatal("RunNetworkInstance returned no instance id")
	}

	list := &managepb.ListNetworkInstanceResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodListNetworkInstance, &managepb.ListNetworkInstanceRequest{}, list, 10*time.Second); err != nil {
		t.Fatalf("ListNetworkInstance: %v", err)
	}
	if len(list.GetInstIds()) != 1 {
		t.Fatalf("ListNetworkInstance = %d ids, want 1", len(list.GetInstIds()))
	}

	// CollectNetworkInfo must carry the fields the console renders; an empty
	// payload makes the console show NaN and blank cells.
	collectInfo := &managepb.CollectNetworkInfoResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodCollectNetworkInfo, &managepb.CollectNetworkInfoRequest{}, collectInfo, 10*time.Second); err != nil {
		t.Fatalf("CollectNetworkInfo: %v", err)
	}
	instanceInfo, ok := collectInfo.GetInfo().GetMap()[instID]
	if !ok {
		t.Fatalf("CollectNetworkInfo has no entry for %s: %v", instID, collectInfo.GetInfo().GetMap())
	}
	if !instanceInfo.GetRunning() {
		t.Fatal("CollectNetworkInfo reports the instance as not running")
	}
	if instanceInfo.GetDevName() == "" {
		t.Fatal("CollectNetworkInfo reports no device name")
	}
	if instanceInfo.GetMyNodeInfo().GetHostname() != "e2e-machine" {
		t.Fatalf("my node info hostname = %q", instanceInfo.GetMyNodeInfo().GetHostname())
	}
	if instanceInfo.GetMyNodeInfo().GetVersion() == "" {
		t.Fatal("my node info carries no version")
	}
	if instanceInfo.GetMyNodeInfo().GetVirtualIpv4() == nil {
		t.Fatal("my node info carries no virtual IPv4")
	}

	info := &managepb.CollectNetworkInfoResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodCollectNetworkInfo, &managepb.CollectNetworkInfoRequest{}, info, 10*time.Second); err != nil {
		t.Fatalf("CollectNetworkInfo: %v", err)
	}
	if len(info.GetInfo().GetMap()) != 1 {
		t.Fatalf("CollectNetworkInfo = %d instances, want 1", len(info.GetInfo().GetMap()))
	}

	meta := &managepb.ListNetworkInstanceMetaResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodListNetworkInstanceMeta, &managepb.ListNetworkInstanceMetaRequest{}, meta, 10*time.Second); err != nil {
		t.Fatalf("ListNetworkInstanceMeta: %v", err)
	}
	if len(meta.GetMetas()) != 1 || meta.GetMetas()[0].GetNetworkName() != "e2e-network" {
		t.Fatalf("ListNetworkInstanceMeta = %v", meta.GetMetas())
	}

	cfgResponse := &managepb.GetNetworkInstanceConfigResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodGetNetworkInstanceConfig, &managepb.GetNetworkInstanceConfigRequest{InstId: instUUID}, cfgResponse, 10*time.Second); err != nil {
		t.Fatalf("GetNetworkInstanceConfig: %v", err)
	}
	if cfgResponse.GetConfig().GetNetworkName() != "e2e-network" {
		t.Fatalf("GetNetworkInstanceConfig network = %q", cfgResponse.GetConfig().GetNetworkName())
	}

	// ConfigRpc: patch the hostname and read it back.
	patchRequest := &configpb.PatchConfigRequest{
		Instance: &instancepb.InstanceIdentifier{
			Selector: &instancepb.InstanceIdentifier_Id{Id: instUUID},
		},
		Patch: &configpb.InstanceConfigPatch{Hostname: proto.String("e2e-renamed")},
	}
	if err := session.Call(ctx, webconsole.ServiceConfigRPC, webconsole.MethodPatchConfig, patchRequest, &configpb.PatchConfigResponse{}, 30*time.Second); err != nil {
		t.Fatalf("PatchConfig: %v", err)
	}
	getConfigRPC := &configpb.GetConfigResponse{}
	if err := session.Call(ctx, webconsole.ServiceConfigRPC, webconsole.MethodGetConfig, &configpb.GetConfigRequest{
		Instance: &instancepb.InstanceIdentifier{
			Selector: &instancepb.InstanceIdentifier_Id{Id: instUUID},
		},
	}, getConfigRPC, 10*time.Second); err != nil {
		t.Fatalf("ConfigRpc GetConfig: %v", err)
	}
	if getConfigRPC.GetConfig().GetHostname() != "e2e-renamed" {
		t.Fatalf("ConfigRpc GetConfig hostname = %q", getConfigRPC.GetConfig().GetHostname())
	}
	getConfig := &managepb.GetNetworkInstanceConfigResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodGetNetworkInstanceConfig, &managepb.GetNetworkInstanceConfigRequest{InstId: instUUID}, getConfig, 10*time.Second); err != nil {
		t.Fatalf("GetNetworkInstanceConfig after patch: %v", err)
	}
	if getConfig.GetConfig().GetHostname() != "e2e-renamed" {
		t.Fatalf("hostname after patch = %q", getConfig.GetConfig().GetHostname())
	}

	// Retain keeps it, Delete removes it.
	retain := &managepb.RetainNetworkInstanceResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodRetainNetworkInstance, &managepb.RetainNetworkInstanceRequest{
		InstIds: []*commonpb.UUID{instUUID},
	}, retain, 10*time.Second); err != nil {
		t.Fatalf("RetainNetworkInstance: %v", err)
	}
	if len(retain.GetRemainInstIds()) != 1 {
		t.Fatalf("RetainNetworkInstance kept %d instances, want 1", len(retain.GetRemainInstIds()))
	}

	del := &managepb.DeleteNetworkInstanceResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodDeleteNetworkInstance, &managepb.DeleteNetworkInstanceRequest{
		InstIds: []*commonpb.UUID{instUUID},
	}, del, 20*time.Second); err != nil {
		t.Fatalf("DeleteNetworkInstance: %v", err)
	}
	list = &managepb.ListNetworkInstanceResponse{}
	if err := session.Call(ctx, webconsole.ServiceWebClient, webconsole.MethodListNetworkInstance, &managepb.ListNetworkInstanceRequest{}, list, 10*time.Second); err != nil {
		t.Fatalf("ListNetworkInstance after delete: %v", err)
	}
	if len(list.GetInstIds()) != 0 {
		t.Fatalf("instance survived DeleteNetworkInstance: %v", list.GetInstIds())
	}

	stopDaemon()
	select {
	case code := <-daemonDone:
		if code != 0 {
			t.Fatalf("runWebConsole returned %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runWebConsole did not stop")
	}
}

// uuidMessage converts the canonical text form into the wire UUID message.
func uuidMessage(t *testing.T, value string) *commonpb.UUID {
	t.Helper()
	compact := strings.ReplaceAll(value, "-", "")
	raw, err := hex.DecodeString(compact)
	if err != nil || len(raw) != 16 {
		t.Fatalf("invalid uuid %q", value)
	}
	return &commonpb.UUID{
		Part1: binary.BigEndian.Uint32(raw[0:4]),
		Part2: binary.BigEndian.Uint32(raw[4:8]),
		Part3: binary.BigEndian.Uint32(raw[8:12]),
		Part4: binary.BigEndian.Uint32(raw[12:16]),
	}
}

var _ rpc.RpcService = e2eConsole{}
