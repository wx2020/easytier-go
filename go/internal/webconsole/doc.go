// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package webconsole implements the EasyTier web-console (config-server)
// client protocol: a config-server tunnel carrying a bidirectional RPC
// session, the WebServerService client (GetFeature, Heartbeat), and the
// WebClientService/ConfigRpc servers the console drives.
//
// Wire contract (frozen):
//   - tunnel: udp/tcp/ws/wss addressed as <scheme>://host:port/<token>
//   - optional Noise upgrade: magic "ET_WEB_NOISE_V1:", prologue
//     "easytier-webclient-noise-v1", pattern
//     Noise_NN_25519_ChaChaPoly_SHA256
//   - RPC: 16-byte peer-manager header (PacketType RpcReq=?, see
//     protocol.PacketTypeRPCRequest) + RpcPacket protobuf, both directions
//     address peer 1
//   - services: domain "", service "WebServerService" (server, methods:
//     1 Heartbeat, 2 GetFeature), "WebClientService" (client, methods 1-8),
//     "ConfigRpc" (client, methods 1-2); method indices are 1-based because
//     the reference generator emits `index = position + 1`
package webconsole
