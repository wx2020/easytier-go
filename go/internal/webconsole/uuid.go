// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package webconsole

import (
	"encoding/binary"
	"encoding/hex"
	"runtime"
	"strings"

	commonpb "github.com/EasyTier/EasyTier/go/internal/proto/common"
	webpb "github.com/EasyTier/EasyTier/go/internal/proto/web"
)

// uuidMessage converts the canonical 8-4-4-4-12 UUID text form into the wire
// UUID message. The four parts are the big-endian 32-bit words of the 16 UUID
// bytes, matching the reference conversion.
func uuidMessage(id string) *commonpb.UUID {
	if message, ok := uuidMessageOK(id); ok {
		return message
	}
	// Fall back to a zero UUID instead of failing a heartbeat: the console
	// treats an unknown machine/instance ID as "not registered yet".
	return &commonpb.UUID{}
}

func uuidMessageOK(id string) (*commonpb.UUID, bool) {
	trimmed := strings.TrimSpace(id)
	compact := strings.ReplaceAll(trimmed, "-", "")
	if len(compact) != 32 {
		return nil, false
	}
	raw, err := hex.DecodeString(compact)
	if err != nil {
		return nil, false
	}
	return &commonpb.UUID{
		Part1: binary.BigEndian.Uint32(raw[0:4]),
		Part2: binary.BigEndian.Uint32(raw[4:8]),
		Part3: binary.BigEndian.Uint32(raw[8:12]),
		Part4: binary.BigEndian.Uint32(raw[12:16]),
	}, true
}

// uuidString is the inverse of uuidMessage: it renders the canonical UUID text
// form and returns "" for an absent message.
func uuidString(message *commonpb.UUID) string {
	if message == nil {
		return ""
	}
	var raw [16]byte
	binary.BigEndian.PutUint32(raw[0:4], message.GetPart1())
	binary.BigEndian.PutUint32(raw[4:8], message.GetPart2())
	binary.BigEndian.PutUint32(raw[8:12], message.GetPart3())
	binary.BigEndian.PutUint32(raw[12:16], message.GetPart4())
	encoded := hex.EncodeToString(raw[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

// NewMachineID returns a fresh random RFC 4122 version 4 UUID in canonical
// form. Callers persist it so one machine keeps one console identity.
func NewMachineID() string { return newUUIDString() }

// defaultDeviceOS reports the host facts the console shows for this machine.
func defaultDeviceOS() *webpb.DeviceOsInfo {
	return &webpb.DeviceOsInfo{
		OsType:       runtime.GOOS,
		Version:      "",
		Distribution: deviceDistribution(),
	}
}

func deviceDistribution() string {
	switch runtime.GOOS {
	case "linux":
		// OpenWrt reports itself through /etc/openwrt_release; the console only
		// displays this string, so one stable label is enough.
		if data, err := readSmallFile("/etc/openwrt_release"); err == nil && strings.Contains(string(data), "OpenWrt") {
			return "OpenWrt"
		}
		return "Linux"
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	case "android":
		return "Android"
	default:
		return runtime.GOOS
	}
}
