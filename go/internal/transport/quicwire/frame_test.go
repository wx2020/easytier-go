// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package quicwire

import (
	"bytes"
	"reflect"
	"testing"
)

func TestHeaderAndPacketRoundTrip(t *testing.T) {
	destCID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	srcCID := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	token := []byte("test-token")
	pn := uint64(42)
	pnLen := 2

	// Construct Initial packet payload
	cryptoData := []byte("fake-transport-parameters-for-initial")
	cryptoFrame := CryptoFrame{Offset: 0, Data: cryptoData}
	payload := cryptoFrame.Append(nil)

	// Long Header Initial
	hdrBytes := AppendLongHeader(nil, PacketTypeInitial, Version1, destCID, srcCID, token, pn, pnLen, len(payload))
	sealedPacket := SealPacket(hdrBytes, payload)

	// Parse header
	parsedHdr, payloadWithTag, err := ParseHeader(sealedPacket, 8, 0)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if !parsedHdr.IsLongHeader || parsedHdr.Type != PacketTypeInitial {
		t.Fatalf("header type mismatch: %+v", parsedHdr)
	}
	if parsedHdr.PacketNumber != pn {
		t.Fatalf("packet number mismatch: got %d, want %d", parsedHdr.PacketNumber, pn)
	}
	if !bytes.Equal(parsedHdr.DestCID, destCID) || !bytes.Equal(parsedHdr.SrcCID, srcCID) {
		t.Fatalf("CID mismatch")
	}
	if !bytes.Equal(parsedHdr.Token, token) {
		t.Fatalf("token mismatch")
	}

	// Verify SeaHash checksum
	recoveredPayload, err := VerifyAndSplitPayload(sealedPacket[:parsedHdr.HeaderLen], payloadWithTag)
	if err != nil {
		t.Fatalf("VerifyAndSplitPayload failed: %v", err)
	}
	if !bytes.Equal(recoveredPayload, payload) {
		t.Fatalf("payload mismatch")
	}

	// Corrupted payload verification
	corrupted := append([]byte(nil), sealedPacket...)
	corrupted[len(corrupted)-10] ^= 0x55
	_, corruptPayloadWithTag, _ := ParseHeader(corrupted, 8, 0)
	if _, err := VerifyAndSplitPayload(corrupted[:parsedHdr.HeaderLen], corruptPayloadWithTag); err == nil {
		t.Fatalf("expected checksum error on corrupted packet")
	}
}

func TestFramesRoundTrip(t *testing.T) {
	frames := []Frame{
		PingFrame{},
		AckFrame{
			LargestAcked: 105,
			AckDelay:     2,
			FirstRange:   5,
			Ranges: []AckRange{
				{Gap: 1, Length: 3},
				{Gap: 2, Length: 0},
			},
		},
		CryptoFrame{
			Offset: 128,
			Data:   []byte("crypto handshake bytes"),
		},
		StreamFrame{
			StreamID: 0,
			Offset:   1024,
			Fin:      true,
			Data:     []byte("tunnel stream payload data"),
		},
		MaxDataFrame{MaxData: 1048576},
		MaxStreamDataFrame{StreamID: 0, MaxStreamData: 262144},
		ConnectionCloseFrame{
			ErrorCode:    0,
			FrameType:    0,
			ReasonPhrase: "normal close",
		},
		HandshakeDoneFrame{},
		PaddingFrame{Length: 16},
	}

	var buf []byte
	for _, f := range frames {
		buf = f.Append(buf)
	}

	parsed, err := ParseFrames(buf)
	if err != nil {
		t.Fatalf("ParseFrames failed: %v", err)
	}

	if len(parsed) != len(frames) {
		t.Fatalf("frame count mismatch: got %d, want %d", len(parsed), len(frames))
	}

	for i := range frames {
		if !reflect.DeepEqual(frames[i], parsed[i]) {
			t.Fatalf("frame %d mismatch:\n got: %+v\nwant: %+v", i, parsed[i], frames[i])
		}
	}
}
