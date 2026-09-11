// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"bytes"
	"io"
	"testing"
)

func TestStreamFrameRoundTrip(t *testing.T) {
	packet := Packet{
		Header:  PeerManagerHeader{FromPeerID: 1, ToPeerID: 2, PacketType: PacketTypePing},
		Payload: []byte{1, 2, 3, 4},
	}
	frame, err := MarshalStreamFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[:4], []byte{20, 0, 0, 0}) {
		t.Fatalf("frame prefix = %x", frame[:4])
	}

	got, err := ReadStreamFrame(bytes.NewReader(frame), DefaultMaxStreamFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.FromPeerID != 1 || got.Header.ToPeerID != 2 || got.Header.PacketType != PacketTypePing {
		t.Fatalf("header = %#v", got.Header)
	}
	if !bytes.Equal(got.Payload, packet.Payload) {
		t.Fatalf("payload = %x", got.Payload)
	}
}

func TestReadStreamFrameRejectsUnsafeAndTruncatedFrames(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		max  int
	}{
		{"short body", []byte{15, 0, 0, 0}, DefaultMaxStreamFrameSize},
		{"oversized body", []byte{0xd1, 0x07, 0, 0}, DefaultMaxStreamFrameSize},
		{"truncated body", []byte{16, 0, 0, 0, 0}, DefaultMaxStreamFrameSize},
		{"invalid max", nil, 15},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ReadStreamFrame(bytes.NewReader(test.data), test.max)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestWriteStreamFramePropagatesWriterError(t *testing.T) {
	err := WriteStreamFrame(failingWriter{}, Packet{})
	if err == nil {
		t.Fatal("expected writer error")
	}
}

func TestWriteStreamFrameHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{}
	if err := WriteStreamFrame(writer, Packet{Payload: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if len(writer.data) != 23 {
		t.Fatalf("wrote %d bytes, want 23", len(writer.data))
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

type shortWriter struct {
	data []byte
}

func (w *shortWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	w.data = append(w.data, data[0])
	return 1, nil
}
