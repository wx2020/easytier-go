// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const DefaultMaxStreamFrameSize = 2000

// MarshalStreamFrame wraps a peer packet in the TCP/Unix four-byte
// little-endian body-length prefix used by EasyTier 2.6.4.
func MarshalStreamFrame(packet Packet) ([]byte, error) {
	body, err := packet.MarshalBody()
	if err != nil {
		return nil, err
	}
	if uint64(len(body)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("stream frame exceeds uint32 length: %d", len(body))
	}

	frame := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}

// ReadStreamFrame reads exactly one bounded TCP or Unix EasyTier frame.
func ReadStreamFrame(reader io.Reader, maxFrameSize int) (Packet, error) {
	if maxFrameSize < PeerManagerHeaderSize {
		return Packet{}, fmt.Errorf("maximum frame size %d is smaller than peer header", maxFrameSize)
	}

	var lengthBuffer [4]byte
	if _, err := io.ReadFull(reader, lengthBuffer[:]); err != nil {
		return Packet{}, fmt.Errorf("read stream frame length: %w", err)
	}

	bodyLength := binary.LittleEndian.Uint32(lengthBuffer[:])
	if bodyLength < PeerManagerHeaderSize {
		return Packet{}, fmt.Errorf("stream frame body too short: %d", bodyLength)
	}
	if uint64(bodyLength) > uint64(maxFrameSize) {
		return Packet{}, fmt.Errorf("stream frame body too long: %d", bodyLength)
	}

	body := make([]byte, bodyLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return Packet{}, fmt.Errorf("read stream frame body: %w", err)
	}
	return ParseBody(body)
}

// WriteStreamFrame serializes and writes one complete TCP or Unix frame.
func WriteStreamFrame(writer io.Writer, packet Packet) error {
	frame, err := MarshalStreamFrame(packet)
	if err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if err != nil {
			return fmt.Errorf("write stream frame: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("write stream frame: %w", io.ErrShortWrite)
		}
		frame = frame[n:]
	}
	return nil
}
