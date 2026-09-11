// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package webclient implements configuration-server sessions over the shared
// TCP, UDP, and WebSocket packet transports.
package webclient

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	DefaultMaxFrameSize        = 64 * 1024
	DefaultHeartbeatInterval   = 30 * time.Second
	DefaultReconnectMinBackoff = 100 * time.Millisecond
	DefaultReconnectMaxBackoff = 5 * time.Second
)

// MessageType identifies a configuration-server message.
type MessageType string

const (
	MessageTypeRegister     MessageType = "register"
	MessageTypeHeartbeat    MessageType = "heartbeat"
	MessageTypeConfigUpdate MessageType = "config_update"
	MessageRegister                     = MessageTypeRegister
	MessageHeartbeat                    = MessageTypeHeartbeat
	MessageConfigUpdate                 = MessageTypeConfigUpdate
)

// MachineRegistration identifies a machine to the configuration server.
type MachineRegistration struct {
	MachineID string `json:"machine_id"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
}

// RegistrationMessage is an alias for the typed registration payload.
type RegistrationMessage = MachineRegistration

// RegisterMessage is an alias for the typed registration payload.
type RegisterMessage = MachineRegistration

// MachineHeartbeat refreshes a registered machine session.
type MachineHeartbeat struct {
	MachineID string `json:"machine_id"`
}

// HeartbeatMessage is an alias for the typed heartbeat payload.
type HeartbeatMessage = MachineHeartbeat

// ConfigUpdate carries a JSON configuration document to a machine.
type ConfigUpdate struct {
	Version string          `json:"version,omitempty"`
	Config  json.RawMessage `json:"config"`
}

// ConfigUpdateMessage is an alias for the typed configuration payload.
type ConfigUpdateMessage = ConfigUpdate

// Message is the wire envelope. Exactly one payload is set according to Type.
type Message struct {
	Type         MessageType
	Registration *MachineRegistration
	Heartbeat    *MachineHeartbeat
	ConfigUpdate *ConfigUpdate
}

type wireMessage struct {
	Type      MessageType     `json:"type"`
	MachineID string          `json:"machine_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Version   string          `json:"version,omitempty"`
	Config    json.RawMessage `json:"config,omitempty"`
}

func (m Message) MarshalJSON() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	wire := wireMessage{Type: m.Type}
	switch m.Type {
	case MessageTypeRegister:
		wire.MachineID, wire.Name, wire.Version = m.Registration.MachineID, m.Registration.Name, m.Registration.Version
	case MessageTypeHeartbeat:
		wire.MachineID = m.Heartbeat.MachineID
	case MessageTypeConfigUpdate:
		wire.Version, wire.Config = m.ConfigUpdate.Version, m.ConfigUpdate.Config
	}
	return json.Marshal(wire)
}

func (m *Message) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire wireMessage
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	result := Message{Type: wire.Type}
	switch wire.Type {
	case MessageTypeRegister:
		result.Registration = &MachineRegistration{MachineID: wire.MachineID, Name: wire.Name, Version: wire.Version}
	case MessageTypeHeartbeat:
		result.Heartbeat = &MachineHeartbeat{MachineID: wire.MachineID}
	case MessageTypeConfigUpdate:
		result.ConfigUpdate = &ConfigUpdate{Version: wire.Version, Config: wire.Config}
	default:
		return fmt.Errorf("unknown webclient message type %q", wire.Type)
	}
	if err := result.validate(); err != nil {
		return err
	}
	*m = result
	return nil
}

func (m Message) validate() error {
	switch m.Type {
	case MessageTypeRegister:
		if m.Registration == nil {
			return errors.New("registration message payload is missing")
		}
		if m.Heartbeat != nil || m.ConfigUpdate != nil {
			return errors.New("registration message has multiple payloads")
		}
		if m.Registration.MachineID == "" {
			return errors.New("machine ID is empty")
		}
	case MessageTypeHeartbeat:
		if m.Heartbeat == nil {
			return errors.New("heartbeat message payload is missing")
		}
		if m.Registration != nil || m.ConfigUpdate != nil {
			return errors.New("heartbeat message has multiple payloads")
		}
		if m.Heartbeat.MachineID == "" {
			return errors.New("machine ID is empty")
		}
	case MessageTypeConfigUpdate:
		if m.ConfigUpdate == nil {
			return errors.New("config update payload is missing")
		}
		if m.Registration != nil || m.Heartbeat != nil {
			return errors.New("config update message has multiple payloads")
		}
		if len(bytes.TrimSpace(m.ConfigUpdate.Config)) == 0 || !json.Valid(m.ConfigUpdate.Config) {
			return errors.New("config update contains invalid JSON")
		}
	default:
		return fmt.Errorf("unknown webclient message type %q", m.Type)
	}
	return nil
}

// NewRegistrationMessage creates a registration envelope.
func NewRegistrationMessage(registration MachineRegistration) Message {
	return Message{Type: MessageTypeRegister, Registration: &registration}
}

// NewHeartbeatMessage creates a heartbeat envelope.
func NewHeartbeatMessage(heartbeat MachineHeartbeat) Message {
	return Message{Type: MessageTypeHeartbeat, Heartbeat: &heartbeat}
}

// NewConfigUpdateMessage creates a configuration update envelope.
func NewConfigUpdateMessage(update ConfigUpdate) Message {
	return Message{Type: MessageTypeConfigUpdate, ConfigUpdate: &update}
}

// WriteFrame writes one bounded, big-endian uint32 length-prefixed payload.
func WriteFrame(w io.Writer, payload []byte, maxSize int) error {
	maxSize = normalizedMaxFrameSize(maxSize)
	if len(payload) > maxSize {
		return fmt.Errorf("webclient frame is %d bytes, maximum is %d", len(payload), maxSize)
	}
	if uint64(len(payload)) > uint64(^uint32(0)) {
		return errors.New("webclient frame is too large for length prefix")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if err := writeFull(w, prefix[:]); err != nil {
		return fmt.Errorf("write webclient frame length: %w", err)
	}
	if err := writeFull(w, payload); err != nil {
		return fmt.Errorf("write webclient frame: %w", err)
	}
	return nil
}

// ReadFrame reads one bounded, big-endian uint32 length-prefixed payload.
func ReadFrame(r io.Reader, maxSize int) ([]byte, error) {
	maxSize = normalizedMaxFrameSize(maxSize)
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("read webclient frame length: %w", err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if uint64(length) > uint64(maxSize) {
		return nil, fmt.Errorf("webclient frame is %d bytes, maximum is %d", length, maxSize)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read webclient frame: %w", err)
	}
	return payload, nil
}

// WriteMessage writes one typed JSON message in a bounded frame.
func WriteMessage(w io.Writer, message Message, maxSize int) error {
	payload, err := MarshalMessage(message, maxSize)
	if err != nil {
		return err
	}
	return WriteFrame(w, payload, maxSize)
}

// ReadMessage reads and validates one typed JSON message from a bounded frame.
func ReadMessage(r io.Reader, maxSize int) (Message, error) {
	payload, err := ReadFrame(r, maxSize)
	if err != nil {
		return Message{}, err
	}
	return UnmarshalMessage(payload)
}

// MarshalMessage encodes one typed message and enforces the JSON size bound.
func MarshalMessage(message Message, maxSize int) ([]byte, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshal webclient message: %w", err)
	}
	if len(payload) > normalizedMaxFrameSize(maxSize) {
		return nil, fmt.Errorf("webclient message is %d bytes, maximum is %d", len(payload), normalizedMaxFrameSize(maxSize))
	}
	return payload, nil
}

// UnmarshalMessage decodes and validates one typed JSON message.
func UnmarshalMessage(payload []byte) (Message, error) {
	var message Message
	if err := json.Unmarshal(payload, &message); err != nil {
		return Message{}, fmt.Errorf("unmarshal webclient message: %w", err)
	}
	return message, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("webclient message contains multiple JSON values")
		}
		return err
	}
	return nil
}

func normalizedMaxFrameSize(maxSize int) int {
	if maxSize <= 0 {
		return DefaultMaxFrameSize
	}
	return maxSize
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := w.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
