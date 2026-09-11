// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/stats"
)

const (
	defaultPingInterval       = 1 * time.Second
	pingResponseTimeout       = 2 * time.Second
	maxConcurrentPingTasks    = 5
	maxBackoffIdx             = 5
	maxConsecutiveLosses      = 5
	lossWindowCapacity        = 100
	pingResultChannelCapacity = 100
	pongChannelCapacity       = 64
)

// ThroughputSnapshot tracks TX and RX packet counts for one peer connection.
// Accessor methods avoid exposing atomic fields with conflicting names.
type ThroughputSnapshot struct {
	txPackets atomic.Uint64
	rxPackets atomic.Uint64
}

func (t *ThroughputSnapshot) IncTX()            { t.txPackets.Add(1) }
func (t *ThroughputSnapshot) IncRX()            { t.rxPackets.Add(1) }
func (t *ThroughputSnapshot) TXPackets() uint64 { return t.txPackets.Load() }
func (t *ThroughputSnapshot) RXPackets() uint64 { return t.rxPackets.Load() }

// WindowLatency is a fixed-capacity sliding window of samples.
type WindowLatency struct {
	mu      sync.Mutex
	samples []uint32
	count   int
}

func NewWindowLatency(capacity int) *WindowLatency {
	return &WindowLatency{samples: make([]uint32, 0, capacity)}
}

// Record appends value, overwriting the oldest sample once full.
func (w *WindowLatency) Record(value uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.samples) < cap(w.samples) {
		w.samples = append(w.samples, value)
	} else {
		w.samples[w.count%cap(w.samples)] = value
	}
	w.count++
}

// Average returns the window mean, or zero when empty.
func (w *WindowLatency) Average() float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.samples) == 0 {
		return 0
	}
	var sum uint64
	for _, value := range w.samples {
		sum += uint64(value)
	}
	return float64(sum) / float64(len(w.samples))
}

// PingResult is the outcome of one ping round trip.
type PingResult struct {
	Latency time.Duration
	Err     error
}

// pingIntervalController adapts the ping frequency based on throughput and
// loss, mirroring Rust PeerConnPinger's backoff logic.
type pingIntervalController struct {
	throughput *ThroughputSnapshot
	lossCount  *atomic.Uint32

	logicTime         uint64
	lastSendLogicTime uint64

	backoffIdx    int32
	maxBackoffIdx int32

	lastTXPackets uint64
	lastRXPackets uint64

	ticker *time.Ticker
}

func newPingIntervalController(throughput *ThroughputSnapshot, lossCount *atomic.Uint32) *pingIntervalController {
	return &pingIntervalController{
		throughput:    throughput,
		lossCount:     lossCount,
		ticker:        time.NewTicker(defaultPingInterval),
		maxBackoffIdx: maxBackoffIdx,
	}
}

func (c *pingIntervalController) tick(ctx context.Context) bool {
	if ctx == nil {
		<-c.ticker.C
		c.logicTime++
		return true
	}
	select {
	case <-c.ticker.C:
		c.logicTime++
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *pingIntervalController) stop() {
	c.ticker.Stop()
}

func (c *pingIntervalController) txIncrease() bool {
	return c.throughput.TXPackets() > c.lastTXPackets
}

func (c *pingIntervalController) rxIncrease() bool {
	return c.throughput.RXPackets() > c.lastRXPackets
}

func (c *pingIntervalController) shouldSendPing() bool {
	if c.lossCount.Load() > 0 {
		c.backoffIdx = 0
	} else if c.txIncrease() && !c.rxIncrease() {
		c.backoffIdx = 0
	}

	c.lastTXPackets = c.throughput.TXPackets()
	c.lastRXPackets = c.throughput.RXPackets()

	if c.logicTime-c.lastSendLogicTime < uint64(1<<c.backoffIdx) {
		return false
	}

	if c.backoffIdx < c.maxBackoffIdx {
		c.backoffIdx++
	}

	if c.backoffIdx > c.maxBackoffIdx-2 && rand.Float64() < 0.2 {
		c.backoffIdx--
	}

	c.lastSendLogicTime = c.logicTime
	return true
}

// PeerConnPinger keeps a peer connection healthy by sending periodic pings.
type PeerConnPinger struct {
	myPeerID uint32
	peerID   uint32
	manager  *PeerConnectionManager

	latencyStats   *WindowLatency
	lossRateStats  *atomic.Uint32
	throughput     *ThroughputSnapshot
	controlMetrics *stats.Counters

	pongCh chan protocol.Packet

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// PeerConnPingerConfig configures one peer pinger.
type PeerConnPingerConfig struct {
	MyPeerID       uint32
	PeerID         uint32
	Manager        *PeerConnectionManager
	LatencyStats   *WindowLatency
	LossRateStats  *atomic.Uint32
	Throughput     *ThroughputSnapshot
	ControlMetrics *stats.Counters
}

func NewPeerConnPinger(config PeerConnPingerConfig) (*PeerConnPinger, error) {
	if config.Manager == nil {
		return nil, errors.New("peer connection manager is required")
	}
	if config.LatencyStats == nil {
		config.LatencyStats = NewWindowLatency(lossWindowCapacity)
	}
	if config.LossRateStats == nil {
		config.LossRateStats = &atomic.Uint32{}
	}
	if config.Throughput == nil {
		config.Throughput = &ThroughputSnapshot{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &PeerConnPinger{
		myPeerID:       config.MyPeerID,
		peerID:         config.PeerID,
		manager:        config.Manager,
		latencyStats:   config.LatencyStats,
		lossRateStats:  config.LossRateStats,
		throughput:     config.Throughput,
		controlMetrics: config.ControlMetrics,
		pongCh:         make(chan protocol.Packet, pongChannelCapacity),
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

func newPingPacket(myPeerID, peerID, seq uint32) protocol.Packet {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, seq)
	return protocol.Packet{
		Header: protocol.PeerManagerHeader{
			FromPeerID: myPeerID,
			ToPeerID:   peerID,
			PacketType: protocol.PacketTypePing,
		},
		Payload: payload,
	}
}

func (p *PeerConnPinger) doPingPongOnce(ctx context.Context, seq uint32) (time.Duration, error) {
	req := newPingPacket(p.myPeerID, p.peerID, seq)
	if err := p.manager.Send(ctx, p.peerID, req); err != nil {
		return 0, err
	}
	if p.controlMetrics != nil {
		p.controlMetrics.Add("ping_tx_bytes", uint64(len(req.Payload)))
	}

	start := time.Now()
	timeoutCtx, cancel := context.WithTimeout(ctx, pingResponseTimeout)
	defer cancel()

	for {
		select {
		case packet := <-p.pongCh:
			if len(packet.Payload) < 4 {
				continue
			}
			respSeq := binary.LittleEndian.Uint32(packet.Payload[:4])
			if respSeq == seq {
				return time.Since(start), nil
			}
		case <-timeoutCtx.Done():
			return 0, errors.New("ping response timeout")
		case <-p.ctx.Done():
			return 0, p.ctx.Err()
		}
	}
}

// HandlePong feeds a received pong packet into the pinger. Callers should
// route inbound Pong packets here after receiving them from the manager.
func (p *PeerConnPinger) HandlePong(packet protocol.Packet) {
	select {
	case p.pongCh <- packet:
	default:
	}
}

// Start launches the ping controller and result loop.
func (p *PeerConnPinger) Start() {
	p.wg.Add(1)
	go p.run()
}

func (p *PeerConnPinger) run() {
	defer p.wg.Done()

	lossCounter := &atomic.Uint32{}
	controller := newPingIntervalController(p.throughput, lossCounter)
	defer controller.stop()

	pingResults := make(chan PingResult, pingResultChannelCapacity)
	lossWindow := NewWindowLatency(lossWindowCapacity)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		var seq uint32
		runningTasks := 0
		for {
			if !controller.tick(p.ctx) {
				return
			}

			for runningTasks > 0 {
				select {
				case result := <-pingResults:
					runningTasks--
					p.recordResult(result, lossWindow, lossCounter)
				default:
					goto doneDrain
				}
			}
		doneDrain:

			if runningTasks >= maxConcurrentPingTasks {
				select {
				case result := <-pingResults:
					runningTasks--
					p.recordResult(result, lossWindow, lossCounter)
				case <-p.ctx.Done():
					return
				}
			}

			if !controller.shouldSendPing() {
				continue
			}

			currentSeq := seq
			seq++
			runningTasks++
			go func() {
				latency, err := p.doPingPongOnce(p.ctx, currentSeq)
				select {
				case pingResults <- PingResult{Latency: latency, Err: err}:
				case <-p.ctx.Done():
				}
			}()
		}
	}()

	var lastRXPackets uint64
	for {
		select {
		case result := <-pingResults:
			if result.Err == nil {
				p.latencyStats.Record(uint32(result.Latency.Microseconds()))
				lossWindow.Record(0)
			} else {
				lossWindow.Record(1)
				lossCounter.Add(1)
			}

			lossRate := lossWindow.Average()
			currentRX := p.throughput.RXPackets()
			if currentRX != lastRXPackets {
				lossCounter.Store(0)
			}

			p.lossRateStats.Store(uint32(lossRate * 100))

			if lossCounter.Load() >= maxConsecutiveLosses {
				// The link is dead: stop the sender loop as well. run()'s
				// deferred controller.stop() halts the shared ticker, so
				// without cancel the sender would park in tick() forever
				// and Stop() would hang.
				p.cancel()
				return
			}

			lastRXPackets = currentRX

		case <-p.ctx.Done():
			return
		}
	}
}

func (p *PeerConnPinger) recordResult(result PingResult, lossWindow *WindowLatency, lossCounter *atomic.Uint32) {
	if result.Err == nil {
		p.latencyStats.Record(uint32(result.Latency.Microseconds()))
		lossWindow.Record(0)
	} else {
		lossWindow.Record(1)
		lossCounter.Add(1)
	}
}

// Stop stops all pinging tasks and waits for them to exit.
func (p *PeerConnPinger) Stop() {
	p.cancel()
	p.wg.Wait()
}

// Latency returns the smoothed round-trip latency towards the peer.
func (p *PeerConnPinger) Latency() time.Duration {
	return time.Duration(p.latencyStats.Average()) * time.Microsecond
}

// LossRate returns the recent loss ratio in the range [0, 1].
func (p *PeerConnPinger) LossRate() float64 {
	return float64(p.lossRateStats.Load()) / 100.0
}

// Throughput exposes the TX/RX counters fed by the connection manager's
// send/receive paths. The ping interval controller reads them to adapt its
// frequency, mirroring Rust PeerConnPinger's throughput-driven backoff.
func (p *PeerConnPinger) Throughput() *ThroughputSnapshot {
	return p.throughput
}
