// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package peer

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/protocol"
	"github.com/EasyTier/EasyTier/go/internal/stats"
)

const (
	defaultPingInterval    = 1 * time.Second
	pingResponseTimeout    = 2 * time.Second
	maxConcurrentPingTasks = 5
	maxConsecutiveLosses   = 5
	lossWindowCapacity     = 100
	// latencyWindowCapacity matches the reference peer connection, which
	// averages the last 15 ping round trips (WindowLatency::new(15)). A wider
	// window keeps stale samples from a bad period in the number, which is
	// what made the peer table disagree with a fresh ping.
	latencyWindowCapacity     = 15
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

// debugPing enables verbose ping tracing (off by default; set ET_DEBUG_PING=1).
var debugPing = os.Getenv("ET_DEBUG_PING") != ""

// PingResult is the outcome of one ping round trip.
type PingResult struct {
	Latency time.Duration
	Err     error
}

// pingIntervalController paces the pings of a peer connection.
//
// The reference peer connection pings every second unconditionally (a fixed
// one-second interval), so the controller only has to make sure at most one
// ping is started per tick. The earlier exponential backoff thinned the pings
// out on an idle link, which left stale samples in the latency window and made
// the reported peer latency disagree with a fresh ping.
type pingIntervalController struct {
	throughput *ThroughputSnapshot
	lossCount  *atomic.Uint32

	logicTime         uint64
	lastSendLogicTime uint64

	lastTXPackets uint64
	lastRXPackets uint64

	ticker *time.Ticker
}

func newPingIntervalController(throughput *ThroughputSnapshot, lossCount *atomic.Uint32) *pingIntervalController {
	return &pingIntervalController{
		throughput: throughput,
		lossCount:  lossCount,
		ticker:     time.NewTicker(defaultPingInterval),
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
	c.lastTXPackets = c.throughput.TXPackets()
	c.lastRXPackets = c.throughput.RXPackets()

	if c.logicTime-c.lastSendLogicTime < 1 {
		return false
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

	// pendingPongs archives the pongs by their sequence number. A single
	// shared channel let concurrent pings consume each other's answer, which
	// showed up as a constant 50% loss and a wrong latency.
	pendingPongs map[uint32]protocol.Packet
	pongMu       sync.Mutex
	// nextSeq hands out globally unique sequence numbers, so a pong can be
	// matched to its ping even when a relaying node answers on behalf of the
	// peer we pinged.
	nextSeq *atomic.Uint32
	// outstanding records the sequence numbers of the pings still waiting for
	// an answer, so the manager can route a pong to the right pinger.
	outstanding map[uint32]struct{}

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
	// NextSeq hands out the ping sequence numbers. It is shared by all
	// pingers of a node so that a pong can be matched to the right ping even
	// when a relaying node answers on behalf of the peer we pinged.
	NextSeq *atomic.Uint32
}

func NewPeerConnPinger(config PeerConnPingerConfig) (*PeerConnPinger, error) {
	if config.Manager == nil {
		return nil, errors.New("peer connection manager is required")
	}
	if config.LatencyStats == nil {
		config.LatencyStats = NewWindowLatency(latencyWindowCapacity)
	}
	if config.LossRateStats == nil {
		config.LossRateStats = &atomic.Uint32{}
	}
	if config.Throughput == nil {
		config.Throughput = &ThroughputSnapshot{}
	}
	if config.NextSeq == nil {
		config.NextSeq = &atomic.Uint32{}
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
		pendingPongs:   make(map[uint32]protocol.Packet),
		outstanding:    make(map[uint32]struct{}),
		nextSeq:        config.NextSeq,
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
	if debugPing {
		log.Printf("ping: send seq=%d to peer %d", seq, p.peerID)
	}

	// Wait for the answer to this very sequence number. The reference uses a
	// broadcast receiver, so every in-flight ping sees its own answer; a
	// shared channel would hand one ping's answer to another one.
	for {
		if packet, ok := p.takePong(seq); ok {
			if len(packet.Payload) < 4 {
				if debugPing {
					log.Printf("ping: short pong payload %d bytes from peer %d", len(packet.Payload), packet.Header.FromPeerID)
				}
				return 0, errors.New("ping response is malformed")
			}
			if debugPing {
				log.Printf("ping: pong seq=%d for peer %d", seq, packet.Header.FromPeerID)
			}
			return time.Since(start), nil
		}
		select {
		case <-timeoutCtx.Done():
			if debugPing {
				log.Printf("ping: timeout waiting seq=%d from peer %d", seq, p.peerID)
			}
			return 0, errors.New("ping response timeout")
		case <-p.ctx.Done():
			return 0, p.ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// PeerID returns the peer this pinger probes. A pong only counts as this
// session's round trip when it arrives on that peer's session.
func (p *PeerConnPinger) PeerID() uint32 {
	return p.peerID
}

// AwaitingSeq reports whether this pinger still waits for the answer of the
// given sequence number, which lets the manager find the pinger a pong
// belongs to.
func (p *PeerConnPinger) AwaitingSeq(seq uint32) bool {
	p.pongMu.Lock()
	defer p.pongMu.Unlock()
	_, ok := p.outstanding[seq]
	return ok
}

// markOutstanding records that a ping is waiting for its answer.
func (p *PeerConnPinger) markOutstanding(seq uint32) {
	p.pongMu.Lock()
	defer p.pongMu.Unlock()
	p.outstanding[seq] = struct{}{}
}

// clearOutstanding forgets a ping that was answered or timed out.
func (p *PeerConnPinger) clearOutstanding(seq uint32) {
	p.pongMu.Lock()
	defer p.pongMu.Unlock()
	delete(p.outstanding, seq)
}

// takePong returns the archived answer for one sequence number.
func (p *PeerConnPinger) takePong(seq uint32) (protocol.Packet, bool) {
	p.pongMu.Lock()
	defer p.pongMu.Unlock()
	packet, ok := p.pendingPongs[seq]
	if ok {
		delete(p.pendingPongs, seq)
	}
	return packet, ok
}

// HandlePong feeds a received pong packet into the pinger. Callers should
// route inbound Pong packets here after receiving them from the manager.
func (p *PeerConnPinger) HandlePong(packet protocol.Packet) {
	if len(packet.Payload) < 4 {
		return
	}
	seq := binary.LittleEndian.Uint32(packet.Payload[:4])
	p.pongMu.Lock()
	defer p.pongMu.Unlock()
	// Keep the map bounded: a stale answer is of no use once its ping timed
	// out.
	if len(p.pendingPongs) >= pongChannelCapacity {
		for key := range p.pendingPongs {
			delete(p.pendingPongs, key)
			break
		}
	}
	p.pendingPongs[seq] = packet
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

			currentSeq := p.nextSeq.Add(1)
			p.markOutstanding(currentSeq)
			runningTasks++
			go func() {
				latency, err := p.doPingPongOnce(p.ctx, currentSeq)
				p.clearOutstanding(currentSeq)
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
				// The link is dead: the reference disconnects the peer
				// connection after five consecutive ping losses, which lets the
				// connector re-establish it and the pinger start over with
				// fresh samples. Stopping only the pinger left a dead session
				// behind and froze the reported latency.
				p.cancel()
				if p.manager != nil {
					_ = p.manager.ClosePeer(p.peerID)
				}
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

// Samples returns the number of latency samples the window holds.
func (p *PeerConnPinger) Samples() int {
	p.latencyStats.mu.Lock()
	defer p.latencyStats.mu.Unlock()
	return len(p.latencyStats.samples)
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
