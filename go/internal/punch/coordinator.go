// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package punch

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/EasyTier/EasyTier/go/internal/nat"
	"github.com/EasyTier/EasyTier/go/internal/proto/common"
	"github.com/EasyTier/EasyTier/go/internal/rpc"
	"github.com/EasyTier/EasyTier/go/internal/stun"
	"github.com/EasyTier/EasyTier/go/internal/transport"
)

// Coordinator loop and retry cadence.
const (
	// DefaultLoopInterval paces candidate collection.
	DefaultLoopInterval = 5 * time.Second
	// BlacklistTimeout is how long a peer stays blacklisted after the
	// remote rejected the punch service.
	BlacklistTimeout = time.Hour
)

// Candidate describes one remote peer eligible for punching.
type Candidate struct {
	PeerID     uint32
	UDPNatType common.NatType
}

// CandidateSource returns the current punch candidates.
type CandidateSource func() []Candidate

// RecentTraffic reports whether the peer carried data recently. It gates
// punching when lazy P2P is enabled.
type RecentTraffic func(peerID uint32) bool

// Config wires the coordinator to its collaborators.
type Config struct {
	MyPeerID uint32
	Domain   string
	RPC      *rpc.PeerRpcManager
	Stun     stun.Source
	Mapper   PortMapper

	DisableUDPHolePunching bool
	DisableSymHolePunching bool
	DisableP2P             bool
	NeedP2P                bool
	LazyP2P                bool

	Candidates    CandidateSource
	RecentTraffic RecentTraffic

	// OnClientSession upgrades a client-side punched session into an
	// authenticated peer connection.
	OnClientSession func(ctx context.Context, session *transport.UDPSession, dstPeerID uint32) error
	// OnServerSession receives sessions accepted by the punch listeners.
	OnServerSession func(session *transport.UDPSession)

	// LoopInterval overrides DefaultLoopInterval when positive.
	LoopInterval time.Duration
}

// Coordinator drives UDP hole punching: it registers the punch RPC service,
// periodically collects candidates, and runs the strategy tasks.
type Coordinator struct {
	cfg     Config
	clients *Clients
	pool    *ListenerPool
	service *Service

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	demand  chan struct{}
	startWg sync.WaitGroup

	mu     sync.Mutex
	active map[uint32]struct{}
	closed bool
}

// NewCoordinator builds a coordinator. Start registers the service and
// begins the collection loop.
func NewCoordinator(cfg Config) *Coordinator {
	if cfg.LoopInterval <= 0 {
		cfg.LoopInterval = DefaultLoopInterval
	}
	clients := &Clients{
		RPC:              cfg.RPC,
		Domain:           cfg.Domain,
		MyPeerID:         cfg.MyPeerID,
		Stun:             cfg.Stun,
		Mapper:           cfg.Mapper,
		Blacklist:        NewTimedSet(BlacklistTimeout),
		ManagedLocalAddr: nil,
	}
	pool := NewListenerPool(cfg.Stun, cfg.Mapper, cfg.OnServerSession)
	return &Coordinator{
		cfg:     cfg,
		clients: clients,
		pool:    pool,
		service: NewService(pool, cfg.Stun),
		demand:  make(chan struct{}, 1),
		active:  make(map[uint32]struct{}),
	}
}

// Start registers the punch service and launches the collection loop.
func (c *Coordinator) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("punch coordinator context is nil")
	}
	if c.cfg.DisableUDPHolePunching {
		return nil
	}
	if err := c.cfg.RPC.Register(c.cfg.Domain, c.service); err != nil {
		return err
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.pool.Start(c.ctx)
	c.wg.Add(1)
	go c.loop()
	return nil
}

// Stop cancels the loop, tears down the socket pools, and unregisters.
func (c *Coordinator) Stop() {
	c.mu.Lock()
	if c.closed || c.cancel == nil {
		c.mu.Unlock()
		return
	}
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()

	cancel()
	c.wg.Wait()
	c.clients.ClearUDPArray()
	c.pool.Close()
	c.cfg.RPC.Unregister(c.cfg.Domain, ServiceName)
}

// NotifyDemand wakes the collection loop immediately.
func (c *Coordinator) NotifyDemand() {
	select {
	case c.demand <- struct{}{}:
	default:
	}
}

func (c *Coordinator) loop() {
	defer c.wg.Done()
	interval := c.cfg.LoopInterval
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.demand:
		case <-timer.C:
		}
		c.collect()
		timer.Reset(interval)
	}
}

// collect filters candidates and launches one strategy task per peer.
func (c *Coordinator) collect() {
	if c.cfg.Candidates == nil {
		return
	}
	myNatInfo := nat.NewUdpNatType(c.cfg.Stun.GetStunInfo().GetUdpNatType())
	if !myNatInfo.IsSym() {
		c.clients.ClearUDPArray()
	}
	if myNatInfo.IsOpen() {
		return
	}
	c.clients.Blacklist.Cleanup()

	for _, candidate := range c.cfg.Candidates() {
		if candidate.PeerID == c.cfg.MyPeerID {
			continue
		}
		if !c.peerAllowed(candidate.PeerID) {
			continue
		}
		dstNatInfo := nat.NewUdpNatType(candidate.UDPNatType)
		if c.clients.Blacklist.Contains(candidate.PeerID) {
			continue
		}
		if !nat.CanPunchAsClient(myNatInfo, dstNatInfo, c.cfg.MyPeerID, candidate.PeerID, c.cfg.DisableSymHolePunching) {
			continue
		}
		c.mu.Lock()
		if _, running := c.active[candidate.PeerID]; running {
			c.mu.Unlock()
			continue
		}
		c.active[candidate.PeerID] = struct{}{}
		c.mu.Unlock()

		taskCtx, taskCancel := context.WithCancel(c.ctx)
		c.wg.Add(1)
		go func(peerID uint32, my, dst nat.UdpNatType) {
			defer c.wg.Done()
			defer c.clearActive(peerID)
			defer taskCancel()
			c.runPunchTask(taskCtx, peerID, my, dst)
		}(candidate.PeerID, myNatInfo, dstNatInfo)
	}
}

// peerAllowed applies the local P2P policy: background punching requires
// non-lazy mode unless the peer recently carried traffic.
func (c *Coordinator) peerAllowed(peerID uint32) bool {
	if c.cfg.DisableP2P && !c.cfg.NeedP2P {
		return false
	}
	if !c.cfg.LazyP2P {
		return true
	}
	if c.cfg.RecentTraffic == nil {
		return false
	}
	return c.cfg.RecentTraffic(peerID)
}

func (c *Coordinator) clearActive(peerID uint32) {
	c.mu.Lock()
	delete(c.active, peerID)
	c.mu.Unlock()
}

// runPunchTask runs the strategy loop for one peer until a tunnel is
// delivered or the coordinator shuts down.
func (c *Coordinator) runPunchTask(ctx context.Context, peerID uint32, my, dst nat.UdpNatType) {
	method := nat.SelectPunchMethod(my, dst, c.cfg.DisableSymHolePunching)
	switch method {
	case nat.PunchMethodConeToCone:
		c.runConeToCone(ctx, peerID)
	case nat.PunchMethodSymToCone:
		c.runSymToCone(ctx, peerID, my)
	case nat.PunchMethodEasySymToEasySym:
		c.runBothEasySym(ctx, peerID, my, dst)
	default:
	}
}

// runConeToCone retries cone punching with the reference backoff ladder.
func (c *Coordinator) runConeToCone(ctx context.Context, peerID uint32) {
	backoff := NewBackOff([]int{1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000})
	for {
		if err := Sleep(ctx, backoff.Next()); err != nil {
			return
		}
		session, err := c.clients.ConePunch(ctx, peerID)
		switch {
		case err != nil:
			backoff.Rollback()
		case session != nil:
			if handoffErr := c.cfg.OnClientSession(ctx, session, peerID); handoffErr != nil {
				backoff.Rollback()
				continue
			}
			return
		}
	}
}

// runSymToCone always tries cone first, then the symmetric strategies under
// the serialized symmetric punch lock.
func (c *Coordinator) runSymToCone(ctx context.Context, peerID uint32, my nat.UdpNatType) {
	backoff := NewBackOff([]int{1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000})
	round := uint32(0)
	portIdx := randomUint32()
	for {
		if err := Sleep(ctx, backoff.Next()); err != nil {
			return
		}
		session, err := c.clients.ConePunch(ctx, peerID)
		if err == nil && session != nil {
			if handoffErr := c.cfg.OnClientSession(ctx, session, peerID); handoffErr != nil {
				backoff.Rollback()
				continue
			}
			return
		}

		c.clients.LockSym()
		session, err = c.clients.SymToConePunch(ctx, peerID, round, &portIdx, my)
		c.clients.UnlockSym()
		switch {
		case err != nil:
			backoff.Rollback()
			if round > 0 {
				round--
			}
		case session != nil:
			if handoffErr := c.cfg.OnClientSession(ctx, session, peerID); handoffErr != nil {
				backoff.Rollback()
				if round > 0 {
					round--
				}
				continue
			}
			return
		default:
			round++
		}
	}
}

// runBothEasySym always tries cone first, then the both-easy-symmetric
// strategy with busy rollback.
func (c *Coordinator) runBothEasySym(ctx context.Context, peerID uint32, my, dst nat.UdpNatType) {
	backoff := NewBackOff([]int{1000, 1000, 2000, 4000, 4000, 8000, 8000, 16000, 64000})
	for {
		if err := Sleep(ctx, backoff.Next()); err != nil {
			return
		}
		session, err := c.clients.ConePunch(ctx, peerID)
		if err == nil && session != nil {
			if handoffErr := c.cfg.OnClientSession(ctx, session, peerID); handoffErr != nil {
				backoff.Rollback()
				continue
			}
			return
		}

		c.clients.LockSym()
		session, busy, err := c.clients.BothEasySymPunch(ctx, peerID, my, dst)
		c.clients.UnlockSym()
		if busy {
			backoff.Rollback()
			continue
		}
		switch {
		case err != nil:
			backoff.Rollback()
		case session != nil:
			if handoffErr := c.cfg.OnClientSession(ctx, session, peerID); handoffErr != nil {
				backoff.Rollback()
				continue
			}
			return
		}
	}
}
