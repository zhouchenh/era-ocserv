package udshandoff

import (
	"sync"
	"sync/atomic"

	"github.com/zhouchenh/era-ocserv/internal/proxyproto"
)

// Metrics is the metric surface the listener increments. It is dimensioned
// exactly as spec §8 requires:
//
//   - uds_incomplete_header_total — single counter (incremented on
//     ErrIncompleteHeader during stream/datagram parsing).
//   - uds_proxy_v2_invalid_signature_total — single counter (incremented on
//     ErrSignatureInvalid).
//   - uds_handoff_unknown_era_tlv_total{type, protocol} — counter keyed by
//     (tlv-type, protocol) pair.
//
// Per-protocol shape (handoff_start, handoff_invalid, flow_closed,
// flow_error) is logged structurally (see LogFields); only the three "wire
// shape" counters above are exported as numbers — they are the spec-named
// ones. Higher-level surfaces (per-protocol byte totals) ride on the
// existing telemetry.Collector. The listener calls Hooks.OnHandoff to bridge
// the two surfaces without coupling this package to telemetry.
//
// Metrics is safe for concurrent use. The zero value is ready to use.
type Metrics struct {
	incompleteHeader        atomic.Uint64
	proxyV2InvalidSignature atomic.Uint64

	mu             sync.RWMutex
	unknownERATLV  map[unknownERAKey]*atomic.Uint64
	handoffInvalid map[ProtocolName]*atomic.Uint64
	handoffAccept  map[ProtocolName]*atomic.Uint64
	frameRejected  map[ProtocolName]*atomic.Uint64
	oversizeDgram  atomic.Uint64
}

type unknownERAKey struct {
	Type     proxyproto.TLVType
	Protocol ProtocolName
}

// NewMetrics returns a zero-initialised *Metrics. The zero value is also
// usable; this constructor exists for symmetry.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// IncIncompleteHeader bumps uds_incomplete_header_total.
func (m *Metrics) IncIncompleteHeader() {
	if m == nil {
		return
	}
	m.incompleteHeader.Add(1)
}

// IncProxyV2InvalidSignature bumps uds_proxy_v2_invalid_signature_total.
func (m *Metrics) IncProxyV2InvalidSignature() {
	if m == nil {
		return
	}
	m.proxyV2InvalidSignature.Add(1)
}

// IncOversizeDatagram bumps the SOCK_DGRAM oversize counter (spec §2.6 +
// §8.1 row "payload size exceeds 64 KiB").
func (m *Metrics) IncOversizeDatagram() {
	if m == nil {
		return
	}
	m.oversizeDgram.Add(1)
}

// IncUnknownERATLV bumps uds_handoff_unknown_era_tlv_total{type, protocol}.
func (m *Metrics) IncUnknownERATLV(t proxyproto.TLVType, protocol ProtocolName) {
	if m == nil {
		return
	}
	key := unknownERAKey{Type: t, Protocol: protocol}
	m.mu.RLock()
	c, ok := m.unknownERATLV[key]
	m.mu.RUnlock()
	if ok {
		c.Add(1)
		return
	}
	m.mu.Lock()
	if m.unknownERATLV == nil {
		m.unknownERATLV = make(map[unknownERAKey]*atomic.Uint64)
	}
	if c, ok = m.unknownERATLV[key]; !ok {
		c = new(atomic.Uint64)
		m.unknownERATLV[key] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// IncHandoffInvalid bumps the per-protocol "rejected handoff" counter. The
// listener calls this on any of: malformed TLV, missing-mandatory, present-
// forbidden, spec-version mismatch (i.e. any case that closes the connection
// in spec §8.1).
func (m *Metrics) IncHandoffInvalid(protocol ProtocolName) {
	if m == nil {
		return
	}
	incPerProto(&m.mu, &m.handoffInvalid, protocol)
}

// IncHandoffAccept bumps the per-protocol "accepted handoff" counter (one
// per successful Accept that passed validation).
func (m *Metrics) IncHandoffAccept(protocol ProtocolName) {
	if m == nil {
		return
	}
	incPerProto(&m.mu, &m.handoffAccept, protocol)
}

// IncFrameRejected bumps the per-protocol "datagram rejected" counter
// (SOCK_DGRAM specific; e.g. fixed-header bad version).
func (m *Metrics) IncFrameRejected(protocol ProtocolName) {
	if m == nil {
		return
	}
	incPerProto(&m.mu, &m.frameRejected, protocol)
}

func incPerProto(mu *sync.RWMutex, mp *map[ProtocolName]*atomic.Uint64, p ProtocolName) {
	mu.RLock()
	c, ok := (*mp)[p]
	mu.RUnlock()
	if ok {
		c.Add(1)
		return
	}
	mu.Lock()
	if *mp == nil {
		*mp = make(map[ProtocolName]*atomic.Uint64)
	}
	if c, ok = (*mp)[p]; !ok {
		c = new(atomic.Uint64)
		(*mp)[p] = c
	}
	mu.Unlock()
	c.Add(1)
}

// Snapshot is a stable view of the counter values for readers (test
// assertions, the future /v1/metrics endpoint).
type Snapshot struct {
	IncompleteHeader        uint64
	ProxyV2InvalidSignature uint64
	OversizeDatagram        uint64
	UnknownERATLV           map[unknownERAKey]uint64
	HandoffInvalid          map[ProtocolName]uint64
	HandoffAccept           map[ProtocolName]uint64
	FrameRejected           map[ProtocolName]uint64
}

// Snapshot returns a copy of the current counters. Safe for concurrent use.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Snapshot{
		IncompleteHeader:        m.incompleteHeader.Load(),
		ProxyV2InvalidSignature: m.proxyV2InvalidSignature.Load(),
		OversizeDatagram:        m.oversizeDgram.Load(),
		UnknownERATLV:           make(map[unknownERAKey]uint64, len(m.unknownERATLV)),
		HandoffInvalid:          make(map[ProtocolName]uint64, len(m.handoffInvalid)),
		HandoffAccept:           make(map[ProtocolName]uint64, len(m.handoffAccept)),
		FrameRejected:           make(map[ProtocolName]uint64, len(m.frameRejected)),
	}
	for k, v := range m.unknownERATLV {
		s.UnknownERATLV[k] = v.Load()
	}
	for k, v := range m.handoffInvalid {
		s.HandoffInvalid[k] = v.Load()
	}
	for k, v := range m.handoffAccept {
		s.HandoffAccept[k] = v.Load()
	}
	for k, v := range m.frameRejected {
		s.FrameRejected[k] = v.Load()
	}
	return s
}

// LookupUnknownERATLV is a test/snapshot helper to read one key without
// allocating the full snapshot.
func (m *Metrics) LookupUnknownERATLV(t proxyproto.TLVType, p ProtocolName) uint64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.unknownERATLV[unknownERAKey{Type: t, Protocol: p}]
	if !ok {
		return 0
	}
	return c.Load()
}
