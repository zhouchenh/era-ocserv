package e2e_test

import (
	"io"
	"sync"

	"github.com/zhouchenh/era-ocserv/internal/bridge"
)

// fakeTunQueue is an in-memory replacement for *tun.Queue used by the
// bridge in tests. Read blocks until the test pushes a packet through
// Inject; Write hands the packet to whichever test goroutine is
// draining the Out channel.
//
// Closing the queue makes pending Read calls return io.EOF (matching
// the real device on close) and subsequent Writes return io.ErrClosedPipe.
type fakeTunQueue struct {
	// in carries packets the test wants the bridge to read out of the
	// tun (i.e. inner packets from "the rest of the host" destined for
	// a connected client).
	in chan []byte
	// out carries packets the bridge wrote into the tun (i.e. inner
	// packets the client sent over the tunnel, headed for upstream).
	out chan []byte

	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

func newFakeTunQueue() *fakeTunQueue {
	return &fakeTunQueue{
		in:   make(chan []byte, 16),
		out:  make(chan []byte, 16),
		done: make(chan struct{}),
	}
}

// Read implements the bridge's tunQueueIO. It blocks on q.in.
func (q *fakeTunQueue) Read(p []byte) (int, error) {
	select {
	case pkt, ok := <-q.in:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, pkt)
		return n, nil
	case <-q.done:
		return 0, io.EOF
	}
}

// Write implements the bridge's tunQueueIO. The packet is copied
// onto q.out so test code can drain it on its own goroutine.
func (q *fakeTunQueue) Write(p []byte) (int, error) {
	pkt := make([]byte, len(p))
	copy(pkt, p)
	select {
	case q.out <- pkt:
		return len(p), nil
	case <-q.done:
		return 0, io.ErrClosedPipe
	}
}

// Close makes future reads return EOF and future writes fail.
// Idempotent.
func (q *fakeTunQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	close(q.done)
}

// Inject pushes a packet into the queue so the bridge's tun reader
// loop will dispatch it to the matching client tunnel. Returns false
// if the queue is full or already closed; tests should not race on
// this beyond their own injection volume.
func (q *fakeTunQueue) Inject(pkt []byte) bool {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case q.in <- cp:
		return true
	case <-q.done:
		return false
	}
}

// fakeTunDevice satisfies the bridge's tunDevice interface with a
// fixed set of fake queues. Tests construct one with the queue count
// they want (usually 1 for predictability).
type fakeTunDevice struct {
	queues []*fakeTunQueue
}

func newFakeTunDevice(queueCount int) *fakeTunDevice {
	if queueCount < 1 {
		queueCount = 1
	}
	qs := make([]*fakeTunQueue, queueCount)
	for i := range qs {
		qs[i] = newFakeTunQueue()
	}
	return &fakeTunDevice{queues: qs}
}

// Queues implements bridge.Device. The returned slice is a copy
// converted to the bridge interface type.
func (d *fakeTunDevice) Queues() []bridge.QueueIO {
	out := make([]bridge.QueueIO, len(d.queues))
	for i, q := range d.queues {
		out[i] = q
	}
	return out
}

// QueuesTyped returns the concrete fakeTunQueue slice for tests to
// drive directly (Inject / drain Out).
func (d *fakeTunDevice) QueuesTyped() []*fakeTunQueue { return d.queues }

// Close closes every queue. Idempotent across all queues.
func (d *fakeTunDevice) Close() {
	for _, q := range d.queues {
		q.Close()
	}
}

// Compile-time check that *fakeTunDevice satisfies bridge.Device.
var _ bridge.Device = (*fakeTunDevice)(nil)
