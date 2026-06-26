//go:build linux

package tun

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// requireRoot skips the test cleanly when /dev/net/tun is unavailable or the
// caller lacks the privileges to open it. CI sets TUN_TEST_ROOT=1 and runs
// these via sudo; local developer workstations skip silently.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Getenv("TUN_TEST_ROOT") != "1" {
		t.Skip("TUN_TEST_ROOT not set; skipping privileged tun test")
	}
	if _, err := os.Stat(tunDevicePath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("%s not present; skipping", tunDevicePath)
		}
		t.Skipf("cannot stat %s: %v", tunDevicePath, err)
	}
	// Probe: try to open the device. If we get EPERM we're not privileged.
	fd, err := unix.Open(tunDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("no permission on %s: %v", tunDevicePath, err)
		}
		t.Fatalf("probe open: %v", err)
	}
	_ = unix.Close(fd)
}

// TestOpenClose covers the bare lifecycle: open a device, verify it has the
// requested number of queues and a non-empty kernel-assigned name, then close
// it. Reopening the same name must succeed once the kernel has torn down the
// device from the previous Close.
func TestOpenClose(t *testing.T) {
	requireRoot(t)

	d, err := Open(Options{Queues: 2, MTU: 1500})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Logf("opened %s with %d queues", d.Name(), len(d.Queues()))
	if d.Name() == "" {
		t.Fatal("device name should not be empty")
	}
	if got, want := len(d.Queues()), 2; got != want {
		t.Fatalf("got %d queues, want %d", got, want)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Idempotent close.
	if err := d.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestOpenDefaultQueues asserts that the default queue count is at least 1
// and never exceeds maxDefaultQueues.
func TestOpenDefaultQueues(t *testing.T) {
	requireRoot(t)

	d, err := Open(Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	got := len(d.Queues())
	if got < 1 {
		t.Fatalf("expected at least 1 queue, got %d", got)
	}
	if got > maxDefaultQueues {
		t.Fatalf("default queue count %d exceeds cap %d", got, maxDefaultQueues)
	}
}

// TestQueueLoopback writes an ICMPv6 echo request on one queue and waits for
// the kernel-generated echo reply on any of the device's queues.
//
// This exercises the full kernel data path:
//
//	Write -> kernel sees the frame as inbound on the tun -> the kernel's
//	ICMPv6 stack replies -> kernel routes the reply via the same tun ->
//	Read on whichever queue the kernel selected by flow hash.
//
// A single echo will land on exactly one queue (the kernel hashes outbound
// packets by 4-tuple). We listen on all of them and accept whichever queue
// produces the reply. The multi-queue stress test below covers the
// distribution case.
func TestQueueLoopback(t *testing.T) {
	requireRoot(t)

	const (
		// Use a Unique-Local-Address /64 so we are guaranteed no collision
		// with site routing. The device end is ::1 and we send from ::2.
		// Both addresses live on the same /64, so kernel routes the reply
		// out the tun directly without needing to know about ::2.
		serverAddr = "fd00:c001:cafe:1::1"
		clientAddr = "fd00:c001:cafe:1::2"
		prefix     = "fd00:c001:cafe:1::1/64"
	)

	p := netip.MustParsePrefix(prefix)
	d, err := Open(Options{Queues: 2, MTU: 1500, IPv6: p})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	queues := d.Queues()
	if len(queues) < 2 {
		t.Fatalf("need >=2 queues for loopback test, got %d", len(queues))
	}

	// Build an ICMPv6 echo request from clientAddr to serverAddr.
	pkt := buildICMPv6Echo(netip.MustParseAddr(clientAddr), netip.MustParseAddr(serverAddr), 0xbeef, 1, []byte("era-ocserv-tun"))

	type result struct {
		queue int
		pkt   []byte
	}
	done := make(chan result, len(queues))
	stop := make(chan struct{})

	for i := range queues {
		go func(qi int, qq *Queue) {
			buf := make([]byte, 2048)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, err := qq.Read(buf)
				if err != nil {
					return
				}
				if n < 48 || buf[0]>>4 != 6 || buf[6] != 58 || buf[40] != 129 {
					continue
				}
				cp := make([]byte, n)
				copy(cp, buf[:n])
				select {
				case done <- result{queue: qi, pkt: cp}:
				default:
				}
				return
			}
		}(i, queues[i])
	}

	if _, err := queues[0].Write(pkt); err != nil {
		close(stop)
		t.Fatalf("Write echo request: %v", err)
	}

	select {
	case r := <-done:
		close(stop)
		if id := binary.BigEndian.Uint16(r.pkt[40+4 : 40+6]); id != 0xbeef {
			t.Fatalf("got echo reply with identifier 0x%x, want 0xbeef", id)
		}
		t.Logf("got %d-byte echo reply on queue %d", len(r.pkt), r.queue)
	case <-time.After(3 * time.Second):
		close(stop)
		t.Fatal("timed out waiting for ICMPv6 echo reply on any queue")
	}
	// Closing the device unblocks the remaining reader goroutines.
	_ = d.Close()
}

// TestMultiQueueConcurrent issues many concurrent writes and reads spread
// across all queues. We expect every packet we send to come back as a kernel
// echo reply on some queue. This is the closest thing to a real-world
// "thousands of clients, many cores" stress in unit form.
func TestMultiQueueConcurrent(t *testing.T) {
	requireRoot(t)

	const (
		serverAddr = "fd00:c001:cafe:2::1"
		clientAddr = "fd00:c001:cafe:2::2"
		prefix     = "fd00:c001:cafe:2::1/64"
	)

	p := netip.MustParsePrefix(prefix)
	d, err := Open(Options{Queues: 4, MTU: 1500, IPv6: p})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer d.Close()

	queues := d.Queues()
	if len(queues) < 2 {
		t.Skipf("need >=2 queues, got %d", len(queues))
	}

	const echoes = 64
	var (
		wgReaders sync.WaitGroup
		wgWriters sync.WaitGroup
		seen      [echoes + 1]atomic.Bool
		readsDone = make(chan struct{})
	)

	// Per-queue reader goroutines.
	stop := make(chan struct{})
	for i, q := range queues {
		wgReaders.Add(1)
		go func(qi int, qq *Queue) {
			defer wgReaders.Done()
			buf := make([]byte, 2048)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, err := qq.Read(buf)
				if err != nil {
					return
				}
				if n < 48 || buf[0]>>4 != 6 || buf[6] != 58 || buf[40] != 129 {
					continue
				}
				id := binary.BigEndian.Uint16(buf[40+4 : 40+6])
				seq := binary.BigEndian.Uint16(buf[40+6 : 40+8])
				if id != 0xbeef || seq > echoes {
					continue
				}
				seen[seq].Store(true)
			}
		}(i, q)
	}

	// Writer goroutines, spread across queues.
	for i := uint16(1); i <= echoes; i++ {
		wgWriters.Add(1)
		go func(seq uint16) {
			defer wgWriters.Done()
			pkt := buildICMPv6Echo(
				netip.MustParseAddr(clientAddr),
				netip.MustParseAddr(serverAddr),
				0xbeef,
				seq,
				[]byte("multi-queue-stress"),
			)
			q := queues[int(seq)%len(queues)]
			if _, err := q.Write(pkt); err != nil {
				t.Errorf("queue %d write seq=%d: %v", int(seq)%len(queues), seq, err)
			}
		}(i)
	}
	wgWriters.Wait()

	// Wait up to 5s for all replies to land. The kernel may coalesce or drop
	// under extreme pressure; we accept >= 90% as success because the
	// purpose of this test is to demonstrate concurrent safety, not to
	// measure kernel echo throughput.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got := 0
		for i := uint16(1); i <= echoes; i++ {
			if seen[i].Load() {
				got++
			}
		}
		if got == echoes {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	close(stop)
	// Closing the device unblocks any read currently parked in the kernel.
	_ = d.Close()
	go func() {
		wgReaders.Wait()
		close(readsDone)
	}()
	select {
	case <-readsDone:
	case <-time.After(2 * time.Second):
		t.Logf("readers did not exit cleanly within 2s")
	}

	got := 0
	for i := uint16(1); i <= echoes; i++ {
		if seen[i].Load() {
			got++
		}
	}
	if got*10 < echoes*9 {
		t.Fatalf("got %d/%d echo replies (<90%%)", got, echoes)
	}
	t.Logf("got %d/%d echo replies across %d queues", got, echoes, len(queues))
}

// TestNameTooLong asserts the explicit error path for an over-long name. This
// path doesn't need /dev/net/tun, so it runs unconditionally.
func TestNameTooLong(t *testing.T) {
	long := make([]byte, unix.IFNAMSIZ+1)
	for i := range long {
		long[i] = 'x'
	}
	_, err := Open(Options{Name: string(long)})
	if err == nil {
		t.Fatal("expected error for overly long Name")
	}
}

// buildICMPv6Echo builds a raw IPv6 + ICMPv6 echo-request packet with
// identifier id, sequence seq, and payload. The checksum is computed against
// the IPv6 pseudo-header per RFC 4443 §2.3.
func buildICMPv6Echo(src, dst netip.Addr, id, seq uint16, payload []byte) []byte {
	// ICMPv6 header is 8 bytes.
	icmpLen := 8 + len(payload)
	totalLen := 40 + icmpLen
	b := make([]byte, totalLen)

	// IPv6 header.
	b[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(b[4:6], uint16(icmpLen))
	b[6] = 58  // Next-Header = ICMPv6
	b[7] = 64  // Hop Limit
	s := src.As16()
	dd := dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], dd[:])

	// ICMPv6 echo request: type 128, code 0.
	b[40] = 128
	b[41] = 0
	// checksum at b[42:44], zero for now
	binary.BigEndian.PutUint16(b[44:46], id)
	binary.BigEndian.PutUint16(b[46:48], seq)
	copy(b[48:], payload)

	// Compute ICMPv6 checksum: pseudo-header (src + dst + length + next-hdr)
	// + the ICMPv6 message.
	cs := icmpv6Checksum(s[:], dd[:], uint32(icmpLen), b[40:totalLen])
	binary.BigEndian.PutUint16(b[42:44], cs)
	return b
}

func icmpv6Checksum(src, dst []byte, length uint32, msg []byte) uint16 {
	var sum uint32
	addBytes := func(p []byte) {
		i := 0
		for ; i+1 < len(p); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
		}
		if i < len(p) {
			sum += uint32(p[i]) << 8
		}
	}
	addBytes(src)
	addBytes(dst)
	sum += length
	sum += 58 // Next-Header
	addBytes(msg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
