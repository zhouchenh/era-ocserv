//go:build linux

package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// defaultMTU is the link MTU used when Options.MTU is zero. The protocol spec
// sets the tun MTU to the larger of cstp_inner_mtu and dtls_inner_mtu (both
// derived from the client's X-CSTP-Base-MTU, typically 1500); 1500 leaves
// headroom for the worst case without fragmentation at the tun.
const defaultMTU = 1500

// maxDefaultQueues caps the default queue count. v1 wants min(NumCPU, 4) per
// ADR 0057 §3 and the protocol spec §5.2.
const maxDefaultQueues = 4

// tunDevicePath is the standard cloning device for TUN/TAP on Linux.
const tunDevicePath = "/dev/net/tun"

// Device is a multi-queue Linux TUN device.
//
// A Device is created by Open and must be released with Close. Its queues are
// returned by Queues; each Queue is independently usable from a dedicated
// goroutine pair.
type Device struct {
	name   string
	queues []*Queue

	closeOnce sync.Once
	closeErr  error
}

// Queue is one file descriptor attached to a multi-queue TUN device.
//
// Reads return exactly one IP packet (no PI prefix, because the device is
// opened with IFF_NO_PI). Writes accept one raw IP packet at a time.
//
// A Queue is safe to read and write concurrently with itself, but per-queue
// throughput is highest when one goroutine reads and one writes.
type Queue struct {
	fd int

	closeOnce sync.Once
	closeErr  error
}

// Open creates a multi-queue TUN device per opts and brings it up.
//
// On success the kernel device is configured (MTU set, link UP, optional
// addresses assigned) and all queues are open for read and write.
//
// On error any partially opened queues are closed before returning.
func Open(opts Options) (*Device, error) {
	n := opts.Queues
	if n <= 0 {
		n = runtime.NumCPU()
		if n > maxDefaultQueues {
			n = maxDefaultQueues
		}
		if n < 1 {
			n = 1
		}
	}

	mtu := opts.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	if len(opts.Name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("tun: name %q too long (max %d bytes)", opts.Name, unix.IFNAMSIZ-1)
	}

	queues := make([]*Queue, 0, n)
	cleanup := func() {
		for _, q := range queues {
			_ = q.Close()
		}
	}

	// First open creates the device; subsequent opens attach to it.
	// The kernel returns the actual assigned name in the ifreq buffer after
	// TUNSETIFF, which matters when opts.Name is empty.
	resolvedName := opts.Name
	for i := 0; i < n; i++ {
		q, name, err := openQueue(resolvedName)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("tun: open queue %d: %w", i, err)
		}
		if resolvedName == "" {
			resolvedName = name
		}
		queues = append(queues, q)
	}

	d := &Device{
		name:   resolvedName,
		queues: queues,
	}

	if err := configureInterface(resolvedName, mtu, opts.IPv4, opts.IPv6); err != nil {
		cleanup()
		return nil, fmt.Errorf("tun: configure %q: %w", resolvedName, err)
	}

	return d, nil
}

// Name returns the kernel-assigned interface name.
func (d *Device) Name() string { return d.name }

// Queues returns the device's per-queue handles. The returned slice is owned
// by the Device; callers must not modify it.
func (d *Device) Queues() []*Queue { return d.queues }

// Close releases all queues. Subsequent calls return the first close error.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		var firstErr error
		for _, q := range d.queues {
			if err := q.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		d.closeErr = firstErr
	})
	return d.closeErr
}

// Read pulls one IP packet from the queue into p. The returned length is the
// number of bytes written into p.
//
// Truncation contract: if p is shorter than the next packet, Linux silently
// truncates and the trailing bytes are LOST. There is no error signal — the
// caller gets (len(p), nil) and cannot tell a truncated packet from a fully-
// received one of the same length. Callers MUST size p at least to the device
// MTU (typically 1500) and ideally to the worst-case CSTP/DTLS inner MTU
// (~1406) plus headroom. The bridge in internal/bridge sizes its scratch
// buffer to 65535 to make truncation impossible in practice.
//
// This contrasts with cstp.Tunnel.ReadPacket which returns the partial
// payload plus io.ErrShortBuffer on truncation; if you migrate code between
// the two paths, the silent-vs-signalled-truncation difference is
// load-bearing.
//
// Read returns os.ErrClosed after Close. EINTR is retried transparently.
func (q *Queue) Read(p []byte) (int, error) {
	for {
		n, err := unix.Read(q.fd, p)
		if err == nil {
			return n, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EBADF) {
			return 0, os.ErrClosed
		}
		return n, &os.PathError{Op: "read", Path: tunDevicePath, Err: err}
	}
}

// Write pushes one IP packet to the queue. The whole slice is written in a
// single syscall (TUN devices are message-oriented, not byte-streams).
//
// Write returns os.ErrClosed after Close. EINTR is retried transparently.
func (q *Queue) Write(p []byte) (int, error) {
	for {
		n, err := unix.Write(q.fd, p)
		if err == nil {
			return n, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EBADF) {
			return 0, os.ErrClosed
		}
		return n, &os.PathError{Op: "write", Path: tunDevicePath, Err: err}
	}
}

// Close releases the queue file descriptor.
func (q *Queue) Close() error {
	q.closeOnce.Do(func() {
		q.closeErr = unix.Close(q.fd)
	})
	return q.closeErr
}

// openQueue opens /dev/net/tun and binds the fd to the named interface (or
// kernel-assigned name when name is empty). It returns the queue and the
// resolved name.
func openQueue(name string) (*Queue, string, error) {
	fd, err := unix.Open(tunDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", &os.PathError{Op: "open", Path: tunDevicePath, Err: err}
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("ifreq: %w", err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)

	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF: %w", err)
	}

	return &Queue{fd: fd}, ifr.Name(), nil
}

// configureInterface drives the link UP with the requested MTU and assigns
// optional IPv4 / IPv6 addresses via netlink (NETLINK_ROUTE).
func configureInterface(name string, mtu int, v4, v6 netip.Prefix) error {
	nl, err := newNetlinkConn()
	if err != nil {
		return fmt.Errorf("netlink open: %w", err)
	}
	defer nl.close()

	idx, err := nl.ifindex(name)
	if err != nil {
		return fmt.Errorf("resolve ifindex for %q: %w", name, err)
	}

	if err := nl.setLink(idx, mtu); err != nil {
		return fmt.Errorf("set link up / mtu: %w", err)
	}

	if v4.IsValid() {
		if !v4.Addr().Is4() {
			return fmt.Errorf("IPv4 prefix %s is not IPv4", v4)
		}
		if err := nl.addAddr(idx, v4); err != nil {
			return fmt.Errorf("add IPv4 %s: %w", v4, err)
		}
	}
	if v6.IsValid() {
		if !v6.Addr().Is6() || v6.Addr().Is4In6() {
			return fmt.Errorf("IPv6 prefix %s is not IPv6", v6)
		}
		if err := nl.addAddr(idx, v6); err != nil {
			return fmt.Errorf("add IPv6 %s: %w", v6, err)
		}
	}
	return nil
}

// asSyscallErrno extracts a syscall.Errno from a nested error chain so we can
// match well-known errors (e.g. EEXIST) without false positives.
func asSyscallErrno(err error) (syscall.Errno, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno, true
	}
	return 0, false
}
