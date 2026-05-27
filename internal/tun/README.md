# internal/tun

## Purpose

Thin Go wrapper around Linux's multi-queue TUN device. era-ocserv owns one
shared `/dev/net/tun` device with both IPv4 and IPv6 routes; this package
opens it with `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE`, brings the link UP at
the configured MTU, assigns optional inner addresses, and exposes N file
descriptors as independent `Queue` handles. The kernel hashes inner-packet
4-tuples across queues so per-queue readers naturally see a coherent subset
of flows. This is the lowest layer of era-ocserv's data plane — everything
above it (per-client routing, framing, TLS) consumes one Queue pair.

## Contract

Surface (godoc has details, this is the "why"):

- `Open(Options) (*Device, error)` — create the device. On any per-queue
  failure all partially-opened queues are closed before returning, so the
  caller never has to half-clean.
- `(*Device).Queues() []*Queue` — fan out by goroutine pair. The slice is
  owned by the Device; callers must not modify it.
- `(*Queue).Read / Write` — one IP packet per call. EINTR is retried
  transparently. `os.ErrClosed` after Close.
- `(*Device).Close` and `(*Queue).Close` — idempotent; only the first call
  surfaces a real error.

Errors are wrapped `*os.PathError` (for `read` / `write` / `open` /
`socket`) so `errors.Is(err, unix.EPERM)` style matching works through the
chain.

## Dependencies

- `golang.org/x/sys/unix` — TUN ioctls, netlink constants, syscall wrappers.
- Standard library only otherwise (`net/netip`, `os`, `sync`, etc.).

No third-party netlink library. The needed surface is tiny (three message
types, no event subscription) so the package speaks `NETLINK_ROUTE`
directly in `netlink_linux.go`.

## Invariants

Callers MUST:

- Run on Linux. On other platforms `Open` returns `ErrUnsupported`; the
  stub exists so packages that import `tun` still build on developer
  workstations.
- Hold `CAP_NET_ADMIN` (or be root). Opening `/dev/net/tun` and the
  `NETLINK_ROUTE` socket both require it.
- Size each read buffer to at least the device MTU. Linux truncates a
  short read and the trailing bytes are lost.
- Pair each queue with at most one reader goroutine and one writer
  goroutine. Reading or writing the same Queue from multiple goroutines
  is technically safe (kernel side serialises) but defeats the per-queue
  throughput model.

Callers MUST NOT:

- Strip a 4-byte tun_pi header. The device is opened with `IFF_NO_PI`;
  reads return raw IP packets.
- Treat the FD as a byte stream. TUN is message-oriented; one
  `read(2)` returns exactly one packet.

## Threading model

- `Open`, `Name`, `Queues`, `Close` are safe to call from any goroutine.
- A `*Queue` is safe for one reader and one writer concurrently. Calling
  `Read` (or `Write`) from multiple goroutines simultaneously on the same
  Queue is technically safe because the kernel serialises, but you give up
  the per-queue parallelism the multi-queue model exists for.
- Calling `Close` while a `Read` or `Write` is in flight on the same
  Queue is safe — the in-flight call returns `os.ErrClosed`.

## Testing model

- The package's own tests live in `tun_linux_test.go` and require Linux
  plus the test runner to either be root or have the cap-net-admin
  capability set on the test binary. The test skips itself if the kernel
  refuses the TUN open.
- Downstream packages do NOT mock `*Device` directly — there is no
  interface to mock. Instead, take a `Reader` / `Writer` pair (or
  `io.ReadWriteCloser`) in the consumer's API; the consumer's test wires a
  `net.Pipe()` or `bytes.Buffer` while production wires a Queue.

## Cross-refs

- Protocol doc — [§5 Tun model on Linux](../../docs/architecture/era-ocserv-protocol.md#5-tun-model-on-linux)
  (rendered after the upstream protocol doc is committed to the tpm
  repo).
- ADR 0057 §3 — single shared multi-queue tun decision.
