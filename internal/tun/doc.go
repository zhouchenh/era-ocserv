// Package tun is a thin Go wrapper around Linux's multi-queue TUN device.
//
// era-ocserv owns one shared Linux TUN device with both IPv4 and IPv6 routes,
// opened with IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE. Each queue is a separate
// file descriptor bound to the same kernel interface; the kernel hashes inner
// packet 4-tuples across queues so per-queue readers naturally see a coherent
// subset of flows. See ADR 0057 §3 and docs/architecture/era-ocserv-protocol.md
// §5 for the protocol-level justification.
//
// This package is intentionally narrow. It opens the device, configures its
// link-layer attributes (MTU, UP, optional IPv4/IPv6 addresses), and exposes N
// independently readable / writable queues. It is NOT a router and does NOT
// maintain a per-client lookup table; those concerns live in higher-level
// packages.
//
// All exported types and functions are no-ops on non-Linux platforms so the
// package can be cross-compiled from any host. The actual device is only
// available on Linux (build tag //go:build linux on the implementation files).
package tun
