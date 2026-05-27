package tun

import "net/netip"

// Options configures a multi-queue TUN device.
//
// All fields are optional; the zero value of Options requests a kernel-named,
// MTU-1500 device with min(NumCPU, 4) queues and no inline address assignment.
type Options struct {
	// Name is the desired Linux interface name (e.g. "era0"). Must be <= 15
	// bytes. Empty means let the kernel assign a name (e.g. "tun0").
	Name string

	// MTU is the link-layer MTU. Zero means 1500.
	MTU int

	// Queues is the number of file descriptors to attach to the device. Each
	// queue is independently read/write-able. Zero means min(NumCPU, 4).
	Queues int

	// IPv4 is an optional inner IPv4 address (with prefix length) assigned to
	// the device. The zero netip.Prefix means do not assign any IPv4.
	IPv4 netip.Prefix

	// IPv6 is an optional inner IPv6 address (with prefix length) assigned to
	// the device. The zero netip.Prefix means do not assign any IPv6.
	IPv6 netip.Prefix
}
