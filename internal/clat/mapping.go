// Vendored from wireguard-go-clat@3dfa6e7 (golang.zx2c4.com/wireguard/clat). Do not edit; update by re-vendoring.
package clat

import (
	"net"
	"sync"
)

type Mapping struct {
	ipv4  []byte
	ipv6  []byte
	mutex sync.RWMutex
}

func cloneIP(addr []byte) []byte {
	if len(addr) == 0 {
		return nil
	}
	clone := make([]byte, len(addr))
	copy(clone, addr)
	return clone
}

func (mapping *Mapping) SetIP(addr []byte) {
	mapping.mutex.Lock()
	defer mapping.mutex.Unlock()

	switch len(addr) {
	case net.IPv4len:
		mapping.ipv4 = cloneIP(addr)
	case net.IPv6len:
		mapping.ipv6 = cloneIP(addr)
	default:
	}
}

func (mapping *Mapping) Clear() {
	mapping.mutex.Lock()
	defer mapping.mutex.Unlock()

	mapping.ipv4 = nil
	mapping.ipv6 = nil
}

func (mapping *Mapping) IPv4() (ipv4 []byte) {
	mapping.mutex.RLock()
	defer mapping.mutex.RUnlock()

	return mapping.ipv4
}

func (mapping *Mapping) IPv6() (ipv6 []byte) {
	mapping.mutex.RLock()
	defer mapping.mutex.RUnlock()

	return mapping.ipv6
}

func (mapping *Mapping) IPs() (ipv4 []byte, ipv6 []byte) {
	mapping.mutex.RLock()
	defer mapping.mutex.RUnlock()

	return mapping.ipv4, mapping.ipv6
}
