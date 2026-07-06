// Package ifac creates and manages TUN network interfaces across Linux,
// macOS, and Windows, and multiplexes IP frames from all managed interfaces
// into a single read path.
//
// Create brings up a TUN device, assigns it the first free host address in
// the given subnet, and starts pumping inbound frames into a shared queue.
// ReadFrom drains that queue; WriteTo injects a frame into the interface
// identified by its IP (or, failing an exact match, the interface whose
// subnet contains the IP).
//
// All functions are safe for concurrent use. The hot path (ReadFrom/WriteTo)
// takes no locks: interface lookup goes through an atomically swapped
// copy-on-write registry, and frame buffers are pooled to stay
// allocation-free in steady state.
package ifac

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/songgao/water"
)

const (
	// maxFrameSize is the largest frame a single ReadFrom can deliver.
	// 64 KiB covers the maximum IP packet size regardless of MTU.
	maxFrameSize = 65536

	// inboxSize bounds the number of frames buffered between the
	// per-interface readers and ReadFrom callers. Readers block (never
	// drop) when it is full; the kernel's own device queue absorbs and
	// sheds load beyond that, as it would for a slow NIC.
	inboxSize = 1024
)

type frame struct {
	ip  string
	buf *[]byte
	n   int
}

type iface struct {
	name   string // logical name given to Create
	dev    string // actual OS device name (may differ on macOS)
	ip     string
	prefix netip.Prefix
	tun    *water.Interface
	done   chan struct{}
}

// registry is immutable after construction; mutations build a new copy and
// swap it in atomically so readers never take a lock.
type registry struct {
	byName map[string]*iface
	byIP   map[string]*iface
}

func (r *registry) clone() *registry {
	next := &registry{
		byName: make(map[string]*iface, len(r.byName)+1),
		byIP:   make(map[string]*iface, len(r.byIP)+1),
	}
	maps.Copy(next.byName, r.byName)
	maps.Copy(next.byIP, r.byIP)
	return next
}

var (
	mu    sync.Mutex // serializes Create/Destroy (registry mutations)
	reg   atomic.Pointer[registry]
	inbox = make(chan frame, inboxSize)
	pool  = sync.Pool{New: func() any {
		b := make([]byte, maxFrameSize)
		return &b
	}}
)

func init() {
	reg.Store(&registry{byName: map[string]*iface{}, byIP: map[string]*iface{}})
}

// Create brings up a TUN interface under the given logical name and returns
// its address. If ip is empty, the first free IPv4 host address in subnet
// (CIDR notation, e.g. "10.42.0.0/24") is assigned automatically; otherwise
// ip is used as given, provided it is a usable host address inside subnet
// and not already assigned to a managed interface. Frames arriving on the
// interface become available through ReadFrom.
//
// Creating interfaces requires elevated privileges (root on Linux/macOS,
// Administrator plus an installed TAP-Windows "tap0901" adapter on Windows).
// On macOS the kernel only permits utunN device names; any other name is
// kept as the logical handle for Destroy/List while the kernel picks the
// actual device.
func Create(name string, subnet string, ip string) (string, error) {
	if name == "" {
		return "", errors.New("ifac: name must not be empty")
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("ifac: invalid subnet %q: %w", subnet, err)
	}

	mu.Lock()
	defer mu.Unlock()

	cur := reg.Load()
	if _, ok := cur.byName[name]; ok {
		return "", fmt.Errorf("ifac: interface %q already exists", name)
	}

	taken := func(a netip.Addr) bool {
		_, used := cur.byIP[a.String()]
		return used
	}

	var addr netip.Addr
	if ip == "" {
		addr, err = pickIP(prefix, taken)
	} else {
		addr, err = checkIP(ip, prefix, taken)
	}
	if err != nil {
		return "", err
	}
	ip = addr.String()

	tun, dev, err := createTUN(name, ip, prefix)
	if err != nil {
		return "", fmt.Errorf("ifac: create %q: %w", name, err)
	}
	if err := configure(dev, ip, prefix); err != nil {
		tun.Close()
		return "", fmt.Errorf("ifac: configure %q (%s): %w", name, dev, err)
	}

	it := &iface{
		name:   name,
		dev:    dev,
		ip:     ip,
		prefix: prefix,
		tun:    tun,
		done:   make(chan struct{}),
	}

	next := cur.clone()
	next.byName[name] = it
	next.byIP[ip] = it
	reg.Store(next)

	go it.readLoop()
	return ip, nil
}

// Destroy tears down the interface previously created under name. Frames
// from it that are already queued may still be returned by ReadFrom.
func Destroy(name string) error {
	mu.Lock()
	defer mu.Unlock()

	cur := reg.Load()
	it, ok := cur.byName[name]
	if !ok {
		return fmt.Errorf("ifac: interface %q not found", name)
	}

	next := cur.clone()
	delete(next.byName, name)
	delete(next.byIP, it.ip)
	reg.Store(next)

	close(it.done)
	err := it.tun.Close()
	teardown(it.dev, it.ip, it.prefix)
	return err
}

// List returns the managed interfaces, sorted by name, with ips[i] holding
// the address of names[i].
func List() (names []string, ips []string, err error) {
	cur := reg.Load()
	names = make([]string, 0, len(cur.byName))
	for n := range cur.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	ips = make([]string, len(names))
	for i, n := range names {
		ips[i] = cur.byName[n].ip
	}
	return names, ips, nil
}

// WriteTo injects the frame b into the interface whose address is ip. If no
// interface has that exact address, the frame goes to the first interface
// whose subnet contains ip (order is unspecified if subnets overlap).
// b must be a complete IP packet no larger than the interface MTU.
func WriteTo(ip string, b []byte) (n int, err error) {
	cur := reg.Load()
	it, ok := cur.byIP[ip]
	if !ok {
		if a, perr := netip.ParseAddr(ip); perr == nil {
			for _, cand := range cur.byIP {
				if cand.prefix.Contains(a) {
					it, ok = cand, true
					break
				}
			}
		}
	}
	if !ok {
		return 0, fmt.Errorf("ifac: no interface for %q", ip)
	}
	return it.tun.Write(b)
}

// ReadFrom blocks until a frame arrives on any managed interface, copies it
// into b, and returns the address of the interface it arrived on along with
// the frame length. If b is too small the frame is truncated to len(b) and
// the error is io.ErrShortBuffer; size b at 65536 bytes (or the MTU) to
// avoid truncation. Multiple goroutines may call ReadFrom concurrently;
// each frame is delivered to exactly one caller.
func ReadFrom(b []byte) (ip string, n int, err error) {
	f := <-inbox
	n = copy(b, (*f.buf)[:f.n])
	pool.Put(f.buf)
	if n < f.n {
		return f.ip, n, io.ErrShortBuffer
	}
	return f.ip, n, nil
}

// readLoop pumps frames from one TUN device into the shared inbox. It exits
// when the device is closed (Destroy) or hits a read error.
func (it *iface) readLoop() {
	for {
		bp := pool.Get().(*[]byte)
		n, err := it.tun.Read(*bp)
		if err != nil {
			pool.Put(bp)
			return
		}
		if n == 0 {
			pool.Put(bp)
			continue
		}
		select {
		case inbox <- frame{ip: it.ip, buf: bp, n: n}:
		case <-it.done:
			pool.Put(bp)
			return
		}
	}
}
