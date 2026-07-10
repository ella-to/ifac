// Package ifac creates and manages TUN network interfaces across Linux,
// macOS, and Windows, and multiplexes IP frames from all managed interfaces
// into a single read path.
//
// Up brings up a TUN device, assigns it the first free host address in
// the given subnet, and starts pumping inbound frames into a shared queue.
// ReadFrom drains that queue; WriteTo injects a frame into the interface
// identified by its IP (or, failing an exact match, the interface whose
// subnet contains the IP).
//
// All functions are safe for concurrent use. Interface lookup goes through an
// atomically swapped copy-on-write registry. Writes take a per-interface
// shared lifecycle guard so teardown cannot close a device during an in-flight
// write. Frame buffers are pooled to stay allocation-free in steady state.
package ifac

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/Doridian/water"
)

const (
	// MaxFrameSize is the largest packet a single ReadFrom can deliver.
	// IP packets and Wintun are both limited to 65,535 bytes.
	MaxFrameSize = 65535

	// inboxSize bounds the number of frames buffered between the
	// per-interface readers and ReadFrom callers. Readers block (never
	// drop) when it is full; the kernel's own device queue absorbs and
	// sheds load beyond that, as it would for a slow NIC.
	inboxSize = 1024
)

// ErrClosed is returned when an operation loses a race with interface
// teardown after it has already selected that interface.
var ErrClosed = errors.New("ifac: interface is closed")

type frame struct {
	source *iface
	buf    *[]byte
	n      int
	err    error
}

type iface struct {
	name   string // logical name given to Up
	dev    string // actual OS device name (may differ on macOS)
	ip     string
	prefix netip.Prefix
	tun    *water.Interface
	done   chan struct{}
	ioMu   sync.RWMutex
	closed bool
}

// registry is immutable after construction; mutations build a new copy and
// swap it in atomically so readers never take a lock.
type registry struct {
	byName map[string]*iface
	byIP   map[string]*iface
	routes []*iface
}

func (r *registry) clone() *registry {
	next := &registry{
		byName: make(map[string]*iface, len(r.byName)+1),
		byIP:   make(map[string]*iface, len(r.byIP)+1),
		routes: append([]*iface(nil), r.routes...),
	}
	maps.Copy(next.byName, r.byName)
	maps.Copy(next.byIP, r.byIP)
	return next
}

var (
	mu    sync.Mutex // serializes Up/Down (registry mutations)
	reg   atomic.Pointer[registry]
	inbox = make(chan frame, inboxSize)
	pool  = sync.Pool{New: func() any {
		b := make([]byte, MaxFrameSize)
		return &b
	}}
)

func init() {
	reg.Store(&registry{byName: map[string]*iface{}, byIP: map[string]*iface{}})
}

// Up brings up a TUN interface under the given logical name and returns
// its address. If ip is empty, the first free IPv4 host address in subnet
// (CIDR notation, e.g. "10.42.0.0/24") is assigned automatically; otherwise
// ip is used as given, provided it is a usable host address inside subnet
// and not already assigned to a managed interface. Frames arriving on the
// interface become available through ReadFrom.
//
// Creating interfaces requires elevated privileges (root on Linux/macOS,
// Administrator on Windows).
// On macOS the kernel only permits utunN device names; any other name is
// kept as the logical handle for Down/List while the kernel picks the
// actual device.
func Up(name string, subnet string, ip string) (string, error) {
	if name == "" {
		return "", errors.New("ifac: name must not be empty")
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("ifac: invalid subnet %q: %w", subnet, err)
	}
	if err := validatePrefix(prefix); err != nil {
		return "", err
	}
	prefix = prefix.Masked()

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
		cleanupErr := errors.Join(teardown(dev, ip, prefix), tun.Close())
		return "", errors.Join(
			fmt.Errorf("ifac: configure %q (%s): %w", name, dev, err),
			wrapCleanupError(name, cleanupErr),
		)
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
	next.routes = append(next.routes, it)
	sortRoutes(next.routes)
	reg.Store(next)

	go it.readLoop()
	return ip, nil
}

// Down tears down the interface previously brought up under name. Packets
// queued by that interface are discarded.
func Down(name string) error {
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
	next.routes = removeRoute(next.routes, it)
	reg.Store(next)

	close(it.done)
	return it.close()
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
// interface has that exact address, the packet follows deterministic
// longest-prefix matching across managed interface subnets.
// b must be a complete IP packet no larger than the interface MTU.
func WriteTo(ip string, b []byte) (n int, err error) {
	if err := validatePacket(b); err != nil {
		return 0, err
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, fmt.Errorf("ifac: invalid destination %q: %w", ip, err)
	}

	cur := reg.Load()
	it, ok := cur.byIP[addr.String()]
	if !ok {
		for _, cand := range cur.routes {
			if cand.prefix.Contains(addr) {
				it, ok = cand, true
				break
			}
		}
	}
	if !ok {
		return 0, fmt.Errorf("ifac: no interface for %q", ip)
	}
	return it.write(b)
}

// ReadFrom blocks until a packet arrives on any managed interface or ctx is
// canceled. It copies the packet into b and returns the address of the
// interface it arrived on along with the packet length. If b is too small,
// the packet is truncated to len(b) and the error is io.ErrShortBuffer; size b
// at MaxFrameSize (or the MTU) to avoid truncation. Multiple goroutines may
// call ReadFrom concurrently; each packet is delivered to exactly one caller.
func ReadFrom(ctx context.Context, b []byte) (ip string, n int, err error) {
	for {
		var f frame
		select {
		case f = <-inbox:
		case <-ctx.Done():
			return "", 0, ctx.Err()
		}

		// Down removes the source before closing the device. Discard packets
		// already queued by that device so a reused address cannot receive stale
		// traffic from a previous interface generation.
		if f.err != nil {
			return f.source.ip, 0, f.err
		}
		current := reg.Load().byName[f.source.name]
		if current != f.source {
			releaseFrame(f)
			continue
		}

		n = copy(b, (*f.buf)[:f.n])
		releaseFrame(f)
		if n < f.n {
			return f.source.ip, n, io.ErrShortBuffer
		}
		return f.source.ip, n, nil
	}
}

// readLoop pumps frames from one TUN device into the shared inbox. It exits
// when the device is closed (Down) or hits a read error.
func (it *iface) readLoop() {
	for {
		bp := pool.Get().(*[]byte)
		n, err := it.tun.Read(*bp)
		if err != nil {
			pool.Put(bp)
			select {
			case <-it.done:
				return
			default:
			}

			removed, cleanupErr := retireFailedInterface(it)
			if removed {
				readErr := fmt.Errorf("ifac: read %q (%s): %w", it.name, it.dev, err)
				select {
				case inbox <- frame{source: it, err: errors.Join(readErr, cleanupErr)}:
				default:
				}
			}
			return
		}
		if n == 0 {
			pool.Put(bp)
			continue
		}
		select {
		case inbox <- frame{source: it, buf: bp, n: n}:
		case <-it.done:
			pool.Put(bp)
			return
		}
	}
}

func releaseFrame(f frame) {
	if f.buf != nil {
		pool.Put(f.buf)
	}
}

func sortRoutes(routes []*iface) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].prefix.Bits() != routes[j].prefix.Bits() {
			return routes[i].prefix.Bits() > routes[j].prefix.Bits()
		}
		if routes[i].prefix.Addr() != routes[j].prefix.Addr() {
			return routes[i].prefix.Addr().Less(routes[j].prefix.Addr())
		}
		return routes[i].name < routes[j].name
	})
}

func removeRoute(routes []*iface, target *iface) []*iface {
	for i, route := range routes {
		if route == target {
			return append(routes[:i:i], routes[i+1:]...)
		}
	}
	return routes
}

func retireFailedInterface(it *iface) (bool, error) {
	mu.Lock()
	defer mu.Unlock()

	cur := reg.Load()
	if cur.byName[it.name] != it {
		return false, nil
	}

	next := cur.clone()
	delete(next.byName, it.name)
	delete(next.byIP, it.ip)
	next.routes = removeRoute(next.routes, it)
	reg.Store(next)

	close(it.done)
	return true, it.close()
}

func (it *iface) write(packet []byte) (int, error) {
	it.ioMu.RLock()
	defer it.ioMu.RUnlock()

	if it.closed {
		return 0, ErrClosed
	}
	return it.tun.Write(packet)
}

func (it *iface) close() error {
	it.ioMu.Lock()
	defer it.ioMu.Unlock()

	if it.closed {
		return nil
	}
	it.closed = true
	return errors.Join(
		teardown(it.dev, it.ip, it.prefix),
		it.tun.Close(),
	)
}

func validatePacket(packet []byte) error {
	if len(packet) == 0 {
		return errors.New("ifac: packet is empty")
	}
	if len(packet) > MaxFrameSize {
		return fmt.Errorf("ifac: packet is %d bytes; maximum is %d", len(packet), MaxFrameSize)
	}

	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return fmt.Errorf("ifac: truncated IPv4 packet: %d bytes", len(packet))
		}
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen < 20 || headerLen > len(packet) {
			return fmt.Errorf("ifac: invalid IPv4 header length: %d", headerLen)
		}
		totalLen := int(packet[2])<<8 | int(packet[3])
		if totalLen != len(packet) {
			return fmt.Errorf("ifac: IPv4 total length is %d; packet has %d bytes", totalLen, len(packet))
		}
	case 6:
		if len(packet) < 40 {
			return fmt.Errorf("ifac: truncated IPv6 packet: %d bytes", len(packet))
		}
		totalLen := 40 + (int(packet[4]) << 8) + int(packet[5])
		if totalLen != len(packet) {
			return fmt.Errorf("ifac: IPv6 payload length describes %d bytes; packet has %d", totalLen, len(packet))
		}
	default:
		return fmt.Errorf("ifac: unsupported IP version %d", packet[0]>>4)
	}
	return nil
}

func wrapCleanupError(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("ifac: clean up %q after failed create: %w", name, err)
}
