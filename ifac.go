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

// teardownDevice is the platform teardown; tests replace it to avoid
// running system commands against fake devices.
var teardownDevice = teardown

// ErrClosed is returned when an operation loses a race with interface
// teardown after it has already selected that interface.
var ErrClosed = errors.New("ifac: interface is closed")

// device is a platform TUN handle. Only the interface's reader goroutine
// calls read; write may be called concurrently, and Close must be safe while
// read and write are in progress.
type device interface {
	// read blocks until a packet arrives, reads it into buf, and reports
	// where in buf the packet starts and how long it is.
	read(buf []byte) (off, n int, err error)
	write(packet []byte) (int, error)
	Close() error
}

type frame struct {
	source *iface
	buf    *[]byte
	n      int
}

// readFailure reports that an interface's device failed and was retired.
type readFailure struct {
	ip  string
	err error
}

type iface struct {
	name   string // logical name given to Up
	dev    string // actual OS device name (may differ on macOS)
	ip     string // addr.String(), precomputed for ReadFrom
	addr   netip.Addr
	prefix netip.Prefix
	tun    device
	done   chan struct{}

	// closed is set once, before the device is torn down. Writers and
	// ReadFrom check it instead of taking a lock or consulting the registry.
	closed atomic.Bool
}

// registry is immutable after construction; mutations build a new copy and
// swap it in atomically so readers never take a lock.
type registry struct {
	byName map[string]*iface
	byIP   map[netip.Addr]*iface
	routes []*iface
}

func (r *registry) clone() *registry {
	next := &registry{
		byName: make(map[string]*iface, len(r.byName)+1),
		byIP:   make(map[netip.Addr]*iface, len(r.byIP)+1),
		routes: append([]*iface(nil), r.routes...),
	}
	maps.Copy(next.byName, r.byName)
	maps.Copy(next.byIP, r.byIP)
	return next
}

// reservation holds the address and subnet of an interface whose OS-level
// setup or teardown is running outside mu.
type reservation struct {
	addr   netip.Addr
	prefix netip.Prefix
}

var (
	mu  sync.Mutex // guards registry mutations and pending
	reg atomic.Pointer[registry]

	// pending reserves names, addresses and subnets for Up and Down calls
	// that are configuring or tearing down a device without holding mu.
	pending = map[string]reservation{}

	inbox = make(chan frame, inboxSize)

	// Read failures bypass the inbox so they are never dropped when it is
	// full. The queue holds at most one entry per retired interface;
	// failReady is signaled whenever it is non-empty.
	failMu    sync.Mutex
	failures  []readFailure
	failReady = make(chan struct{}, 1)
)

func init() {
	reg.Store(&registry{byName: map[string]*iface{}, byIP: map[netip.Addr]*iface{}})
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
	if err := validateName(name); err != nil {
		return "", err
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", fmt.Errorf("ifac: invalid subnet %q: %w", subnet, err)
	}
	if err := validatePrefix(prefix); err != nil {
		return "", err
	}
	prefix = prefix.Masked()

	addr, err := reserve(name, prefix, ip)
	if err != nil {
		return "", err
	}
	ip = addr.String()

	// Device creation and configuration run outside mu (they shell out and
	// can take seconds); the reservation keeps name, address and subnet ours.
	tun, dev, err := createTUN(name)
	if err != nil {
		release(name)
		return "", fmt.Errorf("ifac: create %q: %w", name, err)
	}
	if err := configure(dev, ip, prefix); err != nil {
		// Do not run teardown here: configure may have failed before adding
		// anything, and on macOS deleting the subnet route could remove a
		// route that belongs to someone else. Whatever configure did add
		// (address, link state, route) goes away with the device.
		cleanupErr := tun.Close()
		release(name)
		return "", errors.Join(
			fmt.Errorf("ifac: configure %q (%s): %w", name, dev, err),
			wrapCleanupError(name, cleanupErr),
		)
	}

	it := &iface{
		name:   name,
		dev:    dev,
		ip:     ip,
		addr:   addr,
		prefix: prefix,
		tun:    tun,
		done:   make(chan struct{}),
	}

	mu.Lock()
	delete(pending, name)
	next := reg.Load().clone()
	next.byName[name] = it
	next.byIP[addr] = it
	next.routes = append(next.routes, it)
	sortRoutes(next.routes)
	reg.Store(next)
	mu.Unlock()

	go it.readLoop()
	return ip, nil
}

// reserve validates name, subnet and address against both managed
// interfaces and in-flight Up/Down calls, then records a reservation.
func reserve(name string, prefix netip.Prefix, ip string) (netip.Addr, error) {
	mu.Lock()
	defer mu.Unlock()

	cur := reg.Load()
	if _, ok := cur.byName[name]; ok {
		return netip.Addr{}, fmt.Errorf("ifac: interface %q already exists", name)
	}
	if _, ok := pending[name]; ok {
		return netip.Addr{}, fmt.Errorf("ifac: interface %q is being brought up or torn down", name)
	}
	// Two interfaces on one subnet would compete for the same route (on
	// macOS the second route add fails outright). Nested subnets are fine and
	// are resolved by longest-prefix match.
	for _, r := range cur.routes {
		if r.prefix == prefix {
			return netip.Addr{}, fmt.Errorf("ifac: subnet %s is already used by interface %q", prefix, r.name)
		}
	}
	for n, r := range pending {
		if r.prefix == prefix {
			return netip.Addr{}, fmt.Errorf("ifac: subnet %s is already used by interface %q", prefix, n)
		}
	}

	taken := func(a netip.Addr) bool {
		if _, used := cur.byIP[a]; used {
			return true
		}
		for _, r := range pending {
			if r.addr == a {
				return true
			}
		}
		return false
	}

	var addr netip.Addr
	var err error
	if ip == "" {
		addr, err = pickIP(prefix, taken)
	} else {
		addr, err = checkIP(ip, prefix, taken)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	pending[name] = reservation{addr: addr, prefix: prefix}
	return addr, nil
}

// release drops the reservation for name.
func release(name string) {
	mu.Lock()
	delete(pending, name)
	mu.Unlock()
}

// Down tears down the interface previously brought up under name. Packets
// queued by that interface are discarded.
func Down(name string) error {
	mu.Lock()
	it, ok := reg.Load().byName[name]
	if ok {
		unregisterLocked(it)
	}
	mu.Unlock()

	if !ok {
		return fmt.Errorf("ifac: interface %q not found", name)
	}
	return retire(it)
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
	addr = addr.Unmap() // treat ::ffff:a.b.c.d as a.b.c.d

	cur := reg.Load()
	it, ok := cur.byIP[addr]
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
		case <-failReady:
			if rf, ok := popFailure(); ok {
				return rf.ip, 0, rf.err
			}
			continue
		case <-ctx.Done():
			return "", 0, ctx.Err()
		}

		// Discard packets already queued by an interface that has since been
		// torn down, so a reused address cannot receive stale traffic from a
		// previous interface generation. Up cannot reuse the address until
		// teardown has marked the interface closed.
		if f.source.closed.Load() {
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
//
// Each read lands in a per-interface scratch buffer large enough for any
// packet, so oversized packets are never truncated, and is then copied into
// a pooled buffer sized to the packet. For typical packets that copy is far
// cheaper than queueing a 64 KB buffer per frame.
func (it *iface) readLoop() {
	scratch := make([]byte, MaxFrameSize+readHeadroom)
	for {
		off, n, err := it.tun.read(scratch)
		if err != nil {
			select {
			case <-it.done:
				return
			default:
			}

			removed, cleanupErr := retireFailedInterface(it)
			if removed {
				readErr := fmt.Errorf("ifac: read %q (%s): %w", it.name, it.dev, err)
				pushFailure(readFailure{ip: it.ip, err: errors.Join(readErr, cleanupErr)})
			}
			return
		}
		if n <= 0 {
			continue
		}
		bp := getBuffer(n)
		copy(*bp, scratch[off:off+n])
		select {
		case inbox <- frame{source: it, buf: bp, n: n}:
		case <-it.done:
			putBuffer(bp)
			return
		}
	}
}

func pushFailure(rf readFailure) {
	failMu.Lock()
	failures = append(failures, rf)
	failMu.Unlock()
	signalFailure()
}

func popFailure() (readFailure, bool) {
	failMu.Lock()
	defer failMu.Unlock()
	if len(failures) == 0 {
		return readFailure{}, false
	}
	rf := failures[0]
	failures[0] = readFailure{}
	failures = failures[1:]
	if len(failures) > 0 {
		signalFailure() // wake another ReadFrom for the next one
	}
	return rf, true
}

func signalFailure() {
	select {
	case failReady <- struct{}{}:
	default: // a wake-up is already pending
	}
}

func releaseFrame(f frame) {
	if f.buf != nil {
		putBuffer(f.buf)
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

// retireFailedInterface removes an interface whose device failed, unless
// Down already removed it.
func retireFailedInterface(it *iface) (bool, error) {
	mu.Lock()
	ok := reg.Load().byName[it.name] == it
	if ok {
		unregisterLocked(it)
	}
	mu.Unlock()

	if !ok {
		return false, nil
	}
	return true, retire(it)
}

// unregisterLocked removes it from the registry and reserves its name,
// address and subnet until retire finishes, so a concurrent Up cannot claim
// them while the old device still exists. mu must be held.
func unregisterLocked(it *iface) {
	next := reg.Load().clone()
	delete(next.byName, it.name)
	delete(next.byIP, it.addr)
	next.routes = removeRoute(next.routes, it)
	reg.Store(next)
	pending[it.name] = reservation{addr: it.addr, prefix: it.prefix}
}

// retire stops the reader, tears the device down outside mu, then releases
// the reservation taken by unregisterLocked.
func retire(it *iface) error {
	close(it.done)
	err := it.close()
	release(it.name)
	return err
}

// write needs no lock: every device tolerates Close racing with write, and
// an error caused by that race is reported as ErrClosed.
func (it *iface) write(packet []byte) (int, error) {
	if it.closed.Load() {
		return 0, ErrClosed
	}
	n, err := it.tun.write(packet)
	if err != nil && it.closed.Load() {
		return n, ErrClosed
	}
	return n, err
}

// close marks the interface closed, so writers fail fast with ErrClosed while
// the (possibly slow) platform teardown runs, then releases the device.
func (it *iface) close() error {
	if !it.closed.CompareAndSwap(false, true) {
		return nil
	}
	return errors.Join(
		teardownDevice(it.dev, it.ip, it.prefix),
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
