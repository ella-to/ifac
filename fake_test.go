package ifac

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDev is an in-memory device. Packets sent on packets are returned by
// read; an error sent on fail makes read fail. If loop is set, read returns
// it immediately every time (for benchmarks).
type fakeDev struct {
	packets chan []byte
	fail    chan error
	loop    []byte
	closed  chan struct{}
	once    sync.Once
	writes  atomic.Int64
}

func newFakeDev() *fakeDev {
	return &fakeDev{
		packets: make(chan []byte, 16),
		fail:    make(chan error, 1),
		closed:  make(chan struct{}),
	}
}

func (d *fakeDev) read(buf []byte) (int, int, error) {
	if d.loop != nil {
		select {
		case <-d.closed:
			return 0, 0, os.ErrClosed
		default:
			return 0, copy(buf, d.loop), nil
		}
	}
	select {
	case p := <-d.packets:
		return 0, copy(buf, p), nil
	case err := <-d.fail:
		return 0, 0, err
	case <-d.closed:
		return 0, 0, os.ErrClosed
	}
}

func (d *fakeDev) write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	default:
	}
	d.writes.Add(1)
	return len(p), nil
}

func (d *fakeDev) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// noTeardown stops close from running platform commands for fake devices.
func noTeardown(tb testing.TB) {
	orig := teardownDevice
	teardownDevice = func(string, string, netip.Prefix) error { return nil }
	tb.Cleanup(func() { teardownDevice = orig })
}

// addFake registers an interface backed by dev, as Up would after creating
// a real device, and removes it when the test ends.
func addFake(tb testing.TB, name, subnet, ip string, dev *fakeDev) *iface {
	tb.Helper()
	noTeardown(tb)
	it := &iface{
		name:   name,
		dev:    "fake-" + name,
		ip:     ip,
		addr:   netip.MustParseAddr(ip),
		prefix: netip.MustParsePrefix(subnet),
		tun:    dev,
		done:   make(chan struct{}),
	}
	mu.Lock()
	next := reg.Load().clone()
	next.byName[name] = it
	next.byIP[it.addr] = it
	next.routes = append(next.routes, it)
	sortRoutes(next.routes)
	reg.Store(next)
	mu.Unlock()
	go it.readLoop()

	tb.Cleanup(func() {
		Down(name) // already gone if the test retired it
		drainInbox()
	})
	return it
}

func drainInbox() {
	for {
		select {
		case f := <-inbox:
			releaseFrame(f)
		default:
			for {
				if _, ok := popFailure(); !ok {
					break
				}
			}
			select {
			case <-failReady:
			default:
			}
			return
		}
	}
}

func waitFor(tb testing.TB, what string, cond func() bool) {
	tb.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func ipv4Packet(size int) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	p[2], p[3] = byte(size>>8), byte(size)
	return p
}

func TestUpRejectsDuplicateSubnet(t *testing.T) {
	addFake(t, "dup-a", "10.250.1.0/24", "10.250.1.1", newFakeDev())

	_, err := Up("dup-b", "10.250.1.0/24", "")
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("Up on a managed subnet: error = %v, want 'already used'", err)
	}
	if _, err := Up("dup-a", "10.250.2.0/24", ""); err == nil {
		t.Fatal("Up with an existing name should fail")
	}
}

func TestUpRejectsPendingReservation(t *testing.T) {
	mu.Lock()
	pending["busy"] = reservation{
		addr:   netip.MustParseAddr("10.250.3.1"),
		prefix: netip.MustParsePrefix("10.250.3.0/24"),
	}
	mu.Unlock()
	t.Cleanup(func() { release("busy") })

	for _, tc := range []struct{ name, subnet, ip string }{
		{"busy", "10.250.4.0/24", ""},            // name in flight
		{"other", "10.250.3.0/24", ""},           // subnet in flight
		{"other", "10.250.0.0/16", "10.250.3.1"}, // address in flight
	} {
		if _, err := Up(tc.name, tc.subnet, tc.ip); err == nil {
			t.Errorf("Up(%q, %q, %q) succeeded despite a pending reservation", tc.name, tc.subnet, tc.ip)
		}
	}
}

func TestWriteToRouting(t *testing.T) {
	narrowDev, wideDev := newFakeDev(), newFakeDev()
	addFake(t, "narrow", "10.250.2.0/24", "10.250.2.1", narrowDev)
	addFake(t, "wide", "10.250.0.0/16", "10.250.0.1", wideDev)
	pkt := ipv4Packet(20)

	tests := []struct {
		dst  string
		want *fakeDev
	}{
		{"10.250.2.1", narrowDev},         // exact
		{"10.250.2.77", narrowDev},        // longest prefix
		{"::ffff:10.250.2.77", narrowDev}, // IPv4-mapped
		{"10.250.0.1", wideDev},
		{"10.250.9.9", wideDev},
	}
	for _, tt := range tests {
		before := tt.want.writes.Load()
		if _, err := WriteTo(tt.dst, pkt); err != nil {
			t.Errorf("WriteTo(%s): %v", tt.dst, err)
			continue
		}
		if tt.want.writes.Load() != before+1 {
			t.Errorf("WriteTo(%s) went to the wrong interface", tt.dst)
		}
	}
	if _, err := WriteTo("10.251.0.1", pkt); err == nil {
		t.Error("WriteTo outside every subnet should fail")
	}
}

func TestWriteToClosedInterface(t *testing.T) {
	it := addFake(t, "closing", "10.250.5.0/24", "10.250.5.1", newFakeDev())
	it.closed.Store(true)
	if _, err := WriteTo("10.250.5.1", ipv4Packet(20)); !errors.Is(err, ErrClosed) {
		t.Fatalf("WriteTo after close: error = %v, want ErrClosed", err)
	}
}

func TestReadFromDeliversPackets(t *testing.T) {
	dev := newFakeDev()
	it := addFake(t, "reader", "10.250.6.0/24", "10.250.6.1", dev)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	want := ipv4Packet(1400)
	want[19] = 0xab
	dev.packets <- want
	buf := make([]byte, MaxFrameSize)
	src, n, err := ReadFrom(ctx, buf)
	if err != nil || src != it.ip || !bytes.Equal(buf[:n], want) {
		t.Fatalf("ReadFrom = %q, %d, %v; want %q, %d bytes, nil", src, n, err, it.ip, len(want))
	}

	// Larger than the smallest buffer class, delivered to a short buffer.
	dev.packets <- ipv4Packet(3000)
	small := make([]byte, 100)
	if _, n, err := ReadFrom(ctx, small); !errors.Is(err, io.ErrShortBuffer) || n != len(small) {
		t.Fatalf("ReadFrom into short buffer = %d, %v; want %d, io.ErrShortBuffer", n, err, len(small))
	}
}

func TestReadFromDropsFramesFromClosedInterface(t *testing.T) {
	dev := newFakeDev()
	it := addFake(t, "stale", "10.250.7.0/24", "10.250.7.1", dev)
	dev.packets <- ipv4Packet(20)
	waitFor(t, "frame to be queued", func() bool { return len(inbox) == 1 })
	it.closed.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := ReadFrom(ctx, make([]byte, MaxFrameSize)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReadFrom = %v, want the stale frame discarded and DeadlineExceeded", err)
	}
}

// A read failure must reach ReadFrom even when the inbox is full.
func TestReadFailureDeliveredWhenInboxFull(t *testing.T) {
	busy := &fakeDev{closed: make(chan struct{}), loop: ipv4Packet(20)}
	addFake(t, "busy", "10.250.8.0/24", "10.250.8.1", busy)
	waitFor(t, "inbox to fill", func() bool { return len(inbox) == inboxSize })

	failing := newFakeDev()
	it := addFake(t, "failing", "10.250.9.0/24", "10.250.9.1", failing)
	failing.fail <- errors.New("device unplugged")
	waitFor(t, "failed interface to be retired", func() bool { return it.closed.Load() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := make([]byte, MaxFrameSize)
	for {
		src, _, err := ReadFrom(ctx, buf)
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("read failure was never delivered")
		}
		if err != nil {
			if src != it.ip || !strings.Contains(err.Error(), "device unplugged") {
				t.Fatalf("ReadFrom = %q, %v; want %q and the device error", src, err, it.ip)
			}
			break
		}
	}
	if _, ok := reg.Load().byName["failing"]; ok {
		t.Fatal("failed interface is still registered")
	}
}

func TestDownRetiresFakeInterface(t *testing.T) {
	dev := newFakeDev()
	it := addFake(t, "downme", "10.250.10.0/24", "10.250.10.1", dev)
	if err := Down("downme"); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if !it.closed.Load() {
		t.Fatal("Down did not close the interface")
	}
	select {
	case <-dev.closed:
	default:
		t.Fatal("Down did not close the device")
	}
	mu.Lock()
	_, stillPending := pending["downme"]
	mu.Unlock()
	if stillPending {
		t.Fatal("Down left its reservation behind")
	}
}

func TestWriteToDoesNotAllocate(t *testing.T) {
	addFake(t, "alloc", "10.250.11.0/24", "10.250.11.1", newFakeDev())
	pkt := ipv4Packet(1400)
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := WriteTo("10.250.11.9", pkt); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("WriteTo allocates %.1f times per call, want 0", allocs)
	}
}

func BenchmarkWriteTo(b *testing.B) {
	addFake(b, "bench-w", "10.250.12.0/24", "10.250.12.1", newFakeDev())
	pkt := ipv4Packet(1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := WriteTo("10.250.12.1", pkt); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkReadFrom(b *testing.B) {
	pkt := ipv4Packet(1400)
	addFake(b, "bench-r", "10.250.13.0/24", "10.250.13.1", &fakeDev{closed: make(chan struct{}), loop: pkt})
	ctx := context.Background()
	buf := make([]byte, MaxFrameSize)
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ReadFrom(ctx, buf); err != nil {
			b.Fatal(err)
		}
	}
}
