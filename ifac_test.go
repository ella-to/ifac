package ifac

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestPickIP(t *testing.T) {
	tests := []struct {
		subnet string
		taken  []string
		want   string
		errs   bool
	}{
		{subnet: "10.42.0.0/24", want: "10.42.0.1"},
		{subnet: "10.42.0.7/24", want: "10.42.0.1"}, // non-network base address is masked
		{subnet: "10.42.0.0/24", taken: []string{"10.42.0.1", "10.42.0.2"}, want: "10.42.0.3"},
		{subnet: "192.168.1.0/30", want: "192.168.1.1"},
		{subnet: "192.168.1.0/30", taken: []string{"192.168.1.1", "192.168.1.2"}, errs: true}, // exhausted
		{subnet: "192.168.1.0/31", errs: true},                                                // no usable hosts
		{subnet: "192.168.1.5/32", errs: true},
		{subnet: "fd00::/64", errs: true}, // IPv6 unsupported
	}
	for _, tt := range tests {
		prefix := netip.MustParsePrefix(tt.subnet)
		taken := make(map[string]bool, len(tt.taken))
		for _, ip := range tt.taken {
			taken[ip] = true
		}
		got, err := pickIP(prefix, func(a netip.Addr) bool { return taken[a.String()] })
		if tt.errs {
			if err == nil {
				t.Errorf("pickIP(%s, taken=%v) = %s, want error", tt.subnet, tt.taken, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("pickIP(%s, taken=%v): %v", tt.subnet, tt.taken, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("pickIP(%s, taken=%v) = %s, want %s", tt.subnet, tt.taken, got, tt.want)
		}
	}
}

func TestPickIPSkipsBroadcast(t *testing.T) {
	prefix := netip.MustParsePrefix("10.9.0.0/29") // hosts .1 through .6
	seen := 0
	_, err := pickIP(prefix, func(a netip.Addr) bool {
		seen++
		return true // reject all, forcing a full scan
	})
	if err == nil {
		t.Fatal("expected exhaustion error")
	}
	if seen != 6 {
		t.Errorf("scanned %d candidates, want 6 (network and broadcast excluded)", seen)
	}
}

func TestValidatePrefix(t *testing.T) {
	tests := []struct {
		subnet string
		errs   bool
	}{
		{subnet: "10.0.0.0/8"},
		{subnet: "10.42.0.0/24"},
		{subnet: "192.168.1.0/30"},
		{subnet: "0.0.0.0/0", errs: true},
		{subnet: "192.0.0.0/3", errs: true}, // wider than /8
		{subnet: "127.0.0.0/8", errs: true},
		{subnet: "127.1.0.0/16", errs: true},
		{subnet: "169.254.10.0/24", errs: true},
		{subnet: "224.0.0.0/24", errs: true},
		{subnet: "255.255.255.0/24", errs: true},
		{subnet: "0.1.0.0/16", errs: true},
		{subnet: "192.168.1.0/31", errs: true},
		{subnet: "fd00::/64", errs: true},
	}
	for _, tt := range tests {
		err := validatePrefix(netip.MustParsePrefix(tt.subnet))
		if (err != nil) != tt.errs {
			t.Errorf("validatePrefix(%s) error = %v, want error %t", tt.subnet, err, tt.errs)
		}
	}
}

func TestCheckLinuxIfName(t *testing.T) {
	valid := []string{"tun0", "ifac-test0", "a", "exactly15chars_"}
	invalid := []string{"sixteen-chars-xx", ".", "..", "a/b", "tun%d", "eth0:1", "has space", "tab\tname", "nul\x00"}
	for _, n := range valid {
		if err := checkLinuxIfName(n); err != nil {
			t.Errorf("checkLinuxIfName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range invalid {
		if err := checkLinuxIfName(n); err == nil {
			t.Errorf("checkLinuxIfName(%q) = nil, want error", n)
		}
	}
}

func TestCheckIP(t *testing.T) {
	tests := []struct {
		ip     string
		subnet string
		taken  []string
		errs   bool
	}{
		{ip: "10.42.0.9", subnet: "10.42.0.0/24"},
		{ip: "10.42.0.9", subnet: "10.42.0.0/24", taken: []string{"10.42.0.9"}, errs: true}, // in use
		{ip: "10.42.1.9", subnet: "10.42.0.0/24", errs: true},                               // outside subnet
		{ip: "10.42.0.0", subnet: "10.42.0.0/24", errs: true},                               // network address
		{ip: "10.42.0.255", subnet: "10.42.0.0/24", errs: true},                             // broadcast address
		{ip: "fd00::1", subnet: "10.42.0.0/24", errs: true},                                 // IPv6
		{ip: "not-an-ip", subnet: "10.42.0.0/24", errs: true},
	}
	for _, tt := range tests {
		prefix := netip.MustParsePrefix(tt.subnet)
		taken := make(map[string]bool, len(tt.taken))
		for _, ip := range tt.taken {
			taken[ip] = true
		}
		got, err := checkIP(tt.ip, prefix, func(a netip.Addr) bool { return taken[a.String()] })
		if tt.errs {
			if err == nil {
				t.Errorf("checkIP(%s, %s, taken=%v) = %s, want error", tt.ip, tt.subnet, tt.taken, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("checkIP(%s, %s, taken=%v): %v", tt.ip, tt.subnet, tt.taken, err)
			continue
		}
		if got.String() != tt.ip {
			t.Errorf("checkIP(%s, %s) = %s, want the ip back unchanged", tt.ip, tt.subnet, got)
		}
	}
}

func TestLastAddr(t *testing.T) {
	tests := []struct{ subnet, want string }{
		{"10.0.0.0/24", "10.0.0.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"192.168.4.32/28", "192.168.4.47"},
		{"172.16.0.0/30", "172.16.0.3"},
	}
	for _, tt := range tests {
		if got := lastAddr(netip.MustParsePrefix(tt.subnet)).String(); got != tt.want {
			t.Errorf("lastAddr(%s) = %s, want %s", tt.subnet, got, tt.want)
		}
	}
}

func TestDownUnknown(t *testing.T) {
	if err := Down("no-such-interface"); err == nil {
		t.Fatal("Down of unknown interface should error")
	}
}

func TestWriteToUnknown(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[3] = byte(len(packet))
	if _, err := WriteTo("203.0.113.1", packet); err == nil {
		t.Fatal("WriteTo with no matching interface should error")
	}
}

func TestClosedInterfaceRejectsWrites(t *testing.T) {
	it := &iface{}
	it.closed.Store(true)
	if _, err := it.write(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("write() error = %v, want ErrClosed", err)
	}
	if err := it.close(); err != nil {
		t.Fatalf("second close() error = %v, want nil", err)
	}
}

func TestValidatePacket(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	ipv4[3] = byte(len(ipv4))

	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60

	tests := []struct {
		name   string
		packet []byte
		errs   bool
	}{
		{name: "IPv4", packet: ipv4},
		{name: "IPv6", packet: ipv6},
		{name: "empty", errs: true},
		{name: "unknown version", packet: []byte{0x70}, errs: true},
		{name: "truncated IPv4", packet: []byte{0x45}, errs: true},
		{name: "bad IPv4 header length", packet: append([]byte{0x44, 0, 0, 20}, make([]byte, 16)...), errs: true},
		{name: "wrong IPv4 total length", packet: append([]byte{0x45, 0, 0, 21}, make([]byte, 16)...), errs: true},
		{name: "truncated IPv6", packet: []byte{0x60}, errs: true},
		{name: "wrong IPv6 payload length", packet: append([]byte{0x60, 0, 0, 0, 0, 1}, make([]byte, 34)...), errs: true},
		{name: "too large", packet: append([]byte{0x60}, make([]byte, MaxFrameSize)...), errs: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePacket(tt.packet)
			if (err != nil) != tt.errs {
				t.Fatalf("validatePacket() error = %v, want error %t", err, tt.errs)
			}
		})
	}
}

func TestSortRoutesUsesLongestPrefixFirst(t *testing.T) {
	routes := []*iface{
		{name: "wide", prefix: netip.MustParsePrefix("10.0.0.0/8")},
		{name: "narrow-z", prefix: netip.MustParsePrefix("10.1.2.0/24")},
		{name: "narrow-a", prefix: netip.MustParsePrefix("10.1.2.0/24")},
		{name: "middle", prefix: netip.MustParsePrefix("10.1.0.0/16")},
	}
	routes[1].name = "z"
	routes[2].name = "a"

	sortRoutes(routes)

	got := []string{routes[0].name, routes[1].name, routes[2].name, routes[3].name}
	want := []string{"a", "z", "middle", "wide"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortRoutes() = %v, want %v", got, want)
		}
	}
}

func TestReadFromCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := ReadFrom(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReadFrom() error = %v, want context.Canceled", err)
	}
}

// TestIntegration exercises the full lifecycle against real TUN devices.
// It needs root (Linux/macOS), so it is skipped otherwise.
func TestIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("integration test requires a TAP-Windows adapter; run manually")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root")
	}

	name := "utun71"
	if runtime.GOOS == "linux" {
		name = "ifac-test0"
	}

	ip, err := Up(name, "10.199.0.0/24", "")
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	defer Down(name)

	if ip != "10.199.0.1" {
		t.Errorf("Up assigned %s, want 10.199.0.1", ip)
	}

	names, ips, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for i, n := range names {
		if n == name && ips[i] == ip {
			found = true
		}
	}
	if !found {
		t.Errorf("List() = %v %v, missing %s/%s", names, ips, name, ip)
	}

	// A ping toward another host in the subnet is routed into the TUN
	// device by the kernel, so ReadFrom must surface it.
	go func() {
		bin := "/sbin/ping"
		if runtime.GOOS == "linux" {
			bin = "ping"
		}
		run(bin, "-c", "2", "-W", "1", "10.199.0.2")
	}()

	// The reader reports back over a channel rather than calling t from its
	// own goroutine, and its context ends with the test so it cannot outlive
	// it blocked in ReadFrom.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, MaxFrameSize)
		for {
			src, n, err := ReadFrom(ctx, buf)
			if err != nil {
				result <- fmt.Errorf("ReadFrom: %w", err)
				return
			}
			if src == ip && n > 0 {
				// Loop the frame straight back through WriteTo to
				// exercise the write path with a real packet.
				if _, err := WriteTo(ip, buf[:n]); err != nil {
					result <- fmt.Errorf("WriteTo: %w", err)
					return
				}
				result <- nil
				return
			}
		}
	}()

	if err := <-result; err != nil {
		t.Fatalf("waiting for a frame from the TUN device: %v", err)
	}

	if err := Down(name); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if err := Down(name); err == nil {
		t.Fatal("second Down should error")
	}
}
