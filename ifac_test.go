package ifac

import (
	"errors"
	"io"
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

func TestDestroyUnknown(t *testing.T) {
	if err := Destroy("no-such-interface"); err == nil {
		t.Fatal("Destroy of unknown interface should error")
	}
}

func TestWriteToUnknown(t *testing.T) {
	if _, err := WriteTo("203.0.113.1", []byte{0x45}); err == nil {
		t.Fatal("WriteTo with no matching interface should error")
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

	ip, err := Create(name, "10.199.0.0/24", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer Destroy(name)

	if ip != "10.199.0.1" {
		t.Errorf("Create assigned %s, want 10.199.0.1", ip)
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

	deadline := time.After(10 * time.Second)
	got := make(chan struct{})
	go func() {
		buf := make([]byte, maxFrameSize)
		for {
			src, n, err := ReadFrom(buf)
			if err != nil && !errors.Is(err, io.ErrShortBuffer) {
				t.Errorf("ReadFrom: %v", err)
				return
			}
			if src == ip && n > 0 {
				// Loop the frame straight back through WriteTo to
				// exercise the write path with a real packet.
				if _, werr := WriteTo(ip, buf[:n]); werr != nil {
					t.Errorf("WriteTo: %v", werr)
				}
				close(got)
				return
			}
		}
	}()

	select {
	case <-got:
	case <-deadline:
		t.Fatal("timed out waiting for a frame from the TUN device")
	}

	if err := Destroy(name); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := Destroy(name); err == nil {
		t.Fatal("second Destroy should error")
	}
}
