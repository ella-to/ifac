//go:build linux

package ifac

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"

	"github.com/songgao/water"
)

// ipBin resolves iproute2's ip tool via PATH, falling back to well-known
// absolute locations (sbin directories are often absent from non-root PATHs).
func ipBin() string {
	if p, err := exec.LookPath("ip"); err == nil {
		return p
	}
	for _, f := range []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"} {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return "ip"
}

// createTUN opens a non-persistent TUN device named name; the ip/prefix
// arguments are only needed on Windows.
func createTUN(name, _ string, _ netip.Prefix) (*water.Interface, string, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.Name = name
	tun, err := water.New(cfg)
	if err != nil {
		return nil, "", err
	}
	return tun, tun.Name(), nil
}

func configure(dev, ip string, prefix netip.Prefix) error {
	bin := ipBin()
	if err := run(bin, "addr", "add", fmt.Sprintf("%s/%d", ip, prefix.Bits()), "dev", dev); err != nil {
		return err
	}
	// Bringing the link up also installs the connected route for the subnet.
	return run(bin, "link", "set", "dev", dev, "up")
}

// teardown is best-effort: a non-persistent TUN vanishes when its fd closes.
func teardown(dev, _ string, _ netip.Prefix) {
	_ = run(ipBin(), "link", "delete", dev)
}
