//go:build windows

package ifac

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/songgao/water"
)

// createTUN attaches to an installed TAP-Windows ("tap0901") adapter whose
// friendly name matches name, running it in the driver's TUN emulation mode.
// The driver needs the local address and subnet up front to synthesize ARP
// replies for the Windows kernel.
func createTUN(name, ip string, prefix netip.Prefix) (*water.Interface, string, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.PlatformSpecificParams = water.PlatformSpecificParams{
		ComponentID:   "tap0901",
		InterfaceName: name,
		Network:       fmt.Sprintf("%s/%d", ip, prefix.Bits()),
	}
	tun, err := water.New(cfg)
	if err != nil {
		return nil, "", err
	}
	return tun, tun.Name(), nil
}

func configure(dev, ip string, prefix netip.Prefix) error {
	mask := net.CIDRMask(prefix.Bits(), 32)
	return run("netsh", "interface", "ipv4", "set", "address",
		"name="+dev, "source=static",
		"addr="+ip,
		fmt.Sprintf("mask=%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]))
}

// teardown is best-effort: the TAP adapter itself persists (it is installed
// system-wide), so just release the static address.
func teardown(dev, _ string, _ netip.Prefix) {
	_ = run("netsh", "interface", "ipv4", "set", "address", "name="+dev, "source=dhcp")
}
