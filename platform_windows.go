//go:build windows

package ifac

import (
	"net/netip"
	"strconv"

	"github.com/Doridian/water"
)

// createTUN creates a native layer-3 Wintun adapter. Unlike the legacy
// TAP-Windows emulation path, this does not require a preinstalled tap0901
// adapter and does not synthesize ARP for a layer-3 device.
func createTUN(name, _ string, _ netip.Prefix) (*water.Interface, string, error) {
	cfg := water.Config{DeviceType: water.TUN}
	cfg.PlatformSpecificParams = water.PlatformSpecificParams{
		InterfaceName: name,
	}
	tun, err := water.New(cfg)
	if err != nil {
		return nil, "", err
	}
	return tun, tun.Name(), nil
}

func configure(dev, ip string, prefix netip.Prefix) error {
	const script = `$ErrorActionPreference = 'Stop'
New-NetIPAddress -InterfaceAlias $args[0] -AddressFamily IPv4 -IPAddress $args[1] -PrefixLength ([byte]$args[2]) -PolicyStore ActiveStore | Out-Null`
	return run("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
		"-Command", script, dev, ip, strconv.Itoa(prefix.Bits()))
}

func teardown(dev, ip string, _ netip.Prefix) error {
	const script = `$ErrorActionPreference = 'Stop'
Get-NetIPAddress -InterfaceAlias $args[0] -AddressFamily IPv4 -IPAddress $args[1] -ErrorAction SilentlyContinue |
	Remove-NetIPAddress -Confirm:$false`
	return run("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
		"-Command", script, dev, ip)
}
