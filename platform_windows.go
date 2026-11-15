//go:build windows

package ifac

import (
	"net/netip"
	"strconv"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// readHeadroom is the number of bytes the device prepends to each packet it
// reads. Wintun delivers bare IP packets.
const readHeadroom = 0

// wintunMTU is the MTU the adapter is created with.
const wintunMTU = 1500

// wintunDevice adapts wireguard-go's vectored Wintun device to a
// packet-at-a-time interface. The single-element slices are reused so the
// per-packet path does not allocate. Wintun itself rejects I/O after Close
// and waits for in-flight calls, so Close is safe alongside read and write.
type wintunDevice struct {
	dev tun.Device

	// Only the interface's reader goroutine calls read.
	rbufs [][]byte
	sizes []int

	wmu   sync.Mutex
	wbufs [][]byte
}

func (w *wintunDevice) read(buf []byte) (int, int, error) {
	w.rbufs[0] = buf
	n, err := w.dev.Read(w.rbufs, w.sizes, 0)
	w.rbufs[0] = nil
	if err != nil || n == 0 {
		return 0, 0, err
	}
	return 0, w.sizes[0], nil
}

func (w *wintunDevice) write(packet []byte) (int, error) {
	w.wmu.Lock()
	w.wbufs[0] = packet
	_, err := w.dev.Write(w.wbufs, 0)
	w.wbufs[0] = nil
	w.wmu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(packet), nil
}

func (w *wintunDevice) Close() error { return w.dev.Close() }

// validateName accepts any name; Windows adapter names are free-form.
func validateName(string) error { return nil }

// createTUN creates a native layer-3 Wintun adapter. Unlike the legacy
// TAP-Windows emulation path, this does not require a preinstalled tap0901
// adapter and does not synthesize ARP for a layer-3 device.
func createTUN(name string) (device, string, error) {
	dev, err := tun.CreateTUN(name, wintunMTU)
	if err != nil {
		return nil, "", err
	}
	devName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	return &wintunDevice{
		dev:   dev,
		rbufs: make([][]byte, 1),
		sizes: make([]int, 1),
		wbufs: make([][]byte, 1),
	}, devName, nil
}

// The PowerShell scripts read their inputs from environment variables:
// with -Command, trailing arguments are appended to the script text rather
// than bound to $args, and the environment also keeps adapter names with
// spaces or quotes intact.

func configure(dev, ip string, prefix netip.Prefix) error {
	const script = `$ErrorActionPreference = 'Stop'
New-NetIPAddress -InterfaceAlias $env:IFAC_DEV -AddressFamily IPv4 -IPAddress $env:IFAC_IP -PrefixLength ([byte]$env:IFAC_BITS) -PolicyStore ActiveStore | Out-Null`
	return powershell(script, "IFAC_DEV="+dev, "IFAC_IP="+ip, "IFAC_BITS="+strconv.Itoa(prefix.Bits()))
}

func teardown(dev, ip string, _ netip.Prefix) error {
	const script = `$ErrorActionPreference = 'Stop'
Get-NetIPAddress -InterfaceAlias $env:IFAC_DEV -AddressFamily IPv4 -IPAddress $env:IFAC_IP -ErrorAction SilentlyContinue |
	Remove-NetIPAddress -Confirm:$false`
	return powershell(script, "IFAC_DEV="+dev, "IFAC_IP="+ip)
}

func powershell(script string, env ...string) error {
	return runEnv(env, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
}
