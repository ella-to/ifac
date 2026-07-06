//go:build darwin

package ifac

import (
	"net/netip"
	"regexp"

	"github.com/songgao/water"
)

var utunName = regexp.MustCompile(`^utun[0-9]+$`)

// createTUN opens a utun device. The macOS kernel only accepts utunN device
// names: a name of that form is requested verbatim, anything else lets the
// kernel assign a device while the caller's name remains the logical handle.
// The ip/prefix arguments are only needed on Windows.
func createTUN(name, _ string, _ netip.Prefix) (*water.Interface, string, error) {
	cfg := water.Config{DeviceType: water.TUN}
	if utunName.MatchString(name) {
		cfg.Name = name
	}
	tun, err := water.New(cfg)
	if err != nil {
		return nil, "", err
	}
	return tun, tun.Name(), nil
}

func configure(dev, ip string, prefix netip.Prefix) error {
	// utun is point-to-point; assigning the local address as its own peer
	// and routing the subnet at the interface gives plain subnet semantics.
	if err := run("/sbin/ifconfig", dev, "inet", ip, ip, "up"); err != nil {
		return err
	}
	return run("/sbin/route", "-q", "-n", "add", "-inet", prefix.Masked().String(), "-interface", dev)
}

// teardown is best-effort: the utun device vanishes when its fd closes, but
// the subnet route can linger briefly, so remove it explicitly.
func teardown(dev, _ string, prefix netip.Prefix) {
	_ = run("/sbin/route", "-q", "-n", "delete", "-inet", prefix.Masked().String(), "-interface", dev)
}
