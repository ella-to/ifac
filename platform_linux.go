//go:build linux

package ifac

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// readHeadroom is the number of bytes the device prepends to each packet it
// reads. IFF_NO_PI makes Linux deliver bare IP packets.
const readHeadroom = 0

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

// tunFile is a Linux TUN device. The descriptor is non-blocking, so os.File
// registers it with the runtime poller: an idle reader parks without holding
// an OS thread, and Close safely interrupts a blocked Read or Write.
type tunFile struct {
	f *os.File
}

func (t *tunFile) read(buf []byte) (int, int, error) {
	n, err := t.f.Read(buf)
	return 0, n, err
}

func (t *tunFile) write(packet []byte) (int, error) { return t.f.Write(packet) }

func (t *tunFile) Close() error { return t.f.Close() }

// createTUN opens a non-persistent TUN device named name. The descriptor is
// closed on every error path, so a failed Up never leaks it.
func createTUN(name string) (device, string, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, "", fmt.Errorf("interface name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/net/tun: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF %q: %w", name, err)
	}
	return &tunFile{f: os.NewFile(uintptr(fd), "/dev/net/tun")}, ifr.Name(), nil
}

func configure(dev, ip string, prefix netip.Prefix) error {
	bin := ipBin()
	if err := run(bin, "addr", "add", fmt.Sprintf("%s/%d", ip, prefix.Bits()), "dev", dev); err != nil {
		return err
	}
	// Bringing the link up also installs the connected route for the subnet.
	return run(bin, "link", "set", "dev", dev, "up")
}

// A non-persistent Linux TUN vanishes when its file descriptor is closed.
func teardown(_, _ string, _ netip.Prefix) error {
	return nil
}
