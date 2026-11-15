//go:build darwin

package ifac

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2 // SYSPROTO_CONTROL, <sys/sys_domain.h>
	utunOptIfname   = 2 // UTUN_OPT_IFNAME, <net/if_utun.h>

	// utunHeader is the address-family word utun puts in front of every
	// packet in both directions.
	utunHeader = 4

	// readHeadroom is the number of bytes the device prepends to each packet
	// it reads.
	readHeadroom = utunHeader
)

var utunName = regexp.MustCompile(`^utun[0-9]+$`)

// utun is a macOS utun kernel-control socket. The descriptor is
// non-blocking, so os.File registers it with the runtime poller: an idle
// reader parks without holding an OS thread, and Close safely interrupts a
// blocked Read or Write.
type utun struct {
	f *os.File
}

// read leaves the utun header in place and reports where the packet starts,
// so the packet is never copied just to strip four bytes.
func (t *utun) read(buf []byte) (int, int, error) {
	n, err := t.f.Read(buf)
	if n < utunHeader {
		return 0, 0, err
	}
	return utunHeader, n - utunHeader, err
}

func (t *utun) write(packet []byte) (int, error) {
	var family byte
	switch packet[0] >> 4 {
	case 4:
		family = unix.AF_INET
	case 6:
		family = unix.AF_INET6
	default:
		return 0, errors.New("ifac: unable to determine IP version from packet")
	}

	bp := getBuffer(len(packet) + utunHeader)
	b := (*bp)[:len(packet)+utunHeader]
	b[0], b[1], b[2], b[3] = 0, 0, 0, family
	copy(b[utunHeader:], packet)
	n, err := t.f.Write(b)
	putBuffer(bp)
	return max(n-utunHeader, 0), err
}

func (t *utun) Close() error { return t.f.Close() }

// validateName accepts any name: names other than utunN are only logical
// handles on macOS.
func validateName(string) error { return nil }

// createTUN opens a utun device. The macOS kernel only accepts utunN device
// names: a name of that form is requested verbatim, anything else lets the
// kernel assign a device while the caller's name remains the logical handle.
// The descriptor is closed on every error path, so a failed Up never leaks it.
func createTUN(name string) (_ device, _ string, err error) {
	var unit uint32 // 0 lets the kernel pick the next free utun
	if utunName.MatchString(name) {
		n, perr := strconv.ParseUint(name[len("utun"):], 10, 32)
		if perr != nil || n == 1<<32-1 {
			return nil, "", fmt.Errorf("invalid utun device name %q", name)
		}
		unit = uint32(n) + 1
	}

	// Hold ForkLock so a concurrent exec cannot inherit the descriptor
	// before it is marked close-on-exec (darwin has no SOCK_CLOEXEC).
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, "", fmt.Errorf("utun socket: %w", err)
	}
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()

	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		return nil, "", fmt.Errorf("CTLIOCGINFO: %w", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: unit}); err != nil {
		return nil, "", fmt.Errorf("connect utun unit %d: %w", unit, err)
	}
	dev, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		return nil, "", fmt.Errorf("UTUN_OPT_IFNAME: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, "", fmt.Errorf("set non-blocking: %w", err)
	}
	return &utun{f: os.NewFile(uintptr(fd), dev)}, dev, nil
}

func configure(dev, ip string, prefix netip.Prefix) error {
	// utun is point-to-point; assigning the local address as its own peer
	// and routing the subnet at the interface gives plain subnet semantics.
	if err := run("/sbin/ifconfig", dev, "inet", ip, ip, "up"); err != nil {
		return err
	}
	return run("/sbin/route", "-q", "-n", "add", "-inet", prefix.Masked().String(), "-interface", dev)
}

// Remove the explicit subnet route before the utun descriptor is closed.
func teardown(dev, _ string, prefix netip.Prefix) error {
	return run("/sbin/route", "-q", "-n", "delete", "-inet", prefix.Masked().String(), "-interface", dev)
}
