package ifac

import (
	"fmt"
	"strings"
)

// linuxIfNameMax is IFNAMSIZ-1: the kernel truncates longer names.
const linuxIfNameMax = 15

// checkLinuxIfName rejects names the Linux kernel would truncate,
// reinterpret, or refuse. It lives outside the linux build so it can be
// tested on every platform.
func checkLinuxIfName(name string) error {
	if len(name) > linuxIfNameMax {
		return fmt.Errorf("ifac: interface name %q is longer than %d bytes", name, linuxIfNameMax)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("ifac: invalid interface name %q", name)
	}
	// '/' and whitespace are invalid, '%' makes the kernel treat the name as
	// a template (e.g. "tun%d"), and ':' denotes an address alias.
	if i := strings.IndexFunc(name, func(r rune) bool {
		return r == '/' || r == '%' || r == ':' || r <= ' ' || r == 0x7f
	}); i >= 0 {
		return fmt.Errorf("ifac: interface name %q contains invalid character %q", name, name[i])
	}
	return nil
}
