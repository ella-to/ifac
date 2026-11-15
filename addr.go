package ifac

import (
	"fmt"
	"net/netip"
)

// minPrefixBits is the widest subnet Up accepts. Anything wider would claim a
// large slice of the address space and override the host's own routes.
const minPrefixBits = 8

// reservedPrefixes cannot be assigned to an interface without breaking host
// networking (or are not unicast at all).
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("224.0.0.0/4"),    // multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, incl. limited broadcast
}

func validatePrefix(prefix netip.Prefix) error {
	if !prefix.Addr().Is4() {
		return fmt.Errorf("ifac: subnet %s: only IPv4 subnets are supported", prefix)
	}
	if prefix.Bits() > 30 {
		return fmt.Errorf("ifac: subnet %s has no usable host addresses (need /30 or wider)", prefix)
	}
	if prefix.Bits() < minPrefixBits {
		return fmt.Errorf("ifac: subnet %s is too wide (need /%d or narrower)", prefix, minPrefixBits)
	}
	for _, r := range reservedPrefixes {
		if prefix.Overlaps(r) {
			return fmt.Errorf("ifac: subnet %s overlaps reserved range %s", prefix, r)
		}
	}
	return nil
}

// pickIP returns the first usable IPv4 host address in prefix for which
// taken reports false. The network and broadcast addresses are never
// returned, so prefixes must be /30 or wider.
func pickIP(prefix netip.Prefix, taken func(netip.Addr) bool) (netip.Addr, error) {
	if err := validatePrefix(prefix); err != nil {
		return netip.Addr{}, err
	}
	bcast := lastAddr(prefix)
	for a := prefix.Masked().Addr().Next(); a.Less(bcast); a = a.Next() {
		if !taken(a) {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("ifac: subnet %s: no free addresses", prefix)
}

// checkIP validates a caller-supplied address: it must parse as IPv4, be a
// usable host address inside prefix (not the network or broadcast address),
// and taken must report false for it.
func checkIP(ip string, prefix netip.Prefix, taken func(netip.Addr) bool) (netip.Addr, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("ifac: invalid ip %q: %w", ip, err)
	}
	if !a.Is4() {
		return netip.Addr{}, fmt.Errorf("ifac: ip %q: only IPv4 addresses are supported", ip)
	}
	if !prefix.Contains(a) {
		return netip.Addr{}, fmt.Errorf("ifac: ip %s is not in subnet %s", a, prefix)
	}
	if prefix.Bits() <= 30 && (a == prefix.Masked().Addr() || a == lastAddr(prefix)) {
		return netip.Addr{}, fmt.Errorf("ifac: ip %s is the network or broadcast address of %s", a, prefix)
	}
	if taken(a) {
		return netip.Addr{}, fmt.Errorf("ifac: ip %s is already in use", a)
	}
	return a, nil
}

// lastAddr returns the highest address in an IPv4 prefix (its broadcast
// address for prefixes narrower than /31).
func lastAddr(prefix netip.Prefix) netip.Addr {
	a := prefix.Masked().Addr().As4()
	for i := prefix.Bits(); i < 32; i++ {
		a[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(a)
}
