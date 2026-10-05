package cli

import (
	"net"
	"testing"
)

// Предупреждение SNI-DNS при старте: семейство IP проверяется, только если и наш
// адрес в нём известен, и у домена есть запись этого семейства (как в mtg 9seconds).
func TestSNIFamilyMismatch(t *testing.T) {
	v4 := net.ParseIP("203.0.113.10")
	v6 := net.ParseIP("2001:db8::10")

	cases := []struct {
		name           string
		res            sniCheckResult
		wantV4, wantV6 bool
	}{
		{
			name:   "у машины есть IPv6, у домена только A - не ругаемся",
			res:    sniCheckResult{Resolved: []net.IP{v4}, OurIPv4: v4, OurIPv6: v6, IPv4Match: true},
			wantV4: false, wantV6: false,
		},
		{
			name:   "A указывает не на нас - ругаемся по IPv4",
			res:    sniCheckResult{Resolved: []net.IP{net.ParseIP("198.51.100.1")}, OurIPv4: v4},
			wantV4: true, wantV6: false,
		},
		{
			name:   "AAAA есть и не наш - ругаемся по IPv6",
			res:    sniCheckResult{Resolved: []net.IP{v4, net.ParseIP("2001:db8::99")}, OurIPv4: v4, OurIPv6: v6, IPv4Match: true},
			wantV4: false, wantV6: true,
		},
		{
			name:   "свой IPv6 неизвестен - IPv6 не проверяем",
			res:    sniCheckResult{Resolved: []net.IP{v4, v6}, OurIPv4: v4, IPv4Match: true},
			wantV4: false, wantV6: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotV4, gotV6 := c.res.familyMismatch()
			if gotV4 != c.wantV4 || gotV6 != c.wantV6 {
				t.Fatalf("получили v4=%v v6=%v, ожидали v4=%v v6=%v", gotV4, gotV6, c.wantV4, c.wantV6)
			}
		})
	}
}
