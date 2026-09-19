package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

var (
	ErrBlockedIP      = errors.New("ssrf: blocked destination IP")
	ErrNoAllowedIP    = errors.New("ssrf: no allowed IP address found")
	ErrSchemeNotAllowed = errors.New("ssrf: scheme not allowed")
)

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		addr, ok := netip.AddrFromSlice(ip4)
		if !ok {
			return true
		}
		for _, prefix := range blockedPrefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

type SafeDialer struct {
	Dialer   net.Dialer
	Resolver *net.Resolver
}

func NewSafeDialer() *SafeDialer {
	return &SafeDialer{
		Dialer: net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		Resolver: net.DefaultResolver,
	}
}

func (sd *SafeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	resolver := sd.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	var targetIP net.IP
	for _, ip := range ips {
		if !IsBlockedIP(ip) {
			targetIP = ip
			break
		}
	}

	if targetIP == nil {
		return nil, fmt.Errorf("%w: %s", ErrBlockedIP, host)
	}

	targetAddr := net.JoinHostPort(targetIP.String(), port)
	return sd.Dialer.DialContext(ctx, network, targetAddr)
}

func NewSafeTransport() *http.Transport {
	sd := NewSafeDialer()
	return &http.Transport{
		DialContext:           sd.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func NewSafeClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	return &http.Client{
		Transport: NewSafeTransport(),
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("ssrf: stopped after 10 redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return ErrSchemeNotAllowed
			}
			return nil
		},
	}
}
