// Package netguard performs destination validation in the execution plane, independently of the
// control plane: resolve once, validate every address, and hand pinned addresses to the sandbox.
// This defeats DNS rebinding (no second lookup happens at connect time) and limits redirects to
// destinations that were validated up front.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

var forbidden = mustPrefixes("0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
	"::/128", "fe80::/10", "ff00::/8")
var loopback = mustPrefixes("127.0.0.0/8", "::1/128")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

type Config struct {
	AllowLoopback  bool
	ProtectedPorts []int
}

// Resolver is replaceable in tests (e.g. to simulate rebinding answers).
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

func SystemResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out), nil
}

// Violations returns why addr:port may not be contacted under the given scope CIDRs.
func Violations(cfg Config, addr netip.Addr, port int, allowed, excluded []string) []string {
	var out []string
	for _, p := range forbidden {
		if p.Contains(addr) {
			out = append(out, fmt.Sprintf("%s is in a globally forbidden network", addr))
		}
	}
	for _, p := range loopback {
		if p.Contains(addr) {
			if !cfg.AllowLoopback {
				out = append(out, fmt.Sprintf("%s is loopback and loopback targets are disabled", addr))
			} else if slices.Contains(cfg.ProtectedPorts, port) {
				out = append(out, fmt.Sprintf("port %d on loopback is a protected platform port", port))
			}
		}
	}
	in := false
	for _, c := range allowed {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(addr) {
			in = true
		}
	}
	if !in {
		out = append(out, fmt.Sprintf("%s is outside allowed_cidrs", addr))
	}
	for _, c := range excluded {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(addr) {
			out = append(out, fmt.Sprintf("%s is inside excluded_cidrs", addr))
		}
	}
	return out
}

// Endpoint is a validated destination the sandbox may contact.
type Endpoint struct {
	Scheme string   `json:"scheme"`
	Host   string   `json:"host"`
	Port   int      `json:"port"`
	IPs    []string `json:"ips"`
}

func (e Endpoint) Key() string {
	return fmt.Sprintf("%s://%s:%d", e.Scheme, strings.ToLower(e.Host), e.Port)
}

// BuildAllowlist resolves every scope target once and keeps only endpoints whose every address passes.
// A hostname with ANY disallowed answer is dropped entirely (mixed answers are a rebinding signal).
func BuildAllowlist(ctx context.Context, cfg Config, resolve Resolver, targets []ScopeTarget, allowed, excluded []string) ([]Endpoint, map[string][]string) {
	var eps []Endpoint
	rejected := map[string][]string{}
	for _, t := range targets {
		addrs, err := resolve(ctx, t.Host)
		if err != nil || len(addrs) == 0 {
			rejected[t.Host] = []string{fmt.Sprintf("resolution failed: %v", err)}
			continue
		}
		for _, port := range t.Ports {
			var reasons []string
			ips := make([]string, 0, len(addrs))
			for _, a := range addrs {
				reasons = append(reasons, Violations(cfg, a, port, allowed, excluded)...)
				ips = append(ips, a.String())
			}
			if len(reasons) > 0 {
				rejected[fmt.Sprintf("%s:%d", t.Host, port)] = reasons
				continue
			}
			for _, s := range t.Schemes {
				eps = append(eps, Endpoint{Scheme: s, Host: t.Host, Port: port, IPs: ips})
			}
		}
	}
	return eps, rejected
}

type ScopeTarget struct {
	Host    string
	Ports   []int
	Schemes []string
}
