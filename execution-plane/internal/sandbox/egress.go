package sandbox

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/asvas/execution-plane/internal/netguard"
)

const nftTable = "asvas_exec"

// Egress programs per-slot nftables allow-sets keyed by the sandbox UID. Every packet from a sandbox UID
// that is not to an allowlisted ip:port is rejected by the kernel, independently of the tool code.
type Egress struct {
	mu    sync.Mutex
	slots int
}

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func NewEgress(slots int) (*Egress, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", nftTable, nftTable, nftTable)
	for i := 0; i <= slots; i++ {
		fmt.Fprintf(&b, "  set allow4_%d { type ipv4_addr . inet_service; }\n  set allow6_%d { type ipv6_addr . inet_service; }\n", i, i)
	}
	b.WriteString("  chain out {\n    type filter hook output priority 0; policy accept;\n")
	for i := 0; i <= slots; i++ {
		uid := BaseUID + i
		fmt.Fprintf(&b, "    meta skuid %d ip daddr . tcp dport @allow4_%d accept\n", uid, i)
		fmt.Fprintf(&b, "    meta skuid %d ip6 daddr . tcp dport @allow6_%d accept\n", uid, i)
		fmt.Fprintf(&b, "    meta skuid %d counter reject\n", uid)
	}
	b.WriteString("  }\n}\n")
	if err := nft(b.String()); err != nil {
		return nil, err
	}
	return &Egress{slots: slots}, nil
}

func (e *Egress) Allow(slot int, eps []netguard.Endpoint) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s allow4_%d\nflush set inet %s allow6_%d\n", nftTable, slot, nftTable, slot)
	for _, ep := range eps {
		for _, ip := range ep.IPs {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				return err
			}
			set := "allow4"
			if a.Is6() && !a.Is4In6() {
				set = "allow6"
			}
			fmt.Fprintf(&b, "add element inet %s %s_%d { %s . %d }\n", nftTable, set, slot, a.Unmap(), ep.Port)
		}
	}
	return nft(b.String())
}

func (e *Egress) Clear(slot int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = nft(fmt.Sprintf("flush set inet %s allow4_%d\nflush set inet %s allow6_%d\n", nftTable, slot, nftTable, slot))
}

func (e *Egress) Teardown() { _ = nft(fmt.Sprintf("delete table inet %s\n", nftTable)) }

type netDialer struct{}

func (netDialer) dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}
