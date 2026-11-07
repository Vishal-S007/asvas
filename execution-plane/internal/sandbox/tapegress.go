package sandbox

// Kernel egress control for Firecracker VMs: traffic leaving a VM arrives on the host as forwarded packets from
// its tap device. Each slot's tap only forwards to the job's validated ip:port pairs; everything else is dropped.

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/asvas/execution-plane/internal/netguard"
)

const tapTable = "asvas_fc"

func TapName(slot int) string { return fmt.Sprintf("asvastap%d", slot) }

type TapEgress struct {
	mu    sync.Mutex
	slots int
	apply func(string) error
}

func tapRuleset(slots int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\ndelete table inet %s\ntable inet %s {\n", tapTable, tapTable, tapTable)
	for i := 0; i < slots; i++ {
		fmt.Fprintf(&b, "  set allow4_%d { type ipv4_addr . inet_service; }\n", i)
	}
	b.WriteString("  chain forward_vm {\n    type filter hook forward priority 0; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	for i := 0; i < slots; i++ {
		fmt.Fprintf(&b, "    iifname %q ip daddr . tcp dport @allow4_%d accept\n", TapName(i), i)
		fmt.Fprintf(&b, "    iifname %q counter drop\n", TapName(i))
	}
	b.WriteString("  }\n  chain input_vm {\n    type filter hook input priority 0; policy accept;\n")
	for i := 0; i < slots; i++ { // VMs may not talk to the host itself
		fmt.Fprintf(&b, "    iifname %q ct state established,related accept\n    iifname %q drop\n", TapName(i), TapName(i))
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func NewTapEgress(slots int) (*TapEgress, error) {
	e := &TapEgress{slots: slots, apply: nft}
	return e, e.apply(tapRuleset(slots))
}

func (e *TapEgress) Allow(slot int, eps []netguard.Endpoint) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s allow4_%d\n", tapTable, slot)
	for _, ep := range eps {
		for _, ip := range ep.IPs {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				return err
			}
			if !a.Unmap().Is4() {
				return fmt.Errorf("IPv6 egress from VMs is not supported (%s)", ip)
			}
			fmt.Fprintf(&b, "add element inet %s allow4_%d { %s . %d }\n", tapTable, slot, a.Unmap(), ep.Port)
		}
	}
	return e.apply(b.String())
}

func (e *TapEgress) Clear(slot int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.apply(fmt.Sprintf("flush set inet %s allow4_%d\n", tapTable, slot))
}

func (e *TapEgress) Teardown() { _ = e.apply(fmt.Sprintf("delete table inet %s\n", tapTable)) }
