package sandbox

import (
	"strings"
	"testing"
	"time"

	"github.com/asvas/execution-plane/internal/checks"
)

func TestCredentialsAreUniqueAndBindResults(t *testing.T) {
	iss, _ := NewIssuer()
	a, _ := iss.Issue(0, time.Minute)
	b, _ := iss.Issue(0, time.Minute) // same slot, next run
	if a.ID == b.ID || string(a.Key) == string(b.Key) {
		t.Fatal("credentials must be unique per run")
	}
	r := checks.Result{RequestsUsed: 1}
	if err := SignResult(&a, &r); err != nil {
		t.Fatal(err)
	}
	if err := VerifyResult(a, r, time.Now()); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	if err := VerifyResult(b, r, time.Now()); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("result of another run accepted: %v", err)
	}
	tampered := r
	tampered.RequestsUsed = 2
	if err := VerifyResult(a, tampered, time.Now()); err == nil {
		t.Fatal("tampered result accepted")
	}
	if err := VerifyResult(a, r, time.Now().Add(2*time.Minute)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired credential accepted: %v", err)
	}
}

func TestExpiredCredentialCannotSign(t *testing.T) {
	iss, _ := NewIssuer()
	c, _ := iss.Issue(1, -time.Second)
	r := checks.Result{}
	if err := SignResult(&c, &r); err == nil {
		t.Fatal("expired credential signed a result")
	}
	c.Wipe()
	for _, x := range c.Key {
		if x != 0 {
			t.Fatal("key not wiped")
		}
	}
}

func TestIssuersDoNotShareKeys(t *testing.T) {
	i1, _ := NewIssuer()
	i2, _ := NewIssuer()
	c1, _ := i1.Issue(0, time.Minute)
	r := checks.Result{}
	_ = SignResult(&c1, &r)
	c2 := c1
	c2.Key, _ = func() ([]byte, error) { c, err := i2.Issue(0, time.Minute); return c.Key, err }()
	if VerifyResult(c2, r, time.Now()) == nil {
		t.Fatal("key from another executor verified")
	}
}
