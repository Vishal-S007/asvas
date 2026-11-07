package sandbox

// PO-16 (spec pp. 7, 414): every sandbox run gets its own short-lived credential. The executor derives a fresh
// key per run from a per-process random master (never persisted, never sent anywhere else), hands it only to that
// sandbox, and accepts the sandbox's result only if it is MAC'd with that key before the credential expires.
// A result from another sandbox, a replay of an earlier run in the same slot, or output produced after expiry is
// rejected. The credential id (a hash, not the key) is reported in the attestation for audit.
//
// This sandbox needs no cloud/IAM access, so no cloud credential is issued; a backend that does (e.g. a
// Firecracker VM fetching artifacts) must use the same pattern with an STS-style issuer (not implemented).

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/asvas/execution-plane/internal/checks"
)

type Credential struct {
	ID        string `json:"id"`
	Key       []byte `json:"key"`
	ExpiresMS int64  `json:"expires_unix_ms"`
}

type Issuer struct{ master []byte }

func NewIssuer() (*Issuer, error) {
	m := make([]byte, 32)
	if _, err := rand.Read(m); err != nil {
		return nil, err
	}
	return &Issuer{master: m}, nil
}

// Issue derives a unique credential for one sandbox run. ttl should be the job timeout plus a small margin.
func (i *Issuer) Issue(slot int, ttl time.Duration) (Credential, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Credential{}, err
	}
	exp := time.Now().Add(ttl).UnixMilli()
	mac := hmac.New(sha256.New, i.master)
	fmt.Fprintf(mac, "asvas-sandbox-cred|%d|%d|%x", slot, exp, nonce)
	key := mac.Sum(nil)
	id := sha256.Sum256(key)
	return Credential{ID: hex.EncodeToString(id[:8]), Key: key, ExpiresMS: exp}, nil
}

func (c *Credential) Wipe() {
	for i := range c.Key {
		c.Key[i] = 0
	}
}

func resultMAC(key []byte, r checks.Result) (string, error) {
	r.CredMAC = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// SignResult is called inside the sandbox.
func SignResult(c *Credential, r *checks.Result) error {
	if c == nil {
		return errors.New("no sandbox credential")
	}
	r.CredID = c.ID
	if time.Now().UnixMilli() > c.ExpiresMS {
		return errors.New("sandbox credential expired before the result was produced")
	}
	mac, err := resultMAC(c.Key, *r)
	r.CredMAC = mac
	return err
}

// VerifyResult is called by the executor on the sandbox's output.
func VerifyResult(c Credential, r checks.Result, now time.Time) error {
	if r.CredID != c.ID {
		return fmt.Errorf("result credential %q does not belong to this sandbox run", r.CredID)
	}
	if now.UnixMilli() > c.ExpiresMS {
		return errors.New("sandbox credential expired")
	}
	want, err := resultMAC(c.Key, r)
	if err != nil || !hmac.Equal([]byte(want), []byte(r.CredMAC)) {
		return errors.New("sandbox result MAC invalid")
	}
	return nil
}
