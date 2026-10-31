package checks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"time"
)

// TLSInfo is the evidence recorded for one TLS handshake. It is observational: no application data is sent.
type TLSInfo struct {
	Probe             string   `json:"probe"` // "default" | "legacy-only"
	Handshake         bool     `json:"handshake"`
	Version           string   `json:"version,omitempty"`
	CipherSuite       string   `json:"cipher_suite,omitempty"`
	ALPN              string   `json:"alpn,omitempty"`
	VerifyError       string   `json:"verify_error,omitempty"`
	HostnameError     string   `json:"hostname_error,omitempty"`
	LeafSubject       string   `json:"leaf_subject,omitempty"`
	LeafIssuer        string   `json:"leaf_issuer,omitempty"`
	LeafSANs          []string `json:"leaf_sans,omitempty"`
	LeafNotBefore     string   `json:"leaf_not_before,omitempty"`
	LeafNotAfter      string   `json:"leaf_not_after,omitempty"`
	LeafSHA256        string   `json:"leaf_sha256,omitempty"`
	SelfSigned        bool     `json:"self_signed"`
	DaysUntilExpiry   int      `json:"days_until_expiry"`
	ExpiryWarningDays int      `json:"expiry_warning_days"`
	ChainLength       int      `json:"chain_length"`
}

// RunTLS performs at most two handshakes against the pinned target:
//  1. a normal handshake (TLS 1.2+) recording version, cipher and certificate, verified separately so that an
//     untrusted certificate is still observable;
//  2. a handshake restricted to TLS 1.0/1.1 to observe whether legacy protocol versions are accepted.
func RunTLS(ctx context.Context, s Spec) Result {
	var res Result
	t := s.Target
	if len(t.IPs) == 0 {
		res.Error = "target not in validated allowlist"
		return res
	}
	timeout := time.Duration(s.TimeoutMS) * time.Millisecond / 2
	probes := []struct {
		name     string
		min, max uint16
	}{{"default", tls.VersionTLS12, tls.VersionTLS13}, {"legacy-only", tls.VersionTLS10, tls.VersionTLS11}}
	for i, p := range probes {
		if res.RequestsUsed >= s.MaxRequests {
			break
		}
		ex := Exchange{Seq: i, StartedUnixMS: time.Now().UnixMilli(),
			Request: Request{Method: "TLS-HANDSHAKE", URL: "https://" + net.JoinHostPort(t.Host, strconv.Itoa(t.Port)),
				Scheme: "https", Host: t.Host, Port: t.Port, Path: ""}}
		res.RequestsUsed++
		info, ip, err := handshake(ctx, t.Host, t.Port, t.IPs, p.min, p.max, timeout)
		ex.DurationMS = time.Now().UnixMilli() - ex.StartedUnixMS
		ex.Request.ResolvedIP = ip
		info.Probe = p.name
		info.ExpiryWarningDays = s.ExpiryDays
		ex.TLS = info
		if err != nil {
			msg := err.Error()
			ex.Error = &msg
		}
		res.Exchanges = append(res.Exchanges, ex)
		if ctx.Err() != nil {
			res.Error = ctx.Err().Error()
			return res
		}
	}
	if len(res.Exchanges) == 0 || !res.Exchanges[0].TLS.Handshake {
		res.Error = "TLS handshake with default settings failed"
	}
	return res
}

func handshake(ctx context.Context, host string, port int, ips []string, minV, maxV uint16, timeout time.Duration) (*TLSInfo, string, error) {
	info := &TLSInfo{}
	var raw net.Conn
	var used string
	var err error
	d := net.Dialer{Timeout: timeout}
	for _, ip := range ips {
		raw, err = d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err == nil {
			used = ip
			break
		}
	}
	if raw == nil {
		return info, "", err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	sni := host
	if net.ParseIP(host) != nil {
		sni = "" // SNI must not carry an IP literal
	}
	// Verification is performed explicitly below so that untrusted certificates are recorded, not hidden.
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV} //nolint:gosec
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return info, used, err
	}
	st := c.ConnectionState()
	info.Handshake = true
	info.Version = tls.VersionName(st.Version)
	info.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
	info.ALPN = st.NegotiatedProtocol
	info.ChainLength = len(st.PeerCertificates)
	if len(st.PeerCertificates) == 0 {
		return info, used, errors.New("no peer certificate")
	}
	leaf := st.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	info.LeafSHA256 = hex.EncodeToString(sum[:])
	info.LeafSubject = leaf.Subject.String()
	info.LeafIssuer = leaf.Issuer.String()
	info.LeafSANs = append(append([]string{}, leaf.DNSNames...), ipStrings(leaf.IPAddresses)...)
	info.LeafNotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	info.LeafNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	info.DaysUntilExpiry = int(time.Until(leaf.NotAfter).Hours() / 24)
	info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String() && leaf.CheckSignatureFrom(leaf) == nil
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter}); err != nil {
		info.VerifyError = err.Error()
	}
	if err := leaf.VerifyHostname(host); err != nil {
		info.HostnameError = err.Error()
	}
	return info, used, nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
