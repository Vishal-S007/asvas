// Package checks contains the allowlisted, non-destructive tool implementations. They run inside the
// sandbox child process and can only reach the pre-validated endpoints passed in Spec.Allow.
package checks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/asvas/execution-plane/internal/netguard"
)

const (
	maxBody    = 64 * 1024
	maxExcerpt = 4 * 1024
)

type Spec struct {
	ToolID      string              `json:"tool_id"`
	Target      netguard.Endpoint   `json:"target"`
	Path        string              `json:"path"`
	ExpiryDays  int                 `json:"expiry_days"`
	Method      string              `json:"method"`
	MaxRedirect int                 `json:"max_redirects"`
	Allow       []netguard.Endpoint `json:"allow"`
	MaxRequests int                 `json:"max_requests"`
	RPS         int                 `json:"rps"`
	TimeoutMS   int64               `json:"timeout_ms"`
}

type Request struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Path       string `json:"path"`
	ResolvedIP string `json:"resolved_ip"`
}

type Response struct {
	Status        int         `json:"status"`
	Headers       [][2]string `json:"headers"`
	BodySHA256    string      `json:"body_sha256"`
	BodyLen       int         `json:"body_len"`
	BodyTruncated bool        `json:"body_truncated"`
	BodyExcerpt   string      `json:"body_excerpt"`
	TLSVersion    string      `json:"tls_version,omitempty"`
}

type Redirect struct {
	Location string `json:"location"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

type Exchange struct {
	Seq           int       `json:"seq"`
	Request       Request   `json:"request"`
	Response      *Response `json:"response"`
	Redirect      *Redirect `json:"redirect"`
	TLS           *TLSInfo  `json:"tls,omitempty"`
	Error         *string   `json:"error"`
	StartedUnixMS int64     `json:"started_unix_ms"`
	DurationMS    int64     `json:"duration_ms"`
}

type Result struct {
	Exchanges    []Exchange     `json:"exchanges"`
	RequestsUsed int            `json:"requests_used"`
	Error        string         `json:"error,omitempty"`
	Attestation  map[string]any `json:"sandbox_attestation,omitempty"`
}

func find(allow []netguard.Endpoint, scheme, host string, port int) (netguard.Endpoint, bool) {
	k := netguard.Endpoint{Scheme: scheme, Host: host, Port: port}.Key()
	for _, e := range allow {
		if e.Key() == k {
			return e, true
		}
	}
	return netguard.Endpoint{}, false
}

// client dials only pinned IPs of allowlisted endpoints; there is no DNS lookup and no proxy.
func client(allow []netguard.Endpoint, timeout time.Duration, used *string) *http.Client {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		ResponseHeaderTimeout:  timeout,
		TLSHandshakeTimeout:    timeout,
		MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, ps, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(ps)
			var ips []string
			for _, e := range allow {
				if strings.EqualFold(e.Host, host) && e.Port == port {
					ips = e.IPs
					break
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("destination %s not in validated allowlist", addr)
			}
			var lastErr error
			for _, ip := range ips {
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, ps))
				if err == nil {
					*used = ip
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func Run(ctx context.Context, s Spec) Result {
	var res Result
	method := "GET"
	maxRedirects := 0
	switch s.ToolID {
	case "http.security_headers":
		method, maxRedirects = s.Method, s.MaxRedirect
	case "http.allowed_methods":
		method = http.MethodOptions
	case "tls.configuration":
		return RunTLS(ctx, s)
	default:
		res.Error = "unknown tool"
		return res
	}
	if _, ok := find(s.Allow, s.Target.Scheme, s.Target.Host, s.Target.Port); !ok {
		res.Error = "target not in validated allowlist"
		return res
	}
	timeout := time.Duration(s.TimeoutMS) * time.Millisecond
	cur := &url.URL{Scheme: s.Target.Scheme, Host: net.JoinHostPort(s.Target.Host, strconv.Itoa(s.Target.Port)), Path: s.Path}
	interval := time.Second / time.Duration(max(1, s.RPS))
	for seq := 0; seq <= maxRedirects; seq++ {
		if res.RequestsUsed >= s.MaxRequests {
			res.Error = "request budget exhausted"
			break
		}
		if seq > 0 {
			select {
			case <-ctx.Done():
				res.Error = ctx.Err().Error()
				return res
			case <-time.After(interval):
			}
		}
		port, _ := strconv.Atoi(cur.Port())
		ex := Exchange{Seq: seq, StartedUnixMS: time.Now().UnixMilli(),
			Request: Request{Method: method, URL: cur.String(), Scheme: cur.Scheme, Host: cur.Hostname(), Port: port, Path: cur.EscapedPath()}}
		var usedIP string
		req, err := http.NewRequestWithContext(ctx, method, cur.String(), nil)
		if err != nil {
			msg := err.Error()
			ex.Error = &msg
			res.Exchanges = append(res.Exchanges, ex)
			break
		}
		req.Header.Set("User-Agent", "ASVAS-config-check/0.1 (authorized assessment)")
		req.Header.Set("X-ASVAS-Check", s.ToolID)
		res.RequestsUsed++
		resp, err := client(s.Allow, timeout, &usedIP).Do(req)
		ex.DurationMS = time.Now().UnixMilli() - ex.StartedUnixMS
		ex.Request.ResolvedIP = usedIP
		if err != nil {
			msg := err.Error()
			ex.Error = &msg
			res.Exchanges = append(res.Exchanges, ex)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
				res.Error = ctx.Err().Error()
			}
			break
		}
		ex.Response = readResponse(resp)
		res.Exchanges = append(res.Exchanges, ex)
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" || s.ToolID != "http.security_headers" {
			break
		}
		next, why := nextHop(cur, loc, s.Allow)
		if next == nil {
			res.Exchanges[len(res.Exchanges)-1].Redirect = &Redirect{Location: trunc(loc, 512), Decision: "blocked", Reason: why}
			break
		}
		if seq == maxRedirects {
			res.Exchanges[len(res.Exchanges)-1].Redirect = &Redirect{Location: trunc(loc, 512), Decision: "not_followed", Reason: "max_redirects reached"}
			break
		}
		res.Exchanges[len(res.Exchanges)-1].Redirect = &Redirect{Location: trunc(loc, 512), Decision: "followed"}
		cur = next
	}
	if len(res.Exchanges) > 0 && res.Exchanges[0].Response == nil && res.Error == "" {
		res.Error = "no response from target"
	}
	return res
}

// nextHop validates a redirect target against the allowlist. Only in-scope scheme/host/port are followed.
func nextHop(cur *url.URL, loc string, allow []netguard.Endpoint) (*url.URL, string) {
	u, err := cur.Parse(loc)
	if err != nil {
		return nil, "unparseable Location"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "non-HTTP redirect scheme"
	}
	if u.User != nil {
		return nil, "credentials in redirect URL"
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	p, _ := strconv.Atoi(port)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if _, ok := find(allow, u.Scheme, host, p); !ok {
		return nil, fmt.Sprintf("redirect destination %s://%s:%d is outside the validated scope", u.Scheme, host, p)
	}
	u.Host = net.JoinHostPort(host, port)
	u.RawQuery, u.Fragment = "", ""
	return u, ""
}

func readResponse(resp *http.Response) *Response {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	truncated := len(body) > maxBody
	if truncated {
		body = body[:maxBody]
	}
	sum := sha256.Sum256(body)
	var hs [][2]string
	keys := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range resp.Header[k] {
			hs = append(hs, [2]string{k, trunc(v, 2048)})
		}
	}
	ex := body
	if len(ex) > maxExcerpt {
		ex = ex[:maxExcerpt]
	}
	r := &Response{Status: resp.StatusCode, Headers: hs, BodySHA256: hex.EncodeToString(sum[:]), BodyLen: len(body),
		BodyTruncated: truncated, BodyExcerpt: strings.ToValidUTF8(string(ex), "\uFFFD")}
	if resp.TLS != nil {
		r.TLSVersion = tls.VersionName(resp.TLS.Version)
	}
	return r
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
