package sandbox

// Job channel between the executor and the guest agent inside a Firecracker VM (PO-10), over virtio-vsock.
// Frames are a 4-byte big-endian length followed by JSON. The guest receives one Spec (including the per-run
// credential, PO-16) and returns one Result MAC'd with that credential; the host verifies it (VerifyResult).

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/asvas/execution-plane/internal/checks"
)

const (
	GuestAgentPort = 5000
	maxFrame       = 4 << 20
)

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("frame too large")
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > maxFrame {
		return fmt.Errorf("frame of %d bytes exceeds limit", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// dialGuest connects to the guest agent through Firecracker's host-side vsock unix socket
// ("CONNECT <port>\n" -> "OK <host port>\n"), retrying until the guest is listening or ctx ends.
func dialGuest(ctx context.Context, udsPath string) (net.Conn, error) {
	for {
		c, err := (&net.Dialer{}).DialContext(ctx, "unix", udsPath)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = fmt.Fprintf(c, "CONNECT %d\n", GuestAgentPort); err == nil {
				var line string
				line, err = bufio.NewReader(c).ReadString('\n')
				if err == nil && strings.HasPrefix(line, "OK ") {
					_ = c.SetDeadline(time.Time{})
					return c, nil
				}
				if err == nil {
					err = fmt.Errorf("vsock handshake: %q", strings.TrimSpace(line))
				}
			}
			c.Close()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("guest agent not reachable over vsock: %w (last error: %v)", ctx.Err(), err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// exchange sends the spec and returns the guest's result (unverified; caller runs VerifyResult).
func exchange(ctx context.Context, c net.Conn, spec checks.Spec) (checks.Result, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := writeFrame(c, spec); err != nil {
		return checks.Result{}, err
	}
	var r checks.Result
	if err := readFrame(c, &r); err != nil {
		return checks.Result{}, fmt.Errorf("reading guest result: %w", err)
	}
	return r, nil
}

// ServeGuestConn is the guest agent's handler for one connection: read the spec, run the check, sign, reply.
func ServeGuestConn(ctx context.Context, c net.Conn, attestation map[string]any) error {
	defer c.Close()
	var spec checks.Spec
	if err := readFrame(c, &spec); err != nil {
		return err
	}
	var cred Credential
	if err := json.Unmarshal(spec.Credential, &cred); err != nil {
		return writeFrame(c, checks.Result{Error: "missing sandbox credential"})
	}
	spec.Credential = nil
	jctx, cancel := context.WithTimeout(ctx, time.Duration(max(1000, spec.TimeoutMS))*time.Millisecond)
	defer cancel()
	res := checks.Run(jctx, spec)
	res.Attestation = attestation
	if err := SignResult(&cred, &res); err != nil {
		res = checks.Result{Error: err.Error()}
	}
	cred.Wipe()
	return writeFrame(c, res)
}
