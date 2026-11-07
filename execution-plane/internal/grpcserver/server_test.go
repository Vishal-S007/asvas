package grpcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *ca {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &ca{c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c *ca) issue(t *testing.T, server bool, uri string) ([]byte, []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		u, _ := url.Parse(uri)
		tpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &k.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

type fake struct{ calls int }

func (f *fake) Status() *pb.WorkerStatus {
	return &pb.WorkerStatus{WorkerId: "w1", Backend: "devprocess"}
}
func (f *fake) ApplyControl(_ []byte, sig string) (int, error) {
	f.calls++
	if sig != "good" {
		return 0, errors.New("control message signature invalid")
	}
	return 2, nil
}

func start(t *testing.T, root *ca) (string, *fake) {
	crt, key := root.issue(t, true, "")
	cfg, err := TLSConfig(root.pem, crt, key)
	if err != nil {
		t.Fatal(err)
	}
	b := &fake{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr, err := Serve(ctx, "127.0.0.1:0", New(cfg, b))
	if err != nil {
		t.Fatal(err)
	}
	return addr.String(), b
}

func client(t *testing.T, addr string, serverCA *ca, cert, key []byte) pb.ExecutorServiceClient {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(serverCA.pem)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		c, err := tls.X509KeyPair(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewExecutorServiceClient(conn)
}

func call(c pb.ExecutorServiceClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.GetStatus(ctx, &pb.GetStatusRequest{})
	return err
}

func TestMutualTLSAndAuthorization(t *testing.T) {
	root := newCA(t, "asvas-test-ca")
	addr, b := start(t, root)

	good, gk := root.issue(t, false, ControlPlaneID)
	if err := call(client(t, addr, root, good, gk)); err != nil {
		t.Fatalf("control plane rejected: %v", err)
	}
	if err := call(client(t, addr, root, nil, nil)); err == nil {
		t.Fatal("client without certificate accepted")
	}
	other := newCA(t, "attacker-ca")
	fc, fk := other.issue(t, false, ControlPlaneID)
	if err := call(client(t, addr, root, fc, fk)); err == nil {
		t.Fatal("certificate from a foreign CA accepted")
	}
	wc, wk := root.issue(t, false, "spiffe://asvas.local/some-other-service")
	if err := call(client(t, addr, root, wc, wk)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong identity: want PermissionDenied, got %v", err)
	}

	c := client(t, addr, root, good, gk)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.Control(ctx, &pb.SignedControl{ControlMessage: []byte("x"), Sig: "bad"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unsigned control accepted: %v", err)
	}
	ack, err := c.Control(ctx, &pb.SignedControl{ControlMessage: []byte("x"), Sig: "good"})
	if err != nil || ack.GetJobsSignalled() != 2 || b.calls != 2 {
		t.Fatalf("control failed: %v %v", ack, err)
	}
}

func TestRejectsTLS12Clients(t *testing.T) {
	root := newCA(t, "asvas-test-ca")
	addr, _ := start(t, root)
	good, gk := root.issue(t, false, ControlPlaneID)
	c, _ := tls.X509KeyPair(good, gk)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(root.pem)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{c},
		MaxVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.2 handshake accepted")
	}
}
