// Package grpcserver serves asvas.execution.v1.ExecutorService over mutual TLS 1.3 (spec pp. 58, 66, 68).
//
// Authentication: the client must present a certificate chaining to the configured CA (TLS layer).
// Authorization: the client certificate must carry the control-plane SPIFFE URI SAN (interceptor).
// Control messages are additionally HMAC-signed, so a stolen client certificate alone cannot cancel jobs.
package grpcserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	pb "github.com/asvas/execution-plane/gen/asvasrpc/execution/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const ControlPlaneID = "spiffe://asvas.local/control-plane"

// Backend is what the server needs from the worker.
type Backend interface {
	Status() *pb.WorkerStatus
	ApplyControl(data []byte, sig string) (int, error)
}

type service struct {
	pb.UnimplementedExecutorServiceServer
	b Backend
}

func (s *service) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.WorkerStatus, error) {
	st := s.b.Status()
	st.NowUnix = time.Now().Unix()
	return st, nil
}

func (s *service) Control(_ context.Context, in *pb.SignedControl) (*pb.ControlAck, error) {
	n, err := s.b.ApplyControl(in.GetControlMessage(), in.GetSig())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ControlAck{JobsSignalled: int32(n)}, nil
}

// TLSConfig builds a server config that requires and verifies client certificates (TLS 1.3 only).
func TLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("no CA certificates parsed")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

func LoadTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	crt, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return TLSConfig(ca, crt, key)
}

func authorize(ctx context.Context) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "no verified client certificate")
	}
	for _, u := range ti.State.VerifiedChains[0][0].URIs {
		if u.String() == ControlPlaneID {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "client certificate is not the control plane")
}

// New returns a gRPC server with mTLS credentials and the authorization interceptor.
func New(tlsCfg *tls.Config, b Backend) *grpc.Server {
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := authorize(ctx); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.ConnectionTimeout(5*time.Second), grpc.MaxRecvMsgSize(64<<10))
	pb.RegisterExecutorServiceServer(s, &service{b: b})
	return s
}

// Serve listens on addr until ctx ends.
func Serve(ctx context.Context, addr string, s *grpc.Server) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("grpc listen: %w", err)
	}
	go func() { <-ctx.Done(); s.GracefulStop() }()
	go func() { _ = s.Serve(ln) }()
	return ln.Addr(), nil
}
