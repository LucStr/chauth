package chproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/LucStr/chauth/internal/chusers"
	"github.com/LucStr/chauth/internal/chwire"
)

// upstreamLoginAttempts covers a new temp user that has not reached the answering replica yet.
const upstreamLoginAttempts = 4

func (f *failure) nativeCode() int32 {
	switch f.kind {
	case badTarget:
		return chwire.CodeUnknownDatabase
	case unavailable:
		return chwire.CodeNetworkError
	case limited:
		return chwire.CodeTooManyQueries
	}
	return chwire.CodeAccessDenied
}

// ServeNative accepts native connections on ln, which must not be a TLS listener: TLS is done per
// connection under the handshake deadline. It returns after ctx ends and every connection closed.
func (s *Server) ServeNative(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		s.Stop()
		ln.Close()
	}()
	defer s.conns.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.conns.Add(1)
		go func() {
			defer s.conns.Done()
			s.handleNative(conn)
		}()
	}
}

func (s *Server) handleNative(raw net.Conn) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Duration(s.cfg.Limits.HandshakeTimeout)))
	conn := tls.Server(raw, s.tls)
	if err := conn.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	hello, err := chwire.ReadHello(br, s.cfg.Limits.PreAuthMaxBytes)
	if err != nil {
		if errors.Is(err, chwire.ErrTooLarge) || errors.Is(err, chwire.ErrNotHello) {
			s.refuse(conn, br, chwire.CodeAccessDenied, "chauth: "+err.Error())
		}
		return
	}
	ctx, finish, a := s.begin(context.Background(), "native")
	a.db = hello.Database
	if chwire.RefusedUser(hello.User) {
		finish("deny", "refused user marker")
		s.refuse(conn, br, chwire.CodeAccessDenied, "chauth: log in with the database token as the password")
		return
	}
	in, d, f := s.decide(ctx, hello.Password, hello.Database, a)
	if f != nil {
		finish("deny", f.msg)
		s.refuse(conn, br, f.nativeCode(), f.msg)
		return
	}
	if !s.admit(d.Claims.Subject) {
		msg := fmt.Sprintf("chauth: too many connections for %s (limit %d)", d.Claims.Username, s.cfg.Limits.MaxConnectionsPerUser)
		finish("deny", msg)
		s.refuse(conn, br, chwire.CodeTooManyQueries, msg)
		return
	}
	defer s.leave(d.Claims.Subject)

	lease, err := in.users.Acquire(ctx, d.key())
	if err != nil {
		f := acquireFailure(err)
		finish(f.decision(), err.Error())
		s.refuse(conn, br, f.nativeCode(), f.msg)
		return
	}
	defer lease.Release()
	a.tempUser = lease.User

	up, upr, code, err := s.dialNative(ctx, in, hello, lease, d.Database)
	if err != nil {
		finish("error", err.Error())
		msg := "chauth: could not open the upstream connection"
		if code == chwire.CodeUnknownDatabase {
			msg = fmt.Sprintf("chauth: database %s does not exist on %s", d.Database, d.Instance)
		} else if code != 0 {
			msg = fmt.Sprintf("chauth: the upstream refused the connection (code %d)", code)
			code = chwire.CodeNetworkError
		} else {
			code = chwire.CodeNetworkError
		}
		s.refuse(conn, br, code, msg)
		return
	}
	defer up.Close()
	finish("allow", "")
	_ = raw.SetDeadline(time.Time{})
	start := time.Now()
	in2up, up2in, reason := splice(conn, br, up, upr, time.Duration(s.cfg.Limits.MaxConnectionAge), s.stopping)
	s.log.InfoContext(ctx, "disconnect", "sub", a.sub, "user", a.user, "instance", a.instance, "db", a.db, "temp_user", a.tempUser,
		"protocol", a.protocol, "reason", reason, "duration_ms", time.Since(start).Milliseconds(), "bytes_in", in2up, "bytes_out", up2in)
}

// dialNative logs in upstream with the client's Hello as lease and returns once the server Hello is
// next on the reader. An upstream Exception is returned with its code and never relayed: it names
// the temp user.
func (s *Server) dialNative(ctx context.Context, in *instance, h chwire.Hello, lease *chusers.Lease, db string) (net.Conn, *bufio.Reader, int32, error) {
	host, _, err := net.SplitHostPort(in.cfg.Native)
	if err != nil {
		return nil, nil, 0, err
	}
	tlsConfig, err := in.cfg.TLSConfig(host)
	if err != nil {
		return nil, nil, 0, err
	}
	h.Database, h.User, h.Password = db, lease.User, lease.Password
	wait := 50 * time.Millisecond
	for attempt := 1; ; attempt++ {
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := (&tls.Dialer{Config: tlsConfig}).DialContext(dctx, "tcp", in.cfg.Native)
		cancel()
		if err != nil {
			return nil, nil, 0, err
		}
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		r := bufio.NewReader(c)
		typ := uint64(0)
		if _, err = h.WriteTo(c); err == nil {
			typ, err = chwire.PeekServerPacket(r)
		}
		if err != nil {
			c.Close()
			return nil, nil, 0, err
		}
		if typ == chwire.ServerHello {
			_ = c.SetDeadline(time.Time{})
			return c, r, 0, nil
		}
		if typ != chwire.ServerException {
			c.Close()
			return nil, nil, 0, fmt.Errorf("upstream sent packet %d before its Hello", typ)
		}
		ex, err := chwire.ReadException(r, 1<<20)
		c.Close()
		if err != nil {
			return nil, nil, 0, err
		}
		if ex.Code != chwire.CodeAuthenticationFailed || attempt >= upstreamLoginAttempts {
			return nil, nil, ex.Code, fmt.Errorf("upstream login: %w", ex)
		}
		select {
		case <-ctx.Done():
			return nil, nil, 0, ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// refuse sends one Exception, then reads until the client closes, so the packet is not lost to a
// reset from unread input.
func (s *Server) refuse(conn *tls.Conn, br *bufio.Reader, code int32, msg string) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := chwire.WriteException(conn, code, msg); err != nil {
		return
	}
	_ = conn.CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.Copy(io.Discard, io.LimitReader(br, 1<<20))
}

// splice copies bytes both ways until either side closes, maxAge passes or stop closes, and returns
// the bytes copied client to upstream and back, and why it ended. The readers hold what was read
// past the Hello.
func splice(client net.Conn, clientR io.Reader, upstream net.Conn, upstreamR io.Reader, maxAge time.Duration, stop <-chan struct{}) (in, out int64, reason string) {
	done := make(chan string, 2)
	go func() {
		in, _ = io.Copy(upstream, clientR)
		done <- "client closed"
	}()
	go func() {
		out, _ = io.Copy(client, upstreamR)
		done <- "upstream closed"
	}()
	timer := time.NewTimer(maxAge)
	defer timer.Stop()
	pending := 2
	select {
	case reason = <-done:
		pending--
	case <-timer.C:
		reason = "maxConnectionAge"
	case <-stop:
		reason = "shutdown"
	}
	client.Close()
	upstream.Close()
	for ; pending > 0; pending-- {
		<-done
	}
	return in, out, reason
}
