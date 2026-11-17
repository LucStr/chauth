package chconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/LucStr/chauth/internal/chwire"
)

// Exception codes the connector itself sends, named DB::Exception as a server would. Never 516: on
// it the interactive client asks for a password and waits.
const (
	CodeAccessDenied     = 497
	CodeUnknownDatabase  = 81
	CodeNetworkError     = 210
	CodeUnexpectedPacket = 101
)

var codeNames = map[int32]string{
	CodeAccessDenied:     "ACCESS_DENIED",
	CodeUnknownDatabase:  "UNKNOWN_DATABASE",
	CodeNetworkError:     "NETWORK_ERROR",
	CodeUnexpectedPacket: "UNEXPECTED_PACKET_FROM_CLIENT",
}

// ServeNative accepts native ClickHouse connections on ln until ctx ends, then waits for the open ones.
func (c *Connector) ServeNative(ctx context.Context, ln net.Listener, env string) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { c.handleNative(ctx, conn, env) })
	}
}

func (c *Connector) handleNative(ctx context.Context, conn net.Conn, env string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.HandshakeTimeout))
	br := bufio.NewReader(conn)
	hello, err := chwire.ReadHello(br, maxHello)
	if err != nil {
		if errors.Is(err, chwire.ErrNotHello) || errors.Is(err, chwire.ErrTooLarge) {
			c.refuse(conn, CodeUnexpectedPacket, "chauth connect: "+err.Error())
		}
		return
	}
	if chwire.RefusedUser(hello.User) {
		c.log.Info("connection refused", "protocol", "native", "reason", "user marker")
		c.refuse(conn, CodeAccessDenied, "chauth connect: this login method is not accepted; the token is the password")
		return
	}
	e, rest, err := c.route(hello.Database, env)
	if err != nil {
		c.log.Info("connection refused", "protocol", "native", "database", hello.Database, "reason", err)
		c.refuse(conn, CodeUnknownDatabase, "chauth connect: "+err.Error())
		return
	}
	c.log.Info("connection", "protocol", "native", "database", hello.Database+" → "+e.Name+":"+rest)
	_ = conn.SetDeadline(time.Now().Add(tokenTimeout))
	tok, err := e.Tokens.Token(ctx)
	if err != nil {
		c.log.Error("no token", "env", e.Name, "error", err)
		c.refuse(conn, CodeAccessDenied, err.Error())
		return
	}
	up, err := dialNative(ctx, e)
	if err != nil {
		c.log.Error("dial chauth", "server", e.Server, "error", err)
		c.refuse(conn, CodeNetworkError, "chauth connect: cannot reach "+e.Server)
		return
	}
	defer up.Close()
	_ = conn.SetDeadline(time.Time{})
	hello.Database, hello.Password = rest, tok
	if hello.User == "" {
		hello.User = "default"
	}
	if _, err := hello.WriteTo(up); err != nil {
		c.refuse(conn, CodeNetworkError, "chauth connect: "+e.Server+" closed the connection")
		return
	}
	splice(conn, br, up)
}

// refuse sends one Exception, half-closes and drains, so the client reads the message instead of a reset.
func (c *Connector) refuse(conn net.Conn, code int32, msg string) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if chwire.WriteException(conn, code, "DB::Exception", msg) != nil {
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, conn)
}

func dialNative(ctx context.Context, e *Env) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: e.TLS}
	conn, err := d.DialContext(ctx, "tcp", e.Server)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// splice copies the client's remaining bytes (br holds what came with the Hello) to up and up's
// bytes back; the client's EOF is passed on as a half-close, up's ends the connection.
func splice(client net.Conn, br *bufio.Reader, up *tls.Conn) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, br)
		_ = up.CloseWrite()
		close(done)
	}()
	_, _ = io.Copy(client, up)
	client.Close()
	up.Close()
	<-done
}
