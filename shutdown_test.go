package redcon

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func drainTestWait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func drainTestDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	for i := 0; i < 100; i++ {
		conn, err = net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return conn
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

func TestDrainInFlightCommandDeliversResult(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	var closedErr atomic.Value
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServerNetwork(ln.Addr().Network(), ln.Addr().String(),
		func(c Conn, cmd Command) {
			entered <- struct{}{}
			<-release
			c.WriteString("DONE")
		}, nil, func(c Conn, err error) {
			closedErr.Store(err)
		})
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ln) }()

	conn := drainTestDial(t, ln.Addr().String())
	defer conn.Close()
	if _, err := io.WriteString(conn, "SLOW\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- s.Shutdown(ctx) }()
	drainTestWait(t, "server to start draining", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.state == stateDraining
	})
	unblock()

	if err := <-shutdownErr; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("client got an error instead of the command result: %v", err)
	}
	if string(buf[:n]) != "+DONE\r\n" {
		t.Fatalf("got %q, want %q", buf[:n], "+DONE\r\n")
	}
	drainTestWait(t, "closed callback", func() bool {
		return closedErr.Load() != nil
	})
	if got := closedErr.Load().(error); got != ErrServerClosed {
		t.Fatalf("closed callback err = %v, want %v", got, ErrServerClosed)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestDrainTimeoutForceClosesInFlight(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServerNetwork(ln.Addr().Network(), ln.Addr().String(),
		func(c Conn, cmd Command) {
			entered <- struct{}{}
			<-release
		}, nil, nil)
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ln) }()

	conn := drainTestDial(t, ln.Addr().String())
	defer conn.Close()
	io.WriteString(conn, "SLOW\r\n")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want context deadline exceeded", err)
	}
	select {
	case <-s.Done():
		t.Fatal("Done closed before the in-flight command finished")
	default:
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	unblock()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestDrainStopsAcceptingNewConnections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	s := NewServerNetwork(ln.Addr().Network(), addr,
		func(c Conn, cmd Command) { c.WriteString("PONG") }, nil, nil)
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ln) }()

	conn := drainTestDial(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("server accepted a new connection after shutdown")
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}
