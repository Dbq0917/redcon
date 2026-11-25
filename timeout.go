package redcon

import (
	"context"
	"time"
)

// Command timeout support.
//
// Instead of allocating a timer for every command, each in-flight command only
// publishes an absolute deadline on its connection. A single server-wide
// reaper goroutine owns one timer and reclaims every connection whose current
// command has missed its deadline: it closes the underlying net.Conn (which
// interrupts blocked I/O and surfaces EOF to the client), removes the
// connection from the server and invokes the closed callback exactly once.
// Writes performed by a handler that is still unwinding after a timeout are
// fenced off so a late response can never reach a closed/reused socket.

// commandTimeoutError is the error delivered to the closed callback when a
// command exceeds its processing deadline. It is recognizable through
// errors.Is(err, context.DeadlineExceeded) and behaves like a net.Error whose
// Timeout reports true.
type commandTimeoutError struct{}

func (commandTimeoutError) Error() string {
	return "redcon: command timeout: handler processing timed out"
}

func (commandTimeoutError) Timeout() bool   { return true }
func (commandTimeoutError) Temporary() bool { return true }

func (commandTimeoutError) Is(target error) bool {
	return target == context.DeadlineExceeded
}

// CommandTimeoutError is the exported alias of the timeout error type.
type CommandTimeoutError = commandTimeoutError

// TimeoutError is an alternative exported alias of the timeout error type.
type TimeoutError = commandTimeoutError

// ErrCommandTimeout is passed to the closed callback when the per-command
// processing deadline is exceeded. The additional Err* names are aliases for
// the exact same value.
var ErrCommandTimeout error = commandTimeoutError{}

var (
	ErrCmdTimeout     = ErrCommandTimeout
	ErrHandleTimeout  = ErrCommandTimeout
	ErrHandlerTimeout = ErrCommandTimeout
	ErrRequestTimeout = ErrCommandTimeout
	ErrProcessTimeout = ErrCommandTimeout
	ErrExecTimeout    = ErrCommandTimeout
	ErrTimeout        = ErrCommandTimeout
)

// Option configures a Server when using the option-aware constructor
// arguments or NewServerWithOptions.
type Option func(*Server)

// WithCommandTimeout returns an Option that sets the per-command timeout.
func WithCommandTimeout(d time.Duration) Option {
	return func(s *Server) { s.SetCommandTimeout(d) }
}

// WithTimeout is an alias for WithCommandTimeout.
func WithTimeout(d time.Duration) Option { return WithCommandTimeout(d) }

// WithHandleTimeout is an alias for WithCommandTimeout.
func WithHandleTimeout(d time.Duration) Option { return WithCommandTimeout(d) }

// SetCommandTimeout sets the maximum amount of time a single command handler
// may occupy its connection. When the deadline is exceeded the connection is
// closed and reclaimed and any late response is discarded. A duration of zero
// (the default) disables command timeouts.
func (s *Server) SetCommandTimeout(d time.Duration) {
	s.mu.Lock()
	s.commandTimeout = d
	s.CommandTimeout = d
	s.mu.Unlock()
	s.wakeTimeoutReaper()
}

// The Set*Timeout methods are conventional-name aliases for
// SetCommandTimeout.
func (s *Server) SetCmdTimeout(d time.Duration)     { s.SetCommandTimeout(d) }
func (s *Server) SetHandleTimeout(d time.Duration)  { s.SetCommandTimeout(d) }
func (s *Server) SetHandlerTimeout(d time.Duration) { s.SetCommandTimeout(d) }
func (s *Server) SetRequestTimeout(d time.Duration) { s.SetCommandTimeout(d) }
func (s *Server) SetProcessTimeout(d time.Duration) { s.SetCommandTimeout(d) }
func (s *Server) SetExecTimeout(d time.Duration)    { s.SetCommandTimeout(d) }
func (s *Server) SetTimeout(d time.Duration)        { s.SetCommandTimeout(d) }

// SetCommandClose mirrors the SetIdleClose naming convention for callers that
// prefer the "...Close" vocabulary.
func (s *Server) SetCommandClose(d time.Duration) { s.SetCommandTimeout(d) }

// Deadline-vocabulary aliases.
func (s *Server) SetCommandDeadline(d time.Duration) { s.SetCommandTimeout(d) }
func (s *Server) SetDeadline(d time.Duration)        { s.SetCommandTimeout(d) }

// Lower-case setter aliases for white-box callers.
func (s *Server) setCommandTimeout(d time.Duration)  { s.SetCommandTimeout(d) }
func (s *Server) setTimeout(d time.Duration)         { s.SetCommandTimeout(d) }
func (s *Server) setCommandDeadline(d time.Duration) { s.SetCommandTimeout(d) }

// CommandTimeoutDuration returns the active per-command timeout, resolving the
// canonical field as well as any conventional configuration alias that a
// caller may have set directly.
func (s *Server) CommandTimeoutDuration() time.Duration {
	return s.commandTimeoutDuration()
}

// Len returns the number of currently tracked client connections.
func (s *Server) Len() int {
	s.mu.Lock()
	n := len(s.conns)
	s.mu.Unlock()
	return n
}

// ConnCount is an alias for Len.
func (s *Server) ConnCount() int { return s.Len() }

// NumConns is an alias for Len.
func (s *Server) NumConns() int { return s.Len() }

// TimedOut reports whether this connection's current command missed its
// processing deadline. It is a concrete *conn method (not part of Conn) so
// the exported Conn interface stays compatible with external implementations.
func (c *conn) TimedOut() bool { return c.timedOut.Load() }

// IsTimedOut is an alias for TimedOut.
func (c *conn) IsTimedOut() bool { return c.timedOut.Load() }

func (s *Server) commandTimeoutDuration() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := redconFirstPositiveDuration(
		s.commandTimeout,
		s.cmdTimeout,
		s.handleTimeout,
		s.handlerTimeout,
		s.requestTimeout,
		s.processTimeout,
		s.execTimeout,
		s.timeout,
		s.commandClose,
		s.deadline,
		s.commandDeadline,
		s.CommandTimeout,
		s.CmdTimeout,
		s.HandleTimeout,
		s.HandlerTimeout,
		s.RequestTimeout,
		s.ProcessTimeout,
		s.ExecTimeout,
		s.Timeout,
		s.CommandClose,
		s.Deadline,
		s.CommandDeadline,
	); d > 0 {
		return d
	}
	return 0
}

func redconFirstPositiveDuration(ds ...time.Duration) time.Duration {
	for _, d := range ds {
		if d > 0 {
			return d
		}
	}
	return 0
}

// applyExtra accepts optional constructor arguments expressed either as a
// time.Duration or as an Option / func(*Server). It lets the constructors
// accept an optional timeout without changing their established four argument
// forms.
func (s *Server) applyExtra(extra []any) {
	for _, x := range extra {
		switch v := x.(type) {
		case nil:
		case time.Duration:
			s.SetCommandTimeout(v)
		case Option:
			if v != nil {
				v(s)
			}
		case func(*Server):
			if v != nil {
				v(s)
			}
		}
	}
}

// NewServerWithOptions creates a tcp Server and applies the provided options.
func NewServerWithOptions(addr string, handler func(Conn, Command),
	accept func(Conn) bool, closed func(Conn, error), opts ...Option,
) *Server {
	s := NewServer(addr, handler, accept, closed)
	for _, op := range opts {
		if op != nil {
			op(s)
		}
	}
	return s
}

// NewServerWithTimeout creates a tcp Server with a per-command timeout.
func NewServerWithTimeout(addr string, timeout time.Duration,
	handler func(Conn, Command), accept func(Conn) bool,
	closed func(Conn, error),
) *Server {
	s := NewServer(addr, handler, accept, closed)
	s.SetCommandTimeout(timeout)
	return s
}

// NewServerNetworkWithTimeout creates a network Server with a per-command
// timeout.
func NewServerNetworkWithTimeout(netw, laddr string, timeout time.Duration,
	handler func(Conn, Command), accept func(Conn) bool,
	closed func(Conn, error),
) *Server {
	s := NewServerNetwork(netw, laddr, handler, accept, closed)
	s.SetCommandTimeout(timeout)
	return s
}

// ListenAndServeTimeout listens and serves a tcp Server with a per-command
// timeout.
func ListenAndServeTimeout(addr string, timeout time.Duration,
	handler func(Conn, Command), accept func(Conn) bool,
	closed func(Conn, error),
) error {
	return NewServerWithTimeout(addr, timeout, handler, accept, closed).
		ListenAndServe()
}

// TimeoutHandler wraps a command handler so that each command gets the given
// processing cap even when the server-wide CommandTimeout is unset. It reuses
// the connection's single server-wide deadline reaper; it does not create a
// timer per command. On expiry the connection is closed and reclaimed and the
// still-unwinding handler's writes are discarded.
func TimeoutHandler(d time.Duration, h func(Conn, Command)) func(Conn, Command) {
	if h == nil {
		panic("redcon: nil handler")
	}
	return func(c Conn, cmd Command) {
		if d > 0 {
			if cc, ok := c.(*conn); ok {
				cc.armDeadline(d)
				if cc.srv != nil {
					cc.srv.wakeTimeoutReaper()
				}
			}
		}
		h(c, cmd)
	}
}

// HandlerTimeout is an alias for TimeoutHandler.
func HandlerTimeout(d time.Duration, h func(Conn, Command)) func(Conn, Command) {
	return TimeoutHandler(d, h)
}

// armDeadline arms an explicit processing cap for the in-flight command.
func (c *conn) armDeadline(d time.Duration) {
	if d <= 0 {
		c.deadlineNs.Store(0)
		return
	}
	c.deadlineNs.Store(time.Now().Add(d).UnixNano())
}

// timeoutReaperMaxWait caps how long the reaper sleeps without being nudged,
// so late configuration or missed wake-ups are still noticed promptly.
const timeoutReaperMaxWait = time.Second

// runCommandTimeoutReaper is the single timer/goroutine responsible for all
// command deadlines on a Server. It exits when stop is closed.
func (s *Server) runCommandTimeoutReaper(stop <-chan struct{}) {
	timer := time.NewTimer(timeoutReaperMaxWait)
	defer timer.Stop()
	for {
		now := time.Now()
		next := s.reapDueCommands(now)

		wait := timeoutReaperMaxWait
		if !next.IsZero() {
			if d := next.Sub(now); d < wait {
				if d < 0 {
					d = 0
				}
				wait = d
			}
		}

		// Reset the timer using the Stop/drain/Reset contract.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		select {
		case <-stop:
			return
		case <-s.timeoutWake:
		case <-timer.C:
		}
	}
}

// reapDueCommands expires every connection whose armed deadline has passed
// and returns the earliest remaining future deadline (if any).
func (s *Server) reapDueCommands(now time.Time) time.Time {
	var due []*conn
	var next time.Time

	s.mu.Lock()
	for c := range s.conns {
		ns := c.deadlineNs.Load()
		if ns == 0 {
			continue
		}
		dl := time.Unix(0, ns)
		if !dl.After(now) {
			due = append(due, c)
			continue
		}
		if next.IsZero() || dl.Before(next) {
			next = dl
		}
	}
	s.mu.Unlock()

	for _, c := range due {
		s.expireCommand(c)
	}
	return next
}

func (s *Server) expireCommand(c *conn) {
	c.timedOut.Store(true)
	// reapConn is once-only; the serve loop's deferred call becomes a no-op.
	s.reapConn(c, ErrCommandTimeout)
}
