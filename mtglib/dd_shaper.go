package mtglib

import (
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
)

// shapedClientConn masks the first secured server-to-client response with a
// delay and small writes. Subsequent writes pass through unchanged.
type shapedClientConn struct {
	essentials.Conn

	writeMu        sync.Mutex
	firstWriteDone bool
	delayMinMs     int
	delayMaxMs     int
	fragSize       int
}

func newShapedClientConn(c essentials.Conn, delayMinMs, delayMaxMs, fragSize int) *shapedClientConn {
	return &shapedClientConn{
		Conn:       c,
		delayMinMs: delayMinMs,
		delayMaxMs: delayMaxMs,
		fragSize:   fragSize,
	}
}

func (s *shapedClientConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	if s.firstWriteDone {
		s.writeMu.Unlock()
		return s.Conn.Write(p)
	}

	s.firstWriteDone = true
	defer s.writeMu.Unlock()

	if s.delayMaxMs > 0 {
		delayMs := s.delayMinMs
		if s.delayMaxMs > s.delayMinMs {
			delayMs += rand.Intn(s.delayMaxMs - s.delayMinMs) //nolint:gosec
		}
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	if s.fragSize <= 0 || len(p) <= s.fragSize {
		return s.Conn.Write(p)
	}

	written := 0
	for written < len(p) {
		end := min(written+s.fragSize, len(p))
		n, err := s.Conn.Write(p[written:end])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}

	return written, nil
}
