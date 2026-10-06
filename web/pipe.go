package web

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// pipe is a buffer between the HTTP handler and a logical stream.
//
// Why not net.Pipe: net.Pipe is synchronous, so a write would block until it
// is read. The HTTP request body is parsed in a handler that must answer the
// client quickly; it cannot wait for the MTProto side to read the bytes. So we
// buffer, but with a cap: the client does not get to choose the size.
//
// Deadlines are mandatory: mtg calls SetDeadline for the handshake and expects
// Read to break out when it fires. Without that, a stalled client would hold a
// goroutine and a stats slot forever.
type pipe struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	notify   chan struct{}
	capacity int

	readClosed  bool
	writeClosed bool
	// err is the reason the stream ended (nil means a normal close).
	err error

	readDeadline  time.Time
	writeDeadline time.Time
}

// ErrPipeFull means the buffer overflowed: the client sends faster than the
// stream drains it.
var ErrPipeFull = errors.New("web: stream buffer is full")

func newPipe(capacity int) *pipe {
	return &pipe{
		notify:   make(chan struct{}, 1),
		capacity: capacity,
	}
}

// wake wakes up whoever waits for data or space. It never blocks: it is a
// "something changed" signal, not an event queue.
func (p *pipe) wake() {
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// write puts data into the buffer. It returns ErrPipeFull when there is no
// room: silently dropping MTProto bytes would break the stream unnoticed.
func (p *pipe) write(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.writeClosed || p.readClosed {
		return io.ErrClosedPipe
	}

	if p.buf.Len()+len(data) > p.capacity {
		return ErrPipeFull
	}

	p.buf.Write(data)
	p.wake()

	return nil
}

// Read returns buffered bytes, waiting for them until the deadline.
func (p *pipe) Read(dst []byte) (int, error) {
	for {
		p.mu.Lock()

		if p.buf.Len() > 0 {
			n, _ := p.buf.Read(dst)
			p.mu.Unlock()
			p.wake() // space was freed

			return n, nil
		}

		if p.writeClosed {
			err := p.err
			p.mu.Unlock()

			if err != nil {
				return 0, err
			}

			return 0, io.EOF
		}

		if p.readClosed {
			p.mu.Unlock()

			return 0, io.ErrClosedPipe
		}

		deadline := p.readDeadline
		p.mu.Unlock()

		if err := p.wait(deadline); err != nil {
			return 0, err
		}
	}
}

// wait waits for a signal or the deadline.
func (p *pipe) wait(deadline time.Time) error {
	if deadline.IsZero() {
		<-p.notify

		return nil
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		return os.ErrDeadlineExceeded
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-p.notify:
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

// closeWrite closes the write side: the reader drains the rest and then gets
// EOF (or the given reason).
func (p *pipe) closeWrite(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.writeClosed {
		return
	}

	p.writeClosed = true
	p.err = err
	p.wake()
}

// closeRead closes the read side and discards unread data.
func (p *pipe) closeRead() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.readClosed = true
	p.buf.Reset()
	p.wake()
}

func (p *pipe) setReadDeadline(t time.Time) {
	p.mu.Lock()
	p.readDeadline = t
	p.mu.Unlock()
	p.wake()
}

func (p *pipe) setWriteDeadline(t time.Time) {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	p.wake()
}

func (p *pipe) getWriteDeadline() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.writeDeadline
}
