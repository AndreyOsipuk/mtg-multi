package web

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// pipe - буфер между HTTP-обработчиком и логическим потоком.
//
// Зачем свой, а не net.Pipe: net.Pipe синхронный, и запись блокировалась бы до
// чтения. Тело HTTP-запроса разбирается в обработчике, который обязан быстро
// ответить клиенту, - он не может ждать, пока MTProto-сторона прочитает байты.
// Поэтому буферизуем, но с потолком: размер выбирает не клиент.
//
// Дедлайны обязательны: mtg ставит SetDeadline на время рукопожатия и
// рассчитывает, что Read с него сорвётся. Без этого зависший клиент держал бы
// горутину и слот в статистике бесконечно.
type pipe struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	notify   chan struct{}
	capacity int

	readClosed  bool
	writeClosed bool
	// err - причина, по которой поток закончился (nil = штатное закрытие).
	err error

	readDeadline  time.Time
	writeDeadline time.Time
}

// ErrPipeFull - буфер переполнен: клиент шлёт быстрее, чем поток разбирает.
var ErrPipeFull = errors.New("web: буфер потока переполнен")

func newPipe(capacity int) *pipe {
	return &pipe{
		notify:   make(chan struct{}, 1),
		capacity: capacity,
	}
}

// wake будит того, кто ждёт данных или места. Неблокирующе: сигнал-«есть
// изменения», а не очередь событий.
func (p *pipe) wake() {
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

// write кладёт данные в буфер. Возвращает ErrPipeFull, если места нет:
// молча выбрасывать байты MTProto нельзя - это порвало бы поток незаметно.
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

// Read отдаёт накопленные байты, ожидая их появления до дедлайна.
func (p *pipe) Read(dst []byte) (int, error) {
	for {
		p.mu.Lock()

		if p.buf.Len() > 0 {
			n, _ := p.buf.Read(dst)
			p.mu.Unlock()
			p.wake() // освободилось место

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

// wait ждёт сигнала или наступления дедлайна.
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

// buffered сообщает, сколько байт ждёт чтения.
func (p *pipe) buffered() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.buf.Len()
}

// closeWrite закрывает сторону записи: читатель добёрет остаток и получит EOF
// (или указанную причину).
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

// closeRead закрывает сторону чтения и выбрасывает непрочитанное.
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
