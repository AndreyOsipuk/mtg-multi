package mtglib

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/dc"
)

// fakePoolConn — минимальный essentials.Conn для тестов пула: пулу нужны только
// Close/CloseRead/CloseWrite, Read/Write он не дёргает (встроенный nil net.Conn
// не вызывается).
type fakePoolConn struct {
	net.Conn

	mu     sync.Mutex
	closed bool
}

func (f *fakePoolConn) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()

	return nil
}

func (f *fakePoolConn) CloseRead() error  { return nil }
func (f *fakePoolConn) CloseWrite() error { return nil }

func (f *fakePoolConn) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.closed
}

func testAddr() dc.Addr {
	return dc.Addr{Network: "tcp", Address: "149.154.167.50:443"}
}

// newTestPool собирает dcPool БЕЗ filler-горутин (для детерминированных
// unit-тестов get/topUp).
func newTestPool(dial dcDialFunc, perDC int, maxAge time.Duration) *dcPool {
	return &dcPool{
		dial:     dial,
		logger:   NoopLogger{},
		dcs:      []int{2},
		perDC:    perDC,
		maxAge:   maxAge,
		interval: time.Hour,
		ready:    map[int][]warmConn{},
	}
}

func TestDCPoolTopUpAndGet(t *testing.T) {
	var dials int32

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		atomic.AddInt32(&dials, 1)

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 2, 20*time.Second)
	p.topUp(context.Background(), 2)

	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Fatalf("ожидали 2 прогрева, получили %d", got)
	}

	// Два get подряд отдают тёплые коннекты, третий — промах (пул пуст).
	if _, _, ok := p.get(2); !ok {
		t.Fatal("get #1: ожидали тёплый коннект")
	}
	if _, _, ok := p.get(2); !ok {
		t.Fatal("get #2: ожидали тёплый коннект")
	}
	if _, _, ok := p.get(2); ok {
		t.Fatal("get #3: ожидали промах (пул пуст)")
	}
}

func TestDCPoolGetEvictsAged(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)

	fresh := &fakePoolConn{}
	aged := &fakePoolConn{}

	// aged старше maxAge → get его закрывает и пропускает, отдаёт свежий.
	p.ready[2] = []warmConn{
		{conn: fresh, addr: testAddr(), created: time.Now()},
		{conn: aged, addr: testAddr(), created: time.Now().Add(-time.Hour)},
	}

	conn, _, ok := p.get(2)
	if !ok {
		t.Fatal("ожидали свежий коннект")
	}
	if !aged.isClosed() {
		t.Fatal("протухший коннект должен быть закрыт")
	}
	if conn.(*fakePoolConn) != fresh {
		t.Fatal("ожидали именно свежий коннект")
	}
}

func TestDCPoolGetEmptyIsMiss(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)

	if _, _, ok := p.get(2); ok {
		t.Fatal("пустой пул должен давать промах (фолбэк на холодный dial)")
	}
}

func TestDCPoolTopUpDropsDCMismatch(t *testing.T) {
	fake := &fakePoolConn{}

	// dial вернул коннект к ДРУГОМУ DC (fallback) — в пул под запрошенный DC
	// класть нельзя, коннект надо закрыть.
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return fake, testAddr(), 999, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	p.topUp(context.Background(), 2)

	if len(p.ready[2]) != 0 {
		t.Fatalf("коннект к чужому DC не должен попасть в пул, в пуле %d", len(p.ready[2]))
	}
	if !fake.isClosed() {
		t.Fatal("коннект к чужому DC должен быть закрыт")
	}
}

func TestDCPoolTopUpDialFailureNoStore(t *testing.T) {
	dial := func(_ context.Context, _ int) (essentials.Conn, dc.Addr, int, error) {
		return nil, dc.Addr{}, 0, errors.New("route down")
	}

	p := newTestPool(dial, 2, 20*time.Second)
	p.topUp(context.Background(), 2)

	if len(p.ready[2]) != 0 {
		t.Fatalf("при фейле dial пул должен остаться пустым, в пуле %d", len(p.ready[2]))
	}
}

func TestDCPoolShutdownClosesConns(t *testing.T) {
	var conns []*fakePoolConn
	var mu sync.Mutex

	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		c := &fakePoolConn{}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()

		return c, testAddr(), dcID, nil
	}

	pool := newDCPool(context.Background(), dial, NoopLogger{},
		[]int{2}, 2, 20*time.Second, 5*time.Millisecond)

	// Ждём, пока filler прогреет пул до полного (perDC=2). НЕ забираем через
	// get() — забранный коннект переходит во владение вызывающего, и Shutdown
	// его не закрывает (это корректно), тест бы ложно падал.
	poolLen := func() int {
		pool.mu.Lock()
		defer pool.mu.Unlock()

		return len(pool.ready[2])
	}

	deadline := time.Now().Add(2 * time.Second)
	for poolLen() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("filler не прогрел пул за 2с")
		}
		time.Sleep(5 * time.Millisecond)
	}

	pool.Shutdown()

	mu.Lock()
	defer mu.Unlock()

	for i, c := range conns {
		if !c.isClosed() {
			t.Fatalf("коннект #%d не закрыт после Shutdown", i)
		}
	}
}
