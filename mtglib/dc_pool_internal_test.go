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

	pool := newDCPool(context.Background(), dial, NoopLogger{}, nil,
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

// recorder собирает исходы пула для проверки метрики mtg_dc_pool.
type recorder struct {
	mu      sync.Mutex
	results []string
}

func (r *recorder) observe(_ int, result string) {
	r.mu.Lock()
	r.results = append(r.results, result)
	r.mu.Unlock()
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.results...)
}

func equalResults(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("исходы: получили %v, ожидали %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("исходы: получили %v, ожидали %v", got, want)
		}
	}
}

// Коннект, который DC закрыл, пока он лежал в пуле, клиенту не отдаётся: иначе
// первый write клиента упадёт и Telegram-клиент уйдёт в backoff (02.10.2026 -
// раньше get смотрел только на возраст).
func TestDCPoolGetSkipsDeadConn(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	alive := &fakePoolConn{}
	dead := &fakePoolConn{}
	p.alive = func(c essentials.Conn) bool { return c.(*fakePoolConn) != dead } //nolint: forcetypeassert

	p.ready[2] = []warmConn{
		{conn: alive, addr: testAddr(), created: time.Now()},
		{conn: dead, addr: testAddr(), created: time.Now()},
	}

	conn, _, ok := p.get(2)
	if !ok || conn.(*fakePoolConn) != alive { //nolint: forcetypeassert
		t.Fatal("ожидали живой коннект")
	}

	if !dead.isClosed() {
		t.Fatal("мёртвый коннект должен быть закрыт")
	}

	equalResults(t, rec.all(), []string{DCPoolResultDead, DCPoolResultHit})
}

// Все коннекты мёртвые - промах, клиент дилит холодно.
func TestDCPoolGetAllDeadIsMiss(t *testing.T) {
	p := newTestPool(nil, 2, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe
	p.alive = func(essentials.Conn) bool { return false }

	p.ready[2] = []warmConn{
		{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now()},
		{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now()},
	}

	if _, _, ok := p.get(2); ok {
		t.Fatal("ожидали промах")
	}

	equalResults(t, rec.all(), []string{DCPoolResultDead, DCPoolResultDead, DCPoolResultMiss})
}

// Исходы filler'а и выдачи: прогрев, вытеснение по возрасту, ошибка прогрева,
// протухший при выдаче, промах.
func TestDCPoolReportsResults(t *testing.T) {
	fail := false
	dial := func(_ context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
		if fail {
			return nil, dc.Addr{}, 0, errors.New("dc down")
		}

		return &fakePoolConn{}, testAddr(), dcID, nil
	}

	p := newTestPool(dial, 1, 20*time.Second)
	rec := &recorder{}
	p.observe = rec.observe

	p.topUp(context.Background(), 2) // dial_ok

	p.mu.Lock()
	p.ready[2][0].created = time.Now().Add(-time.Hour)
	p.mu.Unlock()

	fail = true
	p.topUp(context.Background(), 2) // expired + dial_fail

	p.ready[2] = []warmConn{{conn: &fakePoolConn{}, addr: testAddr(), created: time.Now().Add(-time.Hour)}}
	p.get(2) // stale + miss

	equalResults(t, rec.all(), []string{
		DCPoolResultDialOK,
		DCPoolResultExpired, DCPoolResultDialFail,
		DCPoolResultStale, DCPoolResultMiss,
	})
}

// Настоящая проба на net.Pipe: живой коннект молчит - живой; закрытый на той
// стороне - мёртвый; DC прислал данные - тоже мёртвый (на неначатом потоке так
// быть не должно). После пробы дедлайн снят: коннект дальше читается как обычно.
func TestProbeAlive(t *testing.T) {
	t.Run("молчит - живой, дедлайн снят", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()  //nolint: errcheck
		defer remote.Close() //nolint: errcheck

		conn := essentials.WrapNetConn(local)
		if !probeAlive(conn) {
			t.Fatal("молчащий коннект должен считаться живым")
		}

		go remote.Write([]byte{42}) //nolint: errcheck

		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil || buf[0] != 42 {
			t.Fatalf("после пробы чтение должно работать: %v %v", buf, err)
		}
	})

	t.Run("закрыт DC - мёртвый", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close() //nolint: errcheck

		remote.Close() //nolint: errcheck

		if probeAlive(essentials.WrapNetConn(local)) {
			t.Fatal("закрытый коннект должен считаться мёртвым")
		}
	})

	t.Run("DC прислал данные - мёртвый", func(t *testing.T) {
		local, remote := net.Pipe()
		defer local.Close()  //nolint: errcheck
		defer remote.Close() //nolint: errcheck

		go remote.Write([]byte{1}) //nolint: errcheck

		time.Sleep(10 * time.Millisecond)

		if probeAlive(essentials.WrapNetConn(local)) {
			t.Fatal("коннект с неожиданными данными должен считаться мёртвым")
		}
	})
}

// Media DCs (negative ids) and the CDN DC 203 are pooled like regular ones:
// on our nodes most traffic goes there, and before they always missed.
func TestDCPoolWarmsMediaAndCDNDCs(t *testing.T) {
	for _, dcID := range []int{-2, 203} {
		dial := func(_ context.Context, id int) (essentials.Conn, dc.Addr, int, error) {
			return &fakePoolConn{}, testAddr(), id, nil
		}

		p := newTestPool(dial, 1, 20*time.Second)
		p.topUp(context.Background(), dcID)

		if _, _, ok := p.get(dcID); !ok {
			t.Fatalf("dc %d: expected a warm connection", dcID)
		}
	}
}

func TestDefaultDCPoolDCsFollowTraffic(t *testing.T) {
	want := map[int]bool{2: true, -2: true, 203: true}
	for _, id := range DefaultDCPoolDCs {
		delete(want, id)
	}

	if len(want) != 0 {
		t.Fatalf("default warm DCs must include media DC 2 and CDN DC 203, missing %v", want)
	}

	if (ProxyOpts{}).getDCPoolDCs()[0] != DefaultDCPoolDCs[0] {
		t.Fatal("empty DCPoolDCs must fall back to the default")
	}

	if got := (ProxyOpts{DCPoolDCs: []int{5}}).getDCPoolDCs(); len(got) != 1 || got[0] != 5 {
		t.Fatalf("explicit DCPoolDCs must be used, got %v", got)
	}
}
