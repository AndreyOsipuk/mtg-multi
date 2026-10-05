package mtglib

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/dc"
)

// warmConn — тёплый коннект к DC Telegram: уже прошёл TCP-dial + obfuscated2-
// handshake, готов сразу релеить MTProto-кадры клиента. created — момент прогрева
// (для вытеснения протухших).
type warmConn struct {
	conn    essentials.Conn
	addr    dc.Addr
	created time.Time
}

// dcDialFunc дилит DC dcID и делает obfuscated2-handshake, возвращая obf-обёрнутый
// коннект, выбранный addr и ФАКТИЧЕСКИЙ dc (может отличаться от запрошенного при
// AllowFallbackOnUnknownDC). Инъектируется из Proxy (dialAndHandshake); в тестах —
// мок, без сети.
type dcDialFunc func(ctx context.Context, dcID int) (essentials.Conn, dc.Addr, int, error)

// Исходы работы пула для метрики mtg_dc_pool{dc,result}. Без них не видно, помогает
// ли пул вообще: сколько клиентов получили тёплый коннект, сколько ушли в холодный
// dial и почему (02.10.2026).
const (
	DCPoolResultHit      = "hit"       // клиент получил тёплый коннект
	DCPoolResultMiss     = "miss"      // пул пуст - клиент дилит холодно
	DCPoolResultStale    = "stale"     // при выдаче коннект оказался старше maxAge
	DCPoolResultDead     = "dead"      // при выдаче коннект оказался закрыт DC
	DCPoolResultExpired  = "expired"   // фоновое вытеснение по возрасту (норма)
	DCPoolResultDialOK   = "dial_ok"   // filler прогрел коннект
	DCPoolResultDialFail = "dial_fail" // filler не смог прогреть
)

// dcPoolObserver получает исходы работы пула (в проде - в поток событий/метрики).
type dcPoolObserver func(dcID int, result string)

// dcPoolLivenessProbe - сколько ждём при проверке живости. Telegram никогда не шлёт
// первым, поэтому у живого коннекта чтение упирается в таймаут, а у закрытого DC
// сразу отдаёт EOF/RST. 1 мс - цена проверки на каждого клиента.
const dcPoolLivenessProbe = time.Millisecond

// probeAlive проверяет, не закрыл ли DC тёплый коннект, пока тот лежал в пуле.
// Возраст (maxAge) этого не ловит: DC может закрыть коннект в любой момент (рестарт,
// ротация, сброс по сети), и тогда клиент получает мёртвый коннект и Telegram-backoff.
// Живой = чтение упёрлось в таймаут. Любые данные, EOF или сброс - мёртвый: на
// неначатом MTProto-потоке DC не должен присылать ничего. Чтение по таймауту не
// продвигает шифр obfuscated2 (обёртка расшифровывает только прочитанное).
func probeAlive(conn essentials.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(dcPoolLivenessProbe)); err != nil {
		return false
	}

	var buf [1]byte

	_, err := conn.Read(buf[:])

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false
	}

	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// dcPool держит тёплые коннекты к DC Telegram, чтобы клиентский коннект НЕ платил
// за холодный dial+handshake на каждый вход. Аналог me-pool в telemt.
//
// Зачем: mtg-multi по умолчанию дилит DC заново на каждый клиентский коннект
// (proxy.go doTelegramCall). Сам по себе холодный dial — это ~1 RTT (десятки мс),
// но если маршрут нода→DC икнул (ротация адресов DC, флап пиринга, открылся
// circuit-breaker) — весь клиентский коннект падает, а Telegram-клиент за фейл
// наказывает экспоненциальным backoff (секунды→минуты). Тёплый пул отдаёт клиенту
// уже установленный коннект и абсорбирует фейлы фоново — клиент их не видит.
//
// Фоновые filler-горутины (по одной на warmed DC) держат по perDC готовых
// коннектов, вытесняя протухшие (старше maxAge — чтобы DC не успел закрыть
// idle-коннект). Промах пула → клиентский путь фолбэчит на холодный dial (никогда
// не хуже текущего поведения).
type dcPool struct {
	dial     dcDialFunc
	logger   Logger
	observe  dcPoolObserver
	alive    func(essentials.Conn) bool
	dcs      []int
	perDC    int
	maxAge   time.Duration
	interval time.Duration

	mu    sync.Mutex
	ready map[int][]warmConn

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// newDCPool создаёт пул и запускает filler-горутины. ctx — жизненный цикл проксей
// (отменяется в Shutdown). dcs — список DC для прогрева (обычно 1..5).
func newDCPool(ctx context.Context, dial dcDialFunc, logger Logger, observe dcPoolObserver,
	dcs []int, perDC int, maxAge, interval time.Duration,
) *dcPool {
	ctx, cancel := context.WithCancel(ctx)

	p := &dcPool{
		dial:     dial,
		logger:   logger,
		observe:  observe,
		alive:    probeAlive,
		dcs:      dcs,
		perDC:    perDC,
		maxAge:   maxAge,
		interval: interval,
		ready:    make(map[int][]warmConn, len(dcs)),
		cancel:   cancel,
	}

	for _, dcID := range dcs {
		p.wg.Add(1)

		go p.fill(ctx, dcID)
	}

	return p
}

// get отдаёт тёплый коннект к dcID, если есть свежий и живой. Протухшие и
// закрытые DC по пути закрывает и пропускает (клиенту мёртвый коннект не отдаём -
// иначе первый write упадёт и клиент словит backoff). ok=false → в пуле пусто/всё
// негодное, вызывающий дилит холодно. Проба живости идёт без мьютекса: она ждёт
// до dcPoolLivenessProbe, и держать на это время весь пул незачем.
func (p *dcPool) get(dcID int) (essentials.Conn, dc.Addr, bool) {
	for {
		wc, ok := p.pop(dcID)
		if !ok {
			p.report(dcID, DCPoolResultMiss)

			return nil, dc.Addr{}, false
		}

		if time.Since(wc.created) >= p.maxAge {
			wc.conn.Close() //nolint: errcheck
			p.report(dcID, DCPoolResultStale)

			continue
		}

		if p.alive != nil && !p.alive(wc.conn) {
			wc.conn.Close() //nolint: errcheck
			p.report(dcID, DCPoolResultDead)

			continue
		}

		p.report(dcID, DCPoolResultHit)

		return wc.conn, wc.addr, true
	}
}

// pop снимает с пула самый свежий коннект dcID.
func (p *dcPool) pop(dcID int) (warmConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns := p.ready[dcID]
	if len(conns) == 0 {
		return warmConn{}, false
	}

	wc := conns[len(conns)-1]
	p.ready[dcID] = conns[:len(conns)-1]

	return wc, true
}

// report отдаёт исход наблюдателю (метрики), если он задан.
func (p *dcPool) report(dcID int, result string) {
	if p.observe != nil {
		p.observe(dcID, result)
	}
}

// fill — filler-горутина одного DC: пополняет пул до perDC и вытесняет протухшие
// на каждом тике. При фейле dial НЕ долбит в цикле (одна попытка на тик), чтобы не
// устроить handshake-storm на больной DC.
func (p *dcPool) fill(ctx context.Context, dcID int) {
	defer p.wg.Done()

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		p.topUp(ctx, dcID)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// topUp вытесняет протухшие коннекты dcID и дозаливает пул до perDC.
func (p *dcPool) topUp(ctx context.Context, dcID int) {
	p.mu.Lock()

	var live []warmConn

	expired := 0

	for _, wc := range p.ready[dcID] {
		if time.Since(wc.created) >= p.maxAge {
			wc.conn.Close() //nolint: errcheck

			expired++

			continue
		}

		live = append(live, wc)
	}

	p.ready[dcID] = live
	need := p.perDC - len(live)

	p.mu.Unlock()

	for i := 0; i < expired; i++ {
		p.report(dcID, DCPoolResultExpired)
	}

	for i := 0; i < need; i++ {
		if ctx.Err() != nil {
			return
		}

		conn, addr, actualDC, err := p.dial(ctx, dcID)
		if err != nil {
			// DC ещё не доступен (config не загружен) или маршрут лёг — попробуем
			// на следующем тике, клиентов это не блокирует (фолбэк на холодный dial).
			p.logger.InfoError("dc pool warm dial failed", err)
			p.report(dcID, DCPoolResultDialFail)

			return
		}

		// Страховка: при AllowFallbackOnUnknownDC dial мог уйти на другой DC.
		// Для прогреваемых 1..5 такого не бывает (адреса есть), но если случилось —
		// коннект handshake'нут не к тому DC, в пул под dcID его класть нельзя.
		if actualDC != dcID {
			conn.Close() //nolint: errcheck

			return
		}

		p.mu.Lock()
		p.ready[dcID] = append(p.ready[dcID], warmConn{conn: conn, addr: addr, created: time.Now()})
		p.mu.Unlock()

		p.report(dcID, DCPoolResultDialOK)
	}
}

// Shutdown останавливает filler-горутины и закрывает все тёплые коннекты.
func (p *dcPool) Shutdown() {
	p.cancel()
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	for dcID, conns := range p.ready {
		for _, wc := range conns {
			wc.conn.Close() //nolint: errcheck
		}

		p.ready[dcID] = nil
	}
}
