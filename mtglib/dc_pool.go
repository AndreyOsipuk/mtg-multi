package mtglib

import (
	"context"
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
func newDCPool(ctx context.Context, dial dcDialFunc, logger Logger,
	dcs []int, perDC int, maxAge, interval time.Duration,
) *dcPool {
	ctx, cancel := context.WithCancel(ctx)

	p := &dcPool{
		dial:     dial,
		logger:   logger,
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

// get отдаёт тёплый коннект к dcID, если есть свежий. Протухшие по пути закрывает
// и пропускает (клиенту стухший коннект не отдаём — иначе первый write упадёт и
// клиент словит backoff). ok=false → в пуле пусто/всё протухло, вызывающий дилит
// холодно.
func (p *dcPool) get(dcID int) (essentials.Conn, dc.Addr, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conns := p.ready[dcID]
	for len(conns) > 0 {
		wc := conns[len(conns)-1]
		conns = conns[:len(conns)-1]

		if time.Since(wc.created) >= p.maxAge {
			wc.conn.Close() //nolint: errcheck

			continue
		}

		p.ready[dcID] = conns

		return wc.conn, wc.addr, true
	}

	p.ready[dcID] = conns

	return nil, dc.Addr{}, false
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

	for _, wc := range p.ready[dcID] {
		if time.Since(wc.created) >= p.maxAge {
			wc.conn.Close() //nolint: errcheck

			continue
		}

		live = append(live, wc)
	}

	p.ready[dcID] = live
	need := p.perDC - len(live)

	p.mu.Unlock()

	for i := 0; i < need; i++ {
		if ctx.Err() != nil {
			return
		}

		conn, addr, actualDC, err := p.dial(ctx, dcID)
		if err != nil {
			// DC ещё не доступен (config не загружен) или маршрут лёг — попробуем
			// на следующем тике, клиентов это не блокирует (фолбэк на холодный dial).
			p.logger.InfoError("dc pool warm dial failed", err)

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
