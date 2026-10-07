package mtglib

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dolonet/mtg-multi/essentials"
	"github.com/dolonet/mtg-multi/mtglib/internal/dc"
	"github.com/dolonet/mtg-multi/mtglib/internal/doppel"
	"github.com/dolonet/mtg-multi/mtglib/internal/relay"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls"
	"github.com/dolonet/mtg-multi/mtglib/internal/tls/fake"
	"github.com/dolonet/mtg-multi/mtglib/obfuscation"
	"github.com/panjf2000/ants/v2"
)

// Proxy is an MTPROTO proxy structure.
type Proxy struct {
	ctx             context.Context
	ctxCancel       context.CancelFunc
	streamWaitGroup sync.WaitGroup

	allowFallbackOnUnknownDC    bool
	tolerateTimeSkewness        time.Duration
	idleTimeout                 time.Duration
	handshakeTimeout            time.Duration
	domainFrontingPort          int
	domainFrontingHost          string
	domainFrontingProxyProtocol bool
	workerPool                  *ants.PoolWithFunc
	telegram                    *dc.Telegram
	configUpdater               *dc.PublicConfigUpdater
	doppelGanger                *doppel.Ganger
	dcPool                      *dcPool

	ddShapeEnabled    bool
	ddShapeDelayMinMs int
	ddShapeDelayMaxMs int
	ddShapeFragBytes  int

	// serverHelloMSS > 0 - дробить ServerHello FakeTLS (см. server_hello_mss.go).
	serverHelloMSS int

	stats           *ProxyStats
	secretSet       atomic.Pointer[secretSet]
	sessions        *sessionRegistry
	network         Network
	antiReplayCache AntiReplayCache
	blocklist       IPBlocklist
	allowlist       IPBlocklist
	eventStream     EventStream
	logger          Logger
}

// DomainFrontingAddress returns a host:port pair for a fronting domain.
// If a fronting host (literal IP or hostname) is configured, it is used
// instead of the secret's hostname. When secrets use different hostnames,
// pass the matched secret's host to front the correct domain.
func (p *Proxy) DomainFrontingAddress() string {
	return p.domainFrontingAddressForHost(p.secretSet.Load().secrets[0].Host)
}

func (p *Proxy) domainFrontingAddressForHost(host string) string {
	if p.domainFrontingHost != "" {
		host = p.domainFrontingHost
	}

	return net.JoinHostPort(host, strconv.Itoa(p.domainFrontingPort))
}

// ServeConn serves a connection. We do not check IP blocklist and concurrency
// limit here.
func (p *Proxy) ServeConn(conn essentials.Conn) {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	ctx := newStreamContext(p.ctx, p.logger, conn)
	defer ctx.Close()

	if err := ctx.clientConn.SetDeadline(time.Now().Add(p.handshakeTimeout)); err != nil {
		ctx.logger.WarningError("cannot set handshake timeout", err)
		return
	}

	stop := context.AfterFunc(ctx, func() {
		ctx.closeFromOutside()
	})
	defer stop()

	p.eventStream.Send(ctx, NewEventStart(ctx.streamID, ctx.ClientIP()))
	ctx.logger.Info("Stream has been started")

	defer func() {
		p.eventStream.Send(ctx, NewEventFinish(ctx.streamID))
		ctx.logger.Info("Stream has been finished")
	}()

	if !p.doFakeTLSHandshake(ctx) {
		return
	}

	if !p.stats.CanConnect(ctx.secretName) {
		ctx.logger.Info("connection throttled")
		p.eventStream.Send(ctx, NewEventThrottled(ctx.streamID, ctx.secretName))

		return
	}

	if !p.trackSession(ctx) {
		ctx.logger.Info("secret was removed or changed during handshake")
		return
	}
	defer p.sessions.remove(ctx)

	p.stats.UpdateLastSeen(ctx.secretName)

	clientIP := ctx.ClientIP().String()
	ctx.userStats.addIP(clientIP)

	defer ctx.userStats.connections.Add(-1)
	defer ctx.userStats.removeIP(clientIP)

	// FakeTLS-специфика: doppelganger-обёртка (калибровка TLS-шума) + отдельное
	// obfuscated2-рукопожатие поверх распакованного TLS. Для secured (dd) это уже
	// сделано в doSecuredHandshake напрямую — пропускаем.
	if !ctx.secured {
		clientConn, err := p.doppelGanger.NewConn(ctx.clientConn)
		if err != nil {
			ctx.logger.InfoError("cannot wrap into doppelganger connection", err)
			return
		}
		defer clientConn.Stop()

		ctx.clientConn = clientConn

		if err := p.doObfuscatedHandshake(ctx); err != nil {
			ctx.logger.InfoError("obfuscated handshake is failed", err)
			return
		}
	}

	if err := ctx.clientConn.SetDeadline(time.Time{}); err != nil {
		ctx.logger.WarningError("cannot set deadline", err)
		return
	}

	if err := p.doTelegramCall(ctx); err != nil {
		ctx.logger.WarningError("cannot dial to telegram", err)
		return
	}

	// Shape only the first secured server response. FakeTLS connections already
	// have a TLS wrapper and keep their existing behavior.
	if ctx.secured && p.ddShapeEnabled {
		ctx.clientConn = newShapedClientConn(
			ctx.clientConn,
			p.ddShapeDelayMinMs,
			p.ddShapeDelayMaxMs,
			p.ddShapeFragBytes,
		)
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("relay"),
		connIdleTimeout{Conn: ctx.telegramConn, tracker: tracker},
		newCountingConn(connIdleTimeout{Conn: ctx.clientConn, tracker: tracker}, p.stats, ctx.secretName),
	)
}

// ServeStream runs a stream that did not come from the proxy listener (a
// WEB-mode logical stream) through the same admission as a regular
// connection: IP allowlist/blocklist and the worker pool with its concurrency
// limit. Without it WEB streams bypassed both.
func (p *Proxy) ServeStream(conn essentials.Conn) {
	p.dispatch(conn)
}

// dispatch applies IP allowlist/blocklist and hands the connection to the
// worker pool. It returns false only when the pool is closed.
func (p *Proxy) dispatch(conn net.Conn) bool {
	ipAddr := remoteIP(conn)
	logger := p.logger.BindStr("ip", ipAddr.String())

	if !p.allowlist.Contains(ipAddr) {
		conn.Close() //nolint: errcheck
		logger.Info("ip was rejected by allowlist")
		p.eventStream.Send(p.ctx, NewEventIPAllowlisted(ipAddr))

		return true
	}

	if p.blocklist.Contains(ipAddr) {
		conn.Close() //nolint: errcheck
		logger.Info("ip was blacklisted")
		p.eventStream.Send(p.ctx, NewEventIPBlocklisted(ipAddr))

		return true
	}

	err := p.workerPool.Invoke(conn)

	switch {
	case err == nil:
	case errors.Is(err, ants.ErrPoolClosed):
		conn.Close() //nolint: errcheck

		return false
	case errors.Is(err, ants.ErrPoolOverload):
		conn.Close() //nolint: errcheck
		logger.Info("connection was concurrency limited")
		p.eventStream.Send(p.ctx, NewEventConcurrencyLimited())
	}

	return true
}

func remoteIP(conn net.Conn) net.IP {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP
	}

	return net.IPv4zero
}

// Serve starts a proxy on a given listener.
func (p *Proxy) Serve(listener net.Listener) error {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	for {
		conn, err := acceptWithRetry(p.ctx, listener, p.logger)
		if err != nil {
			select {
			case <-p.ctx.Done():
				return nil
			default:
				return fmt.Errorf("cannot accept a new connection: %w", err)
			}
		}

		if !p.dispatch(conn) {
			return nil
		}
	}
}

// Shutdown 'gracefully' shutdowns all connections. Please remember that it
// does not close an underlying listener.
func (p *Proxy) Shutdown() {
	p.ctxCancel()
	p.streamWaitGroup.Wait()
	p.workerPool.Release()
	p.configUpdater.Wait()

	if p.dcPool != nil {
		p.dcPool.Shutdown()
	}

	p.doppelGanger.Shutdown()

	p.allowlist.Shutdown()
	p.blocklist.Shutdown()
}

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.clientConn)
	set := p.secretSet.Load()

	// Classify the transport before invoking a parser. In particular, a TLS
	// ClientHello with an invalid HMAC is an active probe and must be forwarded
	// byte-for-byte to the mask host; parsing its first 64 bytes as a secured
	// handshake would consume and corrupt the fallback stream.
	firstBytes := [5]byte{}
	if _, err := io.ReadFull(rewind, firstBytes[:]); err != nil {
		ctx.logger.InfoError("cannot read initial handshake bytes", err)
		p.doDomainFrontingForHost(ctx, rewind, set.secrets[0].Host)

		return false
	}
	rewind.Rewind()

	if !isFakeTLSHandshake(firstBytes) {
		ok, err := p.doSecuredHandshake(ctx, rewind, set)
		if ok {
			return true
		}

		ctx.logger.InfoError("cannot process secured handshake", err)
		p.doDomainFrontingForHost(ctx, rewind, set.secrets[0].Host)

		return false
	}

	result, err := fake.ReadClientHelloMulti(
		rewind,
		set.keys,
		set.hostnames,
		p.tolerateTimeSkewness,
	)
	if err != nil {
		ctx.logger.InfoError("cannot read client hello", err)

		frontHost := set.secrets[0].Host
		if result != nil && result.MatchedHost != "" {
			frontHost = result.MatchedHost
		}

		p.doDomainFrontingForHost(ctx, rewind, frontHost)

		return false
	}

	if p.antiReplayCache.SeenBefore(result.Hello.SessionID) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	matchedSecret := set.secrets[result.MatchedIndex]
	ctx.matchedSecretKey = matchedSecret.Key[:]
	ctx.secretName = set.names[result.MatchedIndex]
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	gangerNoise := p.doppelGanger.NoiseParams()
	noiseParams := fake.NoiseParams{Mean: gangerNoise.Mean, Jitter: gangerNoise.Jitter}

	// ServerHello - единственный ответ сервера в рукопожатии FakeTLS, по нему
	// ТСПУ и узнаёт mtg. С client-mss он уходит мелкими сегментами прямо в
	// исходный TCP-сокет; у dd ответа на рукопожатие нет вовсе.
	var helloWriter io.Writer = ctx.clientConn
	if p.serverHelloMSS > 0 {
		helloWriter = fragmentedWriter{
			conn:     ctx.rawConn,
			mss:      p.serverHelloMSS,
			deadline: time.Now().Add(p.handshakeTimeout),
		}
	}

	if err := fake.SendServerHello(helloWriter, matchedSecret.Key[:], result.Hello, noiseParams); err != nil {
		p.logger.InfoError("cannot send welcome packet", err)
		return false
	}

	ctx.clientConn = tls.New(ctx.clientConn, true, false)

	return true
}

func isFakeTLSHandshake(firstBytes [5]byte) bool {
	return firstBytes[0] == tls.TypeHandshake &&
		firstBytes[1] == 3 &&
		firstBytes[2] == 1
}

// doSecuredHandshake обрабатывает соединение как secured (dd-секрет): obfuscated2
// напрямую, без FakeTLS. Матчинг по 16б-ключу — конфиг остаётся ee, ключ у dd и
// ee один и тот же. true = распознан и настроен; ServeConn дальше пропускает
// FakeTLS-специфику (doppelganger + отдельный doObfuscatedHandshake).
func (p *Proxy) doSecuredHandshake(ctx *streamContext, rewind *connRewind, set *secretSet) (bool, error) {
	rewind.Rewind()

	idx, dcIdx, cn, replayKey, err := obfuscation.ReadHandshakeMulti(rewind, set.keys)
	if err != nil {
		return false, err
	}

	if p.antiReplayCache.SeenBefore(replayKey) {
		p.logger.Warning("replay attack has been detected (secured)!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))

		return false, errors.New("replay attack has been detected")
	}

	rewind.Commit()
	ctx.secured = true
	ctx.dc = dcIdx
	ctx.clientConn = cn
	ctx.matchedSecretKey = set.secrets[idx].Key[:]
	ctx.secretName = set.names[idx]
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName).BindInt("dc", dcIdx)

	return true, nil
}

func (p *Proxy) doObfuscatedHandshake(ctx *streamContext) error {
	// Use the secret key that was matched during the FakeTLS handshake.
	obfs := obfuscation.Obfuscator{
		Secret: ctx.matchedSecretKey,
	}

	dc, conn, err := obfs.ReadHandshake(ctx.clientConn)
	if err != nil {
		return fmt.Errorf("cannot process client handshake: %w", err)
	}

	ctx.dc = dc
	ctx.clientConn = conn
	ctx.logger = ctx.logger.BindInt("dc", dc)

	return nil
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	dcid := ctx.dc

	// Тёплый пул: если есть готовый коннект к нужному DC — берём его, минуя
	// холодный dial+handshake (и Telegram-backoff при флапе маршрута нода→DC).
	if p.dcPool != nil {
		if conn, addr, ok := p.dcPool.get(dcid); ok {
			p.attachTelegramConn(ctx, conn, addr)

			return nil
		}
	}

	conn, foundAddr, actualDC, err := p.dialAndHandshake(ctx, dcid)
	if err != nil {
		return err
	}

	if actualDC != dcid {
		ctx.logger = ctx.logger.BindInt("original_dc", dcid)
		ctx.logger.Warning("unknown DC, fallbacks")
		ctx.dc = actualDC
	}

	p.attachTelegramConn(ctx, conn, foundAddr)

	return nil
}

// dialAndHandshake дилит DC dcID и делает obfuscated2-handshake, возвращая
// obf-обёрнутый коннект (готов релеить), выбранный addr и ФАКТИЧЕСКИЙ dc (может
// отличаться от запрошенного при AllowFallbackOnUnknownDC). НЕ трогает
// streamContext — используется и клиентским путём, и filler'ом тёплого пула
// (dcPool), у которого streamContext нет.
func (p *Proxy) dialAndHandshake(ctx context.Context, dcID int) (essentials.Conn, dc.Addr, int, error) {
	negativeDCID := dcID < 0
	lookupDCID := dcID
	if lookupDCID < 0 {
		lookupDCID = -lookupDCID
	}

	addresses := p.telegram.GetAddresses(lookupDCID)
	if len(addresses) == 0 && p.allowFallbackOnUnknownDC {
		dcID = dc.DefaultDC
		if negativeDCID {
			dcID = -dc.DefaultDC
		}
		addresses = p.telegram.GetAddresses(dc.DefaultDC)
	}

	var (
		conn      essentials.Conn
		err       error
		foundAddr dc.Addr
	)

	for _, addr := range addresses {
		conn, err = p.network.DialContext(ctx, addr.Network, addr.Address)
		if err == nil {
			foundAddr = addr
			break
		}
	}
	if err != nil {
		return nil, dc.Addr{}, 0, fmt.Errorf("no addresses to call: %w", err)
	}
	if conn == nil {
		return nil, dc.Addr{}, 0, fmt.Errorf("no available addresses for DC %d", dcID)
	}

	tgConn, err := foundAddr.Obfuscator.SendHandshake(conn, dcID)
	if err != nil {
		conn.Close() // nolint: errcheck

		return nil, dc.Addr{}, 0, fmt.Errorf("cannot perform server handshake: %w", err)
	}

	return tgConn, foundAddr, dcID, nil
}

// attachTelegramConn вешает готовый (dial+handshake сделаны) коннект к DC на
// streamContext и шлёт событие ConnectedToDC. Общий хвост для холодного dial и
// тёплого пула.
func (p *Proxy) attachTelegramConn(ctx *streamContext, conn essentials.Conn, addr dc.Addr) {
	ctx.telegramConn = connTraffic{
		Conn:     conn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}

	if telegramHost, _, err := net.SplitHostPort(addr.Address); err == nil {
		p.eventStream.Send(
			ctx,
			NewEventConnectedToDC(ctx.streamID,
				net.ParseIP(telegramHost),
				ctx.dc),
		)
	}
}

func (p *Proxy) doDomainFrontingForHost(ctx *streamContext, conn *connRewind, host string) {
	p.eventStream.Send(p.ctx, NewEventDomainFronting(ctx.streamID))
	conn.FinalRewind()

	nativeDialer := p.network.NativeDialer()
	fConn, err := nativeDialer.DialContext(ctx, "tcp", p.domainFrontingAddressForHost(host))
	if err != nil {
		p.logger.WarningError("cannot dial to the fronting domain", err)

		return
	}

	frontConn := essentials.WrapNetConn(fConn)

	if p.domainFrontingProxyProtocol {
		frontConn = newConnProxyProtocol(ctx.clientConn, frontConn)
	}

	frontConn = connTraffic{
		Conn:     frontConn,
		ctx:      ctx,
		streamID: ctx.streamID,
		stream:   p.eventStream,
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("domain-fronting"),
		connIdleTimeout{Conn: frontConn, tracker: tracker},
		connIdleTimeout{Conn: conn, tracker: tracker},
	)
}

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) {
	if err := opts.valid(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	tg, err := dc.New(opts.getPreferIP())
	if err != nil {
		return nil, fmt.Errorf("cannot build telegram dc fetcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := opts.getLogger("proxy")
	updatersLogger := logger.Named("telegram-updaters")

	set := newSecretSet(opts.getSecrets())

	stats := NewProxyStats()
	for _, name := range set.names {
		stats.PreRegister(name)
	}

	if opts.APIBindTo != "" {
		stats.StartServer(ctx, opts.APIBindTo, logger)
	}

	if opts.ThrottleMaxConnections > 0 {
		stats.SetThrottle(int64(opts.ThrottleMaxConnections), opts.getThrottleCheckInterval())
		stats.startThrottleLoop(ctx, logger)
	}

	if opts.DomainFrontingIP != "" {
		logger.Warning("mtglib.ProxyOpts.DomainFrontingIP is deprecated and ignored; use DomainFrontingHost instead")
	}

	proxy := &Proxy{
		ctx:                      ctx,
		ctxCancel:                cancel,
		stats:                    stats,
		sessions:                 newSessionRegistry(),
		network:                  opts.Network,
		antiReplayCache:          opts.AntiReplayCache,
		blocklist:                opts.IPBlocklist,
		allowlist:                opts.IPAllowlist,
		eventStream:              opts.EventStream,
		logger:                   logger,
		domainFrontingPort:       opts.getDomainFrontingPort(),
		domainFrontingHost:       opts.DomainFrontingHost,
		tolerateTimeSkewness:     opts.getTolerateTimeSkewness(),
		idleTimeout:              opts.getIdleTimeout(),
		handshakeTimeout:         opts.getHandshakeTimeout(),
		allowFallbackOnUnknownDC: opts.AllowFallbackOnUnknownDC,
		telegram:                 tg,
		doppelGanger: doppel.NewGanger(
			ctx,
			opts.Network,
			logger.Named("doppelganger"),
			opts.DoppelGangerEach,
			int(opts.DoppelGangerPerRaid),
			opts.DoppelGangerURLs,
			opts.DoppelGangerDRS,
		),
		configUpdater: dc.NewPublicConfigUpdater(
			tg,
			updatersLogger.Named("public-config"),
			opts.Network.MakeHTTPClient(nil),
		),
		domainFrontingProxyProtocol: opts.DomainFrontingProxyProtocol,

		ddShapeEnabled:    opts.DDShapeEnabled,
		ddShapeDelayMinMs: opts.getDDShapeDelayMinMs(),
		ddShapeDelayMaxMs: opts.getDDShapeDelayMaxMs(),
		ddShapeFragBytes:  opts.getDDShapeFragBytes(),
		serverHelloMSS:    opts.ServerHelloMSS,
	}

	proxy.secretSet.Store(set)
	stats.SetSecretsDigest(set.digest())
	proxy.doppelGanger.Run()

	if opts.AutoUpdate {
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv4, "tcp4")
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv6, "tcp6")
	}

	// Тёплый пул коннектов к DC (аналог me-pool telemt). Включён по умолчанию;
	// filler'ы стартуют сразу и фейлят-ретраят, пока AutoUpdate не подтянет
	// адреса DC — клиентов это не блокирует (фолбэк на холодный dial).
	if opts.DCPoolEnabled {
		proxy.dcPool = newDCPool(
			ctx,
			proxy.dialAndHandshake,
			logger.Named("dc-pool"),
			func(dcID int, result string) {
				proxy.eventStream.Send(proxy.ctx, NewEventDCPool(dcID, result))
			},
			opts.getDCPoolDCs(),
			opts.getDCPoolSize(),
			DCPoolConnMaxAge,
			DCPoolRefreshInterval,
		)
	}

	pool, err := ants.NewPoolWithFunc(opts.getConcurrency(),
		func(arg any) {
			proxy.ServeConn(arg.(essentials.Conn)) //nolint: forcetypeassert
		},
		ants.WithLogger(opts.getLogger("ants")),
		ants.WithNonblocking(true))
	if err != nil {
		panic(err)
	}

	proxy.workerPool = pool

	return proxy, nil
}

// trackSession registers an authenticated session and counts it in the stats.
// It fails if the secret the session has authenticated with was removed or
// changed by UpdateSecrets after the handshake had started. Both happen under
// the registry lock, so a concurrent update either sees the session and
// closes it, or the session is rejected; the stats of a removed secret are
// never recreated.
func (p *Proxy) trackSession(ctx *streamContext) bool {
	p.sessions.mu.Lock()
	defer p.sessions.mu.Unlock()

	if !p.secretSet.Load().sameSecret(ctx.secretName, ctx.matchedSecretKey) {
		return false
	}

	p.sessions.add(ctx)
	ctx.userStats = p.stats.getOrCreate(ctx.secretName)
	ctx.userStats.connections.Add(1)

	return true
}

// UpdateSecrets replaces the set of secrets without restarting the proxy.
//
// New handshakes use the new set right away. Live sessions of secrets that
// are kept unchanged continue to work; sessions of removed secrets and of
// secrets whose key or host has changed are closed. Other options (bind
// addresses, domain fronting, defense settings) are not affected.
func (p *Proxy) UpdateSecrets(secrets map[string]Secret) (SecretsUpdate, error) {
	update := SecretsUpdate{}

	if len(secrets) == 0 {
		return update, ErrSecretEmpty
	}

	for name, secret := range secrets {
		if !secret.Valid() {
			return update, fmt.Errorf("invalid secret %q", name)
		}
	}

	next := newSecretSet(secrets)

	for _, name := range next.names {
		p.stats.PreRegister(name)
	}

	toClose := []*streamContext{}
	gone := []string{}

	p.sessions.mu.Lock()

	prev := p.secretSet.Swap(next)
	p.stats.SetSecretsDigest(next.digest())

	for _, name := range prev.names {
		newSecret, ok := next.byName[name]

		switch {
		case !ok:
			update.Removed++
			gone = append(gone, name)
		case newSecret != prev.byName[name]:
			update.Changed++
		default:
			continue
		}

		for ctx := range p.sessions.sessions[name] {
			toClose = append(toClose, ctx)
		}

		delete(p.sessions.sessions, name)
	}

	for _, name := range gone {
		p.stats.Forget(name)
	}

	p.sessions.mu.Unlock()

	for _, name := range next.names {
		if _, ok := prev.byName[name]; !ok {
			update.Added++
		}
	}

	for _, ctx := range toClose {
		ctx.closeFromOutside()
	}

	update.ClosedSessions = len(toClose)

	return update, nil
}
