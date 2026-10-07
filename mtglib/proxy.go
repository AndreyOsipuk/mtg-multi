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
	"github.com/dolonet/mtg-multi/mtglib/internal/middleproxy"
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

	middleProxy    *middleproxy.Manager
	ourIPv4        net.IP
	ourIPv6        net.IP
	advertisedPort int

	usageStateFile string
	emitTraffic    bool

	// securedDisabled выключает приём secured (dd): всё, что не FakeTLS,
	// уходит на маскировку.
	securedDisabled   bool
	ddShapeEnabled    bool
	ddShapeDelayMinMs int
	ddShapeDelayMaxMs int
	ddShapeFragBytes  int

	// serverHelloMSS > 0 - дробить ServerHello FakeTLS (см. server_hello_mss.go).
	serverHelloMSS int

	stats   *ProxyStats
	secrets atomic.Pointer[secretSet]
	// sessions - аутентифицированные сессии по именам секретов. Регистрация
	// сессии (trackSession) и подмена набора (applySecretConfigLocked) идут под
	// одной блокировкой sessions.mu: рукопожатие, начатое на старом наборе, не
	// проходит после удаления или смены ключа.
	sessions *sessionRegistry
	reloader func() (SecretConfig, error)
	// reloadMu упорядочивает все изменения набора секретов: SIGHUP, POST
	// /reload, PUT/POST/DELETE /secrets, /adtag.
	reloadMu sync.Mutex
	// secretsHook вызывается под reloadMu до подмены набора (WEB-вход). Ошибка
	// отменяет применение целиком.
	secretsHook     func(map[string]Secret) error
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
	return p.domainFrontingAddressForHost(p.secrets.Load().secrets[0].Host)
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
		ctx.logger.Info("secret was removed, changed or denied during handshake")
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
		newCountingConn(connIdleTimeout{Conn: ctx.clientConn, tracker: tracker}, ctx.userStats),
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

	if p.usageStateFile != "" {
		if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
			p.logger.WarningError("cannot flush usage state on shutdown", err)
		}
	}
}

// ReloadSecrets re-reads the secret set through the configured reloader and
// applies it, so a client add, removal, disable or re-key takes effect without
// restarting the process. It is the POST /reload entry point; SIGHUP goes
// through ApplySecrets with the same re-read configuration, and both end in
// applySecretConfigLocked. It returns ErrReloaderNotConfigured when the proxy
// was built without a SecretsReloader, and an error (leaving the current set
// active) when the reloader fails or yields no valid secret.
func (p *Proxy) ReloadSecrets() error {
	if p.reloader == nil {
		return ErrReloaderNotConfigured
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg, err := p.reloader()
	if err != nil {
		return fmt.Errorf("cannot reload secrets: %w", err)
	}

	return p.swapSecretConfigLocked(cfg)
}

// ApplySecrets replaces the whole secret configuration (secrets, advertising
// tags, limits) without restarting the proxy.
//
// New handshakes use the new set right away. Live sessions of secrets that
// are kept unchanged continue to work; sessions of removed secrets, of
// secrets whose key or host has changed and of secrets that are now disabled
// or expired are closed. Other options (bind addresses, domain fronting,
// defense settings) are not affected.
func (p *Proxy) ApplySecrets(cfg SecretConfig) (SecretsUpdate, error) {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	return p.applySecretConfigLocked(cfg)
}

// UpdateSecrets replaces only the set of secrets. Advertising tags and limits
// of the names that are kept stay as they are; those of removed names are
// dropped.
func (p *Proxy) UpdateSecrets(secrets map[string]Secret) (SecretsUpdate, error) {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()
	cfg.Secrets = secrets

	for name := range cfg.SecretAdTags {
		if _, ok := secrets[name]; !ok {
			delete(cfg.SecretAdTags, name)
		}
	}

	for name := range cfg.Limits {
		if _, ok := secrets[name]; !ok {
			delete(cfg.Limits, name)
		}
	}

	return p.applySecretConfigLocked(cfg)
}

// SetSecretsHook registers fn to be called with every new secret set before
// it is applied (for example, to rebuild WEB-mode profiles). An error from fn
// aborts the update and keeps the current set everywhere. fn is called right
// away with the current set, so the hook owner starts in sync even if an
// update has happened between NewProxy and this call.
func (p *Proxy) SetSecretsHook(fn func(map[string]Secret) error) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	if fn != nil {
		if err := fn(p.secrets.Load().toConfig().Secrets); err != nil {
			return err
		}
	}

	p.secretsHook = fn

	return nil
}

// swapSecretConfigLocked is applySecretConfigLocked for callers that need
// only the error. The caller MUST hold reloadMu.
func (p *Proxy) swapSecretConfigLocked(cfg SecretConfig) error {
	_, err := p.applySecretConfigLocked(cfg)

	return err
}

// applySecretConfigLocked - единственная точка смены набора секретов: SIGHUP,
// POST /reload и все мутаторы API приходят сюда. Порядок:
//
//  1. проверки - до любых побочных эффектов;
//  2. хук (WEB-вход): его таблицы строятся первыми, при ошибке прокси не
//     трогаем - обе стороны остаются на прежнем списке;
//  3. подмена набора, отпечатка и сбор сессий на закрытие - под sessions.mu,
//     той же блокировкой, под которой регистрируется сессия (trackSession);
//  4. закрытие сессий через исходное соединение (closeFromOutside).
//
// Вызывающий ОБЯЗАН держать reloadMu.
func (p *Proxy) applySecretConfigLocked(cfg SecretConfig) (SecretsUpdate, error) {
	update := SecretsUpdate{}

	if len(cfg.Secrets) == 0 {
		return update, fmt.Errorf("%w: %w", ErrSecretEmpty, ErrSecretInvalid)
	}

	for name, secret := range cfg.Secrets {
		if !secret.Valid() {
			return update, fmt.Errorf("%w: invalid secret %q", ErrSecretInvalid, name)
		}
	}

	if p.secretsHook != nil {
		if err := p.secretsHook(cfg.Secrets); err != nil {
			return update, fmt.Errorf("cannot apply secrets to hook: %w", err)
		}
	}

	next := newSecretSetFromConfig(cfg)

	for _, name := range next.names {
		p.stats.PreRegister(name)
	}

	toClose := []*streamContext{}
	gone := []string{}

	p.sessions.mu.Lock()

	prev := p.secrets.Swap(next)
	p.stats.SetSecretsDigest(next.digest())

	if prev != nil {
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
	}

	// Сессии оставшихся пользователей, которых теперь запрещают лимиты
	// (выключен или истёк срок). Превышение квоты живые сессии не рвёт - как и
	// throttle, оно действует только на новые соединения.
	for name, sessions := range p.sessions.sessions {
		if p.deniedNow(next.limitsOf(name)) {
			for ctx := range sessions {
				toClose = append(toClose, ctx)
			}

			delete(p.sessions.sessions, name)
		}
	}

	for _, name := range gone {
		p.stats.Forget(name)
	}

	p.sessions.mu.Unlock()

	for _, name := range next.names {
		if prev == nil {
			update.Added++

			continue
		}

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

// trackSession registers an authenticated session and counts it in the stats.
// It fails if the secret the session has authenticated with was removed or
// changed after the handshake had started, or is now disabled or expired.
// Both happen under the registry lock, so a concurrent update either sees the
// session and closes it, or the session is rejected; the stats of a removed
// secret are never recreated.
func (p *Proxy) trackSession(ctx *streamContext) bool {
	p.sessions.mu.Lock()
	defer p.sessions.mu.Unlock()

	set := p.secrets.Load()

	if !set.sameSecret(ctx.secretName, ctx.matchedSecretKey) {
		return false
	}

	if p.deniedNow(set.limitsOf(ctx.secretName)) {
		return false
	}

	p.sessions.add(ctx)
	ctx.userStats = p.stats.getOrCreate(ctx.secretName)
	ctx.userStats.connections.Add(1)

	return true
}

// deniedNow reports whether limits forbid a secret right now regardless of its
// traffic: it is disabled or has expired.
func (p *Proxy) deniedNow(lim SecretLimits) bool {
	if lim.Disabled {
		return true
	}

	return !lim.ExpiresAt.IsZero() && !time.Now().Before(lim.ExpiresAt)
}

// checkLimits reports whether a new connection for the named secret is allowed
// by its governance limits, combining the snapshot limit (disabled flag, expiry
// deadline, quota ceiling) with the live usage counter held in stats. The
// returned DenyReason is DenyNone when allowed.
func (p *Proxy) checkLimits(name string, lim SecretLimits) (bool, DenyReason) {
	if lim.Disabled {
		return false, DenyDisabled
	}

	if !lim.ExpiresAt.IsZero() && !time.Now().Before(lim.ExpiresAt) {
		return false, DenyExpired
	}

	if lim.QuotaBytes > 0 && p.stats.QuotaUsed(name, lim.QuotaReset) >= lim.QuotaBytes {
		return false, DenyQuota
	}

	return true, DenyNone
}

// closeDeniedConns closes every live stream whose secret is now denied because
// it was disabled or has expired, so such a change takes effect immediately
// instead of only blocking new connections. A quota overrun does not close
// live streams — consistent with the throttle, existing connections are never
// killed mid-flight. applySecretConfigLocked does the same as a part of every
// update; this is for a check outside of an update.
func (p *Proxy) closeDeniedConns() int {
	set := p.secrets.Load()

	var denied []*streamContext

	p.sessions.mu.Lock()
	for name, sessions := range p.sessions.sessions {
		if !p.deniedNow(set.limitsOf(name)) {
			continue
		}

		for sc := range sessions {
			denied = append(denied, sc)
		}

		delete(p.sessions.sessions, name)
	}
	p.sessions.mu.Unlock()

	for _, sc := range denied {
		sc.closeFromOutside()
	}

	return len(denied)
}

// rolloverAllQuotas applies a monthly quota rollover to every secret whose
// policy is monthly, keeping the persisted and displayed usage fresh even for
// secrets that no client is currently hitting.
func (p *Proxy) rolloverAllQuotas() {
	set := p.secrets.Load()
	now := time.Now()

	for i, name := range set.names {
		if set.limits[i].QuotaReset == QuotaResetMonthly {
			p.stats.rollover(name, set.limits[i].QuotaReset, now)
		}
	}
}

// startUsagePersistence periodically rolls quota periods over and flushes the
// usage counters to usageStateFile until ctx is cancelled.
func (p *Proxy) startUsagePersistence(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(usageFlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.rolloverAllQuotas()

				if err := p.stats.FlushUsage(p.usageStateFile); err != nil {
					p.logger.WarningError("cannot flush usage state", err)
				}
			}
		}
	}()
}

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.clientConn)

	// Read the active secret snapshot once so a concurrent update cannot
	// desync the key list, hostnames and matched index mid-handshake.
	set := p.secrets.Load()

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
		if p.securedDisabled {
			ctx.logger.Info("not a FakeTLS handshake and secured mode is disabled")
			p.doDomainFrontingForHost(ctx, rewind, set.secrets[0].Host)

			return false
		}

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
	ctx.adTag = set.effectiveAdTag(result.MatchedIndex)
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	// Enforce per-user governance limits before we speak TLS back. A denied
	// user (disabled, expired, or over quota) is routed to the cover site just
	// like a wrong secret, so the outcome is indistinguishable to a prober.
	if allowed, reason := p.checkLimits(ctx.secretName, set.limits[result.MatchedIndex]); !allowed {
		ctx.logger.BindStr("deny_reason", reason.String()).
			Info("connection denied by per-user limit; routing to fronting")
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

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
//
// Лимиты пользователя (выключен, истёк, квота) проверяются до Commit: отказ
// уходит на маскировку так же, как неверный ключ.
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

	if allowed, reason := p.checkLimits(set.names[idx], set.limits[idx]); !allowed {
		return false, fmt.Errorf("connection denied by per-user limit: %s", reason.String())
	}

	rewind.Commit()
	ctx.secured = true
	ctx.dc = dcIdx
	ctx.clientConn = cn
	ctx.matchedSecretKey = set.secrets[idx].Key[:]
	ctx.secretName = set.names[idx]
	ctx.adTag = set.effectiveAdTag(idx)
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

// wrapTraffic wraps conn so per-read/write byte counts are emitted as
// EventTraffic, but only when a metrics observer is configured (emitTraffic).
// EventTraffic is consumed solely by the statsd/prometheus observers, so when
// none is enabled the wrapper is skipped entirely — avoiding a heap allocation
// (plus time.Now, a streamID hash and a channel send) on every relay read and
// write.
func (p *Proxy) wrapTraffic(conn essentials.Conn, ctx *streamContext) essentials.Conn {
	if !p.emitTraffic {
		return conn
	}

	return connTraffic{
		Conn:     conn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	// When this stream carries an advertising tag, route it through a Telegram
	// middle proxy so a sponsored channel appears. On any failure we log and
	// fall through to the direct path so the client stays online (availability
	// is favored over the sponsored channel).
	if ctx.adTag != nil && p.middleProxy != nil {
		if err := p.doMiddleProxyCall(ctx); err != nil {
			ctx.logger.WarningError("cannot route through middle proxy, using direct connection", err)
		} else {
			return nil
		}
	}

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

// doMiddleProxyCall dials a Telegram middle proxy for the stream's DC and sets
// ctx.telegramConn to an RPC stream that carries the client's traffic together
// with the advertising tag. It returns an error (leaving ctx.telegramConn
// unset) if the middle proxy cannot be reached, so the caller can fall back to
// a direct connection.
func (p *Proxy) doMiddleProxyCall(ctx *streamContext) error {
	clientAddr, _ := ctx.clientConn.RemoteAddr().(*net.TCPAddr)

	stream, middleIP, err := p.middleProxy.DialProxyStream(p.network, middleproxy.DialParams{
		DC:             ctx.dc,
		ClientAddr:     clientAddr,
		PublicIPv4:     p.ourIPv4,
		PublicIPv6:     p.ourIPv6,
		AdvertisedPort: p.advertisedPort,
		AdTag:          *ctx.adTag,
	})
	if err != nil {
		return fmt.Errorf("cannot dial middle proxy: %w", err)
	}

	ctx.telegramConn = p.wrapTraffic(stream, ctx)

	p.eventStream.Send(ctx, NewEventConnectedToDC(ctx.streamID, middleIP, ctx.dc))

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
	ctx.telegramConn = p.wrapTraffic(conn, ctx)

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

	frontConn = p.wrapTraffic(frontConn, ctx)

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("domain-fronting"),
		connIdleTimeout{Conn: frontConn, tracker: tracker},
		connIdleTimeout{Conn: conn, tracker: tracker},
	)
}

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) { //nolint: funlen
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

	initialSet := buildSecretSet(opts.getSecrets(), opts.SecretAdTags, opts.GlobalAdTag, opts.SecretLimits)

	stats := NewProxyStats()
	for _, name := range initialSet.names {
		stats.PreRegister(name)
	}

	if opts.UsageStateFile != "" {
		if err := stats.LoadUsage(opts.UsageStateFile); err != nil {
			logger.WarningError("cannot load usage state", err)
		}
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
		reloader:                 opts.SecretsReloader,
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
		ourIPv4:                     opts.PublicIPv4,
		ourIPv6:                     opts.PublicIPv6,
		advertisedPort:              opts.AdvertisedPort,
		usageStateFile:              opts.UsageStateFile,
		emitTraffic:                 opts.EmitTraffic,

		securedDisabled:   opts.SecuredDisabled,
		ddShapeEnabled:    opts.DDShapeEnabled,
		ddShapeDelayMinMs: opts.getDDShapeDelayMinMs(),
		ddShapeDelayMaxMs: opts.getDDShapeDelayMaxMs(),
		ddShapeFragBytes:  opts.getDDShapeFragBytes(),
		serverHelloMSS:    opts.ServerHelloMSS,
	}

	// The middle-proxy manager is always available so advertising can be
	// enabled at runtime via the API. It fetches Telegram's proxy secret and
	// middle-proxy list lazily (nothing happens until an ad-tagged stream is
	// dialed), so a proxy without advertising never touches the network. When
	// advertising is already configured, warm it so the first client is fast.
	proxy.middleProxy = middleproxy.NewManager(
		ctx,
		opts.Network.MakeHTTPClient(nil),
		updatersLogger.Named("middle-proxy"),
		opts.getPreferIP(),
	)

	if opts.GlobalAdTag != nil || len(opts.SecretAdTags) > 0 {
		proxy.middleProxy.Warm()
	}

	proxy.secrets.Store(initialSet)
	stats.SetSecretsDigest(initialSet.digest())

	// Start the management API only now that the proxy exists, so the routes
	// can drive ReloadSecrets and the secrets/adtag mutators. /stats, /reload,
	// /secrets and /adtag share the api-bind-to listener; reload is a
	// no-op-with-error when no reloader was supplied.
	if opts.APIBindTo != "" {
		proxy.startAPIServer(ctx, opts.APIBindTo, opts.APIToken)
	}

	if opts.UsageStateFile != "" {
		proxy.startUsagePersistence(ctx)
	}

	proxy.doppelGanger.Run()

	if opts.AutoUpdate {
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv4, "tcp4")
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv6, "tcp6")
	}

	// Тёплый пул коннектов к DC (аналог me-pool telemt). Filler'ы стартуют сразу
	// и фейлят-ретраят, пока AutoUpdate не подтянет адреса DC — клиентов это не
	// блокирует (фолбэк на холодный dial).
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
