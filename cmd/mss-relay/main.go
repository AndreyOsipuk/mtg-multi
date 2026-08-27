// mss-relay — TCP-релей для mtg-плеча с двухступенчатым MSS.
//
// Зачем. РФ-релей проксирует клиентов на зарубежную mtg-ноду. Мобильный ТСПУ
// глушит первый ответ прокси, если он приходит одним нормальным сегментом,
// поэтому исторически мы вешали `iptables TCPMSS --set-mss 92` на порт релея.
// Беда в том, что правило файрвола действует ВЕСЬ сеанс: поток дробится на
// 80-байтные сегменты, медиа падает до ~150 кбит/с, а Telegram Desktop вообще
// не подключается — его FakeTLS ClientHello ~1800 б не доезжает (26.08.2026).
// Из-за этого приходилось держать второй «чистый» порт (8768) для ee и десктопа.
//
// Как здесь. Повторяем приём telemt (client_mss + client_mss_bulk): слушаем с
// НОРМАЛЬНЫМ MSS — клиент шлёт рукопожатие целиком; перед тем как отдать первый
// ответ сервера, ставим на принятый сокет TCP_MAXSEG=92 (ответ уходит мелкими
// сегментами — ТСПУ доволен), а как только «окно рукопожатия» пройдено,
// возвращаем полный MSS, и дальше поток идёт нормально.
//
// Итог: один порт обслуживает и сотовый Android (dd), и iPhone/десктоп (ee) —
// как :443 у telemt. Второй порт становится не нужен.
//
// Только Linux: TCP_MAXSEG на живом сокете есть лишь там.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type config struct {
	listen        string
	backend       string
	mssHandshake  int
	mssBulk       int
	handshakeSize int64
	handshakeTime time.Duration
	dialTimeout   time.Duration
	idleTimeout   time.Duration
	verbose       bool
}

func main() {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", ":8767", "адрес прослушивания (host:port)")
	flag.StringVar(&cfg.backend, "backend", "", "адрес mtg-ноды (host:port), обязателен")
	flag.IntVar(&cfg.mssHandshake, "mss-handshake", 92, "MSS на время первого ответа сервера (0 = не менять)")
	flag.IntVar(&cfg.mssBulk, "mss-bulk", 1400, "MSS после окна рукопожатия")
	flag.Int64Var(&cfg.handshakeSize, "handshake-bytes", 4096, "сколько байт ответа считать рукопожатием")
	flag.DurationVar(&cfg.handshakeTime, "handshake-timeout", 2*time.Second, "предел окна рукопожатия по времени")
	flag.DurationVar(&cfg.dialTimeout, "dial-timeout", 10*time.Second, "таймаут подключения к ноде")
	flag.DurationVar(&cfg.idleTimeout, "idle-timeout", 0, "закрывать соединение без трафика (0 = никогда)")
	flag.BoolVar(&cfg.verbose, "verbose", false, "логировать каждое соединение")
	flag.Parse()

	if cfg.backend == "" {
		fmt.Fprintln(os.Stderr, "нужен -backend host:port")
		os.Exit(2)
	}
	if cfg.mssHandshake != 0 && cfg.mssBulk != 0 && cfg.mssBulk <= cfg.mssHandshake {
		fmt.Fprintln(os.Stderr, "-mss-bulk должен быть больше -mss-handshake")
		os.Exit(2)
	}

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.listen, err)
	}
	log.Printf("mss-relay: %s → %s (MSS %d на первые %d б ответа, дальше %d)",
		cfg.listen, cfg.backend, cfg.mssHandshake, cfg.handshakeSize, cfg.mssBulk)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Print("mss-relay: остановка")
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn.(*net.TCPConn), cfg)
	}
}

func handle(client *net.TCPConn, cfg config) {
	defer client.Close()
	_ = client.SetNoDelay(true)

	upstream, err := net.DialTimeout("tcp", cfg.backend, cfg.dialTimeout)
	if err != nil {
		if cfg.verbose {
			log.Printf("%s: не подключиться к ноде: %v", client.RemoteAddr(), err)
		}
		return
	}
	defer upstream.Close()
	if tcpUp, ok := upstream.(*net.TCPConn); ok {
		_ = tcpUp.SetNoDelay(true)
	}

	// Окно рукопожатия: ответ сервера уходит мелкими сегментами.
	if cfg.mssHandshake > 0 {
		if err := setMSS(client, cfg.mssHandshake); err != nil && cfg.verbose {
			log.Printf("%s: не выставить MSS %d: %v", client.RemoteAddr(), cfg.mssHandshake, err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// нода → клиент: следим за объёмом и вовремя поднимаем MSS
	go func() {
		defer wg.Done()
		copyWithMSSSwitch(client, upstream, cfg)
		_ = client.CloseWrite()
	}()

	// клиент → нода
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if tcpUp, ok := upstream.(*net.TCPConn); ok {
			_ = tcpUp.CloseWrite()
		}
	}()

	wg.Wait()
}

// copyWithMSSSwitch льёт данные ноды клиенту и, пройдя окно рукопожатия,
// возвращает полный MSS. Окно закрывается по объёму ИЛИ по времени - второе
// нужно, когда первый ответ короче порога (secured-рукопожатие ~64 б) и без
// таймера соединение до конца сеанса осталось бы с мелкими сегментами.
func copyWithMSSSwitch(client *net.TCPConn, upstream net.Conn, cfg config) {
	var sent int64
	restored := cfg.mssHandshake <= 0 || cfg.mssBulk <= 0
	deadline := time.Now().Add(cfg.handshakeTime)
	buf := make([]byte, 32*1024)

	for {
		n, rerr := upstream.Read(buf)
		if n > 0 {
			if _, werr := client.Write(buf[:n]); werr != nil {
				return
			}
			sent += int64(n)
			if !restored && (sent >= cfg.handshakeSize || time.Now().After(deadline)) {
				if err := setMSS(client, cfg.mssBulk); err != nil && cfg.verbose {
					log.Printf("%s: не вернуть MSS %d: %v", client.RemoteAddr(), cfg.mssBulk, err)
				}
				restored = true
			}
		}
		if rerr != nil {
			return
		}
	}
}
