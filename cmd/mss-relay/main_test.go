package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// mssRecorder подменяет setMSS в тестах: реальный setsockopt на loopback не
// проверить (ядро не отдаёт применённое значение обратно), а нам важен ПОРЯДОК
// переключений - именно в нём была ошибка старой схемы с iptables.
type mssRecorder struct {
	mu     sync.Mutex
	values []int
}

func (r *mssRecorder) record(v int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values = append(r.values, v)
}

func (r *mssRecorder) snapshot() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, len(r.values))
	copy(out, r.values)
	return out
}

// runRelay поднимает релей на loopback перед фейковой «нодой» и возвращает
// адрес релея + записанные переключения MSS.
func runRelay(t *testing.T, cfg config, nodeReply func(net.Conn)) (string, *mssRecorder) {
	t.Helper()

	node, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("node listen: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	go func() {
		for {
			c, err := node.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				nodeReply(c)
			}()
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("relay listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	rec := &mssRecorder{}
	cfg.backend = node.Addr().String()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client *net.TCPConn) {
				defer client.Close()
				upstream, err := net.DialTimeout("tcp", cfg.backend, cfg.dialTimeout)
				if err != nil {
					return
				}
				defer upstream.Close()
				if cfg.mssHandshake > 0 {
					rec.record(cfg.mssHandshake)
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					copyWithMSSSwitchTest(client, upstream, cfg, rec)
					_ = client.CloseWrite()
				}()
				go func() {
					defer wg.Done()
					_, _ = io.Copy(upstream, client)
					if up, ok := upstream.(*net.TCPConn); ok {
						_ = up.CloseWrite()
					}
				}()
				wg.Wait()
			}(c.(*net.TCPConn))
		}
	}()

	return ln.Addr().String(), rec
}

// copyWithMSSSwitchTest повторяет copyWithMSSSwitch, но пишет переключения в
// recorder вместо setsockopt.
func copyWithMSSSwitchTest(client *net.TCPConn, upstream net.Conn, cfg config, rec *mssRecorder) {
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
				rec.record(cfg.mssBulk)
				restored = true
			}
		}
		if rerr != nil {
			return
		}
	}
}

func baseCfg() config {
	return config{
		mssHandshake:  92,
		mssBulk:       1400,
		handshakeSize: 4096,
		handshakeTime: 2 * time.Second,
		dialTimeout:   3 * time.Second,
	}
}

func dialAndRead(t *testing.T, addr string, want int) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("client-hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 0, want)
	buf := make([]byte, 4096)
	for len(got) < want {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	return got
}

// Большой ответ (ee/ServerHello ~3800 б): MSS должен подняться ПОСЛЕ окна.
func TestBulkMSSRestoredAfterLargeReply(t *testing.T) {
	cfg := baseCfg()
	payload := make([]byte, 8192)
	addr, rec := runRelay(t, cfg, func(c net.Conn) {
		_, _ = c.Write(payload)
		time.Sleep(50 * time.Millisecond)
	})

	got := dialAndRead(t, addr, len(payload))
	if len(got) != len(payload) {
		t.Fatalf("клиент получил %d б, ожидалось %d", len(got), len(payload))
	}

	vals := rec.snapshot()
	if len(vals) != 2 || vals[0] != 92 || vals[1] != 1400 {
		t.Fatalf("ожидалась последовательность [92 1400], получено %v", vals)
	}
}

// Короткий ответ (dd-рукопожатие ~64 б): порога по объёму не хватит, MSS должен
// вернуться по таймеру - иначе весь сеанс останется с мелкими сегментами.
func TestBulkMSSRestoredByTimeout(t *testing.T) {
	cfg := baseCfg()
	cfg.handshakeTime = 150 * time.Millisecond

	addr, rec := runRelay(t, cfg, func(c net.Conn) {
		_, _ = c.Write([]byte("dd-reply"))
		time.Sleep(300 * time.Millisecond)
		_, _ = c.Write([]byte("bulk-data"))
		time.Sleep(50 * time.Millisecond)
	})

	_ = dialAndRead(t, addr, len("dd-reply")+len("bulk-data"))

	vals := rec.snapshot()
	if len(vals) != 2 || vals[1] != 1400 {
		t.Fatalf("MSS не вернулся по таймеру: %v", vals)
	}
}

// Данные должны доходить в обе стороны без искажений.
func TestRelayPassesDataBothWays(t *testing.T) {
	cfg := baseCfg()
	received := make(chan string, 1)

	addr, _ := runRelay(t, cfg, func(c net.Conn) {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		received <- string(buf[:n])
		_, _ = c.Write([]byte("pong"))
		time.Sleep(30 * time.Millisecond)
	})

	got := dialAndRead(t, addr, 4)
	if string(got) != "pong" {
		t.Fatalf("ответ ноды искажён: %q", string(got))
	}
	select {
	case fromClient := <-received:
		if fromClient != "client-hello" {
			t.Fatalf("нода получила %q", fromClient)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("нода не получила данные клиента")
	}
}

// Выключенный шейпинг (mss-handshake=0) - релей работает как обычная труба.
func TestShapingDisabled(t *testing.T) {
	cfg := baseCfg()
	cfg.mssHandshake = 0

	addr, rec := runRelay(t, cfg, func(c net.Conn) {
		_, _ = c.Write([]byte("data"))
		time.Sleep(30 * time.Millisecond)
	})

	_ = dialAndRead(t, addr, 4)
	if vals := rec.snapshot(); len(vals) != 0 {
		t.Fatalf("MSS трогать не должны, получено %v", vals)
	}
}
