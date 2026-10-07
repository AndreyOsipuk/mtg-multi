//go:build linux

package mtglib

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// tcpTimestampsOverhead - размер опции TCP timestamps (с выравниванием): на
// столько полезная нагрузка сегмента меньше MSS, если timestamps согласованы.
const tcpTimestampsOverhead = 12

// tcpiOptTimestamps - бит TCPI_OPT_TIMESTAMPS в tcpi_options (linux/tcp.h);
// в golang.org/x/sys/unix константы нет.
const tcpiOptTimestamps = 1

// serverHelloWaitMax - верхняя граница ожидания отправки одного ServerHello,
// если дедлайн рукопожатия не задан.
const serverHelloWaitMax = 10 * time.Second

const (
	notsentPollMin = 100 * time.Microsecond
	notsentPollMax = 5 * time.Millisecond
)

// writeFragmented пишет data в TCP-соединение кусками, каждый из которых уходит
// отдельным сегментом с полезной нагрузкой не больше, чем при MSS = mss.
// Если соединение не TCP или mss <= 0 - обычная запись целиком.
func writeFragmented(conn net.Conn, data []byte, mss int, deadline time.Time) (int, error) {
	tcp := tcpConnOf(conn)
	if tcp == nil || mss <= 0 {
		return conn.Write(data) //nolint: wrapcheck
	}

	rawConn, err := tcp.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("cannot get raw connection: %w", err)
	}

	// Каждый кусок должен уходить сразу, без Nagle (в Go включено по
	// умолчанию, но не полагаемся на это).
	if err := tcp.SetNoDelay(true); err != nil {
		return 0, fmt.Errorf("cannot set TCP_NODELAY: %w", err)
	}

	info, err := getTCPInfo(rawConn)
	if err != nil {
		return 0, err
	}

	chunk := segmentPayload(mss, info)

	if deadline.IsZero() {
		deadline = time.Now().Add(serverHelloWaitMax)
	}

	written := 0

	for written < len(data) {
		if err := waitNotSent(rawConn, deadline); err != nil {
			return written, err
		}

		end := min(written+chunk, len(data))

		n, err := tcp.Write(data[written:end])
		written += n

		if err != nil {
			return written, err //nolint: wrapcheck
		}
	}

	// Дождаться, пока уйдёт и последний кусок: иначе к нему может
	// приклеиться следующая запись.
	return written, waitNotSent(rawConn, deadline)
}

// segmentPayload - полезная нагрузка сегмента при MSS = mss: минус опция
// timestamps, если она согласована, и не больше текущего MSS соединения.
func segmentPayload(mss int, info *unix.TCPInfo) int {
	payload := mss
	if info.Options&tcpiOptTimestamps != 0 {
		payload -= tcpTimestampsOverhead
	}

	if sndMSS := int(info.Snd_mss); sndMSS > 0 && payload > sndMSS {
		payload = sndMSS
	}

	return max(payload, 1)
}

type rawControl interface {
	Control(f func(fd uintptr)) error
}

func getTCPInfo(rawConn rawControl) (*unix.TCPInfo, error) {
	var (
		info   *unix.TCPInfo
		sysErr error
	)

	if err := rawConn.Control(func(fd uintptr) {
		info, sysErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil {
		return nil, fmt.Errorf("cannot access socket: %w", err)
	}

	if sysErr != nil {
		return nil, fmt.Errorf("cannot get TCP_INFO: %w", sysErr)
	}

	return info, nil
}

// waitNotSent ждёт, пока в очереди сокета не останется неотправленных байт
// (уже ушедшие в сеть, но не подтверждённые не в счёт). Опрос с растущей
// паузой: ждать приходится только когда упёрлись в окно перегрузки, это
// единицы RTT на рукопожатие.
func waitNotSent(rawConn rawControl, deadline time.Time) error {
	pause := notsentPollMin

	for {
		info, err := getTCPInfo(rawConn)
		if err != nil {
			return err
		}

		if info.Notsent_bytes == 0 {
			return nil
		}

		if !time.Now().Before(deadline) {
			return fmt.Errorf("server hello is not sent in time: %w", os.ErrDeadlineExceeded)
		}

		time.Sleep(pause)

		pause = min(pause*2, notsentPollMax)
	}
}

// tcpConnOf достаёт исходное TCP-соединение клиента: напрямую или из-под
// обёртки PROXY protocol. nil - не TCP (например, поток WEB-режима).
func tcpConnOf(conn net.Conn) *net.TCPConn {
	switch c := conn.(type) {
	case *net.TCPConn:
		return c
	case interface{ TCPConn() (*net.TCPConn, bool) }:
		if tcp, ok := c.TCPConn(); ok {
			return tcp
		}
	}

	return nil
}
