//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// setMSS меняет TCP_MAXSEG на уже принятом соединении. Ядро применяет значение
// к последующим отправкам, поэтому вызов посреди сеанса допустим - именно так
// telemt дробит ServerHello и возвращает нормальный размер для потока.
func setMSS(conn *net.TCPConn, mss int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
	}); cerr != nil {
		return cerr
	}
	return serr
}
