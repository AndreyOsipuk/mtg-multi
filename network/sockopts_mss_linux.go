//go:build linux

package network

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenerMSSSupported сообщает, умеет ли платформа задавать MSS слушающего
// сокета (TCP_MAXSEG). Вне Linux параметр client-mss игнорируется.
const ListenerMSSSupported = true

// ListenControlMSS возвращает Control для net.ListenConfig, который ставит
// TCP_MAXSEG на слушающий сокет до bind/listen. Принятые соединения наследуют
// значение: SYN-ACK объявляет клиенту этот MSS, и ядро не шлёт клиенту
// сегменты крупнее него до конца соединения (mss_clamp фиксируется при
// рукопожатии; поднять его позже через setsockopt нельзя). mss <= 0 - ничего
// не трогать.
func ListenControlMSS(mss int) func(network, address string, conn syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		if mss <= 0 {
			return nil
		}

		var opErr error

		if err := conn.Control(func(fd uintptr) {
			opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
		}); err != nil {
			return fmt.Errorf("cannot access listener socket: %w", err)
		}

		if opErr != nil {
			return fmt.Errorf("cannot set TCP_MAXSEG=%d: %w", mss, opErr)
		}

		return nil
	}
}
