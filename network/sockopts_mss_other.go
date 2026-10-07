//go:build !linux

package network

import "syscall"

// ListenerMSSSupported сообщает, умеет ли платформа задавать MSS слушающего
// сокета (TCP_MAXSEG). Вне Linux параметр client-mss игнорируется.
const ListenerMSSSupported = false

// ListenControlMSS вне Linux ничего не делает: client-mss работает только
// на Linux.
func ListenControlMSS(_ int) func(network, address string, conn syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return nil
	}
}
