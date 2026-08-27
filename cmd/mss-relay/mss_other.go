//go:build !linux

package main

import "net"

// На не-Linux MSS не трогаем: TCP_MAXSEG на живом сокете есть только в Linux.
// Релей при этом работает как обычная труба - удобно для локальной отладки.
func setMSS(_ *net.TCPConn, _ int) error { return nil }
