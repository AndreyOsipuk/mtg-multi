//go:build !linux

package mtglib

import (
	"net"
	"time"
)

// writeFragmented вне Linux пишет данные целиком: client-mss работает только
// на Linux (нужны TCP_INFO и tcpi_notsent_bytes).
func writeFragmented(conn net.Conn, data []byte, _ int, _ time.Time) (int, error) {
	return conn.Write(data) //nolint: wrapcheck
}
