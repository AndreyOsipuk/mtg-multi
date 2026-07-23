package obfuscation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"

	"github.com/dolonet/mtg-multi/essentials"
)

// Obfuscator implements the obfuscated2 handshake
// (https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation).
// Set Secret to the MTProxy secret for key-mixed handshakes; leave nil for
// direct DC connections.
type Obfuscator struct {
	Secret []byte
}

// ReadHandshake reads the 64-byte obfuscated2 client handshake from r,
// validates it, and returns the DC the client requested along with a
// transparent en/decrypting wrapper over r.
func (o Obfuscator) ReadHandshake(r essentials.Conn) (int, essentials.Conn, error) {
	raw := handshakeFrame{}

	if _, err := io.ReadFull(r, raw.data[:]); err != nil {
		return 0, nil, fmt.Errorf("cannot read frame: %w", err)
	}

	dc, cn, ok := o.tryFrame(raw, r)
	if !ok {
		return 0, nil, fmt.Errorf("unsupported connection type")
	}

	return dc, cn, nil
}

// tryFrame пытается разобрать УЖЕ прочитанный 64-байтный кадр `raw` ключом o.Secret.
// Работает на КОПИИ (raw передаётся по значению) — можно пробовать несколько ключей
// над одним кадром (multi-secret secured-режим). ok=false, если ключ не подошёл
// (connectionType после дешифровки не совпал).
func (o Obfuscator) tryFrame(raw handshakeFrame, r essentials.Conn) (int, essentials.Conn, bool) {
	frame := raw // копия

	hasher := sha256.New()
	recvCipher := o.getCipher(&frame, hasher)

	frame.revert()
	hasher.Reset()
	sendCipher := o.getCipher(&frame, hasher)

	recvCipher.XORKeyStream(frame.data[:], frame.data[:])

	if val := frame.connectionType(); subtle.ConstantTimeCompare(val, hfConnectionType[:]) != 1 {
		return 0, nil, false
	}

	cn := conn{
		Conn:       r,
		recvCipher: recvCipher,
		sendCipher: sendCipher,
	}

	return frame.dc(), cn, true
}

// ReadHandshakeMulti читает 64-байтный obfuscated2-кадр ОДИН раз и перебирает
// секреты: у чьего ключа connectionType сходится — тот и матч. Используется для
// secured-режима (dd-секрет), где клиент шлёт obfuscated2 напрямую (без FakeTLS),
// и мы не знаем заранее, какой это юзер. Возвращает индекс совпавшего секрета,
// dc, обёрнутое соединение и КЛЮЧ КАДРА (32б) для anti-replay.
func ReadHandshakeMulti(r essentials.Conn, secrets [][]byte) (int, int, essentials.Conn, []byte, error) {
	raw := handshakeFrame{}

	if _, err := io.ReadFull(r, raw.data[:]); err != nil {
		return -1, 0, nil, nil, fmt.Errorf("cannot read frame: %w", err)
	}

	// Ключ кадра (случаен на каждый коннект) — для anti-replay ДО дешифровки.
	replayKey := make([]byte, hfLenKey)
	copy(replayKey, raw.key())

	for i, secret := range secrets {
		obf := Obfuscator{Secret: secret}
		if dc, cn, ok := obf.tryFrame(raw, r); ok {
			return i, dc, cn, replayKey, nil
		}
	}

	return -1, 0, nil, nil, fmt.Errorf("no matching secret for secured handshake")
}

// SendHandshake writes a fresh 64-byte obfuscated2 handshake for the given
// DC to w and returns a transparent en/decrypting wrapper over w.
func (o Obfuscator) SendHandshake(w essentials.Conn, dc int) (essentials.Conn, error) {
	frame := generateHandshake(dc)
	copyFrame := frame
	hasher := sha256.New()

	sendCipher := o.getCipher(&frame, hasher)

	frame.revert()
	hasher.Reset()
	recvCipher := o.getCipher(&frame, hasher)

	sendCipher.XORKeyStream(frame.data[:], frame.data[:])
	copy(frame.key(), copyFrame.key())
	copy(frame.iv(), copyFrame.iv())

	if _, err := w.Write(frame.data[:]); err != nil {
		return nil, fmt.Errorf("cannot send a handshake: %w", err)
	}

	return conn{
		Conn:       w,
		recvCipher: recvCipher,
		sendCipher: sendCipher,
	}, nil
}

func (o Obfuscator) getCipher(f *handshakeFrame, hasher hash.Hash) cipher.Stream {
	blockKey := f.key()

	if o.Secret != nil {
		hasher.Write(blockKey)
		hasher.Write(o.Secret)
		blockKey = hasher.Sum(nil)
	}

	block, _ := aes.NewCipher(blockKey)

	return cipher.NewCTR(block, f.iv())
}
