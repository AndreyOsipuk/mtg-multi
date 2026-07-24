package mtglib

import (
	"bytes"
	"io"
	"testing"

	"github.com/dolonet/mtg-multi/internal/testlib"
	"github.com/stretchr/testify/require"
)

type recordingShaperConn struct {
	testlib.EssentialsConnMock

	writes       [][]byte
	zeroProgress int
}

func (c *recordingShaperConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(p))
	if c.zeroProgress > 0 && len(c.writes) == c.zeroProgress {
		return 0, nil
	}

	return len(p), nil
}

func TestShapedClientConnFragmentsOnlyFirstWrite(t *testing.T) {
	t.Parallel()

	base := &recordingShaperConn{}
	conn := newShapedClientConn(base, 0, 0, 3)

	n, err := conn.Write([]byte("abcdefgh"))
	require.NoError(t, err)
	require.Equal(t, 8, n)
	require.Equal(t, [][]byte{
		[]byte("abc"),
		[]byte("def"),
		[]byte("gh"),
	}, base.writes)

	n, err = conn.Write([]byte("ijkl"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte("ijkl"), base.writes[3])
}

func TestShapedClientConnStopsOnZeroProgress(t *testing.T) {
	t.Parallel()

	base := &recordingShaperConn{zeroProgress: 2}
	conn := newShapedClientConn(base, 0, 0, 3)

	n, err := conn.Write([]byte("abcdef"))
	require.ErrorIs(t, err, io.ErrNoProgress)
	require.Equal(t, 3, n)
}
