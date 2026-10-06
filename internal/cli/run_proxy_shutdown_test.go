package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// На проде: systemctl restart останавливал mtg с кодом 1 - ошибка Accept от
// закрытого при остановке listener считалась аварией.
func TestWaitAndShutdownOrdinaryStopIsClean(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)

	cancel() // SIGTERM

	err := waitAndShutdown(ctx, serveErr, func() {
		// Закрытие listener будит Serve с ошибкой - уже после решения.
		serveErr <- errors.New("use of closed network connection")
	})
	require.NoError(t, err)
}

func TestWaitAndShutdownReportsServeFailure(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	stopped := false

	// Serve упал сам: ошибка в канале, потом cancel().
	serveErr <- errors.New("too many open files")
	cancel()

	err := waitAndShutdown(ctx, serveErr, func() { stopped = true })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many open files")
	assert.True(t, stopped)
}
