package web_test

import (
	"testing"

	"github.com/dolonet/mtg-multi/web"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Формат кадра задан Telegram Desktop. Тест фиксирует раскладку побайтово:
// заголовок 8 байт, тип, 24-битный идентификатор потока и длина - big-endian.
func TestEncodeLayout(t *testing.T) {
	encoded := web.Encode(web.FrameData, 0x0102_03, []byte("abc"))

	assert.Equal(t, []byte{
		0x02,             // тип
		0x01, 0x02, 0x03, // поток
		0x00, 0x00, 0x00, 0x03, // длина
		'a', 'b', 'c',
	}, encoded)
}

func TestParseAllRoundTrip(t *testing.T) {
	body := append(
		web.Encode(web.FrameOpen, 7, nil),
		web.Encode(web.FrameData, 7, []byte("hello"))...,
	)
	body = append(body, web.Encode(web.FrameClose, 7, nil)...)

	frames, err := web.ParseAll(body, web.DefaultLimits())
	require.NoError(t, err)
	require.Len(t, frames, 3)

	assert.Equal(t, web.FrameOpen, frames[0].Type)
	assert.Equal(t, uint32(7), frames[0].StreamID)
	assert.Empty(t, frames[0].Payload)

	assert.Equal(t, web.FrameData, frames[1].Type)
	assert.Equal(t, []byte("hello"), frames[1].Payload)

	assert.Equal(t, web.FrameClose, frames[2].Type)
}

func TestParseAllMaxStreamID(t *testing.T) {
	frames, err := web.ParseAll(web.Encode(web.FrameOpen, web.MaxStreamID, nil), web.DefaultLimits())
	require.NoError(t, err)
	assert.Equal(t, uint32(web.MaxStreamID), frames[0].StreamID)
}

// Тело приходит из сети, поэтому разбор обязан отвергать мусор ДО аллокаций:
// заявленная длина - это не обещание, а вход под контролем клиента.
func TestParseAllRejects(t *testing.T) {
	limits := web.DefaultLimits()

	t.Run("пустое тело", func(t *testing.T) {
		_, err := web.ParseAll(nil, limits)
		assert.ErrorIs(t, err, web.ErrEmptyBatch)
	})

	t.Run("обрезанный заголовок", func(t *testing.T) {
		_, err := web.ParseAll([]byte{0x02, 0x00, 0x00}, limits)
		assert.ErrorIs(t, err, web.ErrIncomplete)
	})

	t.Run("нагрузка короче заявленной", func(t *testing.T) {
		frame := web.Encode(web.FrameData, 1, []byte("hello"))
		_, err := web.ParseAll(frame[:len(frame)-2], limits)
		assert.ErrorIs(t, err, web.ErrIncomplete)
	})

	t.Run("неизвестный тип", func(t *testing.T) {
		_, err := web.ParseAll([]byte{0x7f, 0, 0, 1, 0, 0, 0, 0}, limits)
		assert.ErrorIs(t, err, web.ErrUnknownType)
	})

	t.Run("нагрузка больше лимита", func(t *testing.T) {
		// Заявленная длина огромная, самих данных нет - классическая попытка
		// заставить сервер выделить память по чужому слову.
		_, err := web.ParseAll([]byte{0x02, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}, limits)
		assert.ErrorIs(t, err, web.ErrPayloadLimit)
	})

	t.Run("кадров больше лимита", func(t *testing.T) {
		tight := web.Limits{MaxFramesPerBody: 2, MaxFramePayloadLen: 16}

		var body []byte
		for range 3 {
			body = append(body, web.Encode(web.FrameOpen, 1, nil)...)
		}

		_, err := web.ParseAll(body, tight)
		assert.ErrorIs(t, err, web.ErrTooManyFrames)
	})
}

func TestValidateClientShape(t *testing.T) {
	t.Run("допустимые кадры", func(t *testing.T) {
		for name, frame := range map[string]web.Frame{
			"OPEN без нагрузки":  {Type: web.FrameOpen, StreamID: 1},
			"CLOSE без нагрузки": {Type: web.FrameClose, StreamID: 1},
			"DATA с нагрузкой":   {Type: web.FrameData, StreamID: 1, Payload: []byte("x")},
			"WINDOW с прибавкой": {Type: web.FrameWindow, StreamID: 1, Payload: web.WindowPayload(1024)},
			"PONG на потоке 0":   {Type: web.FramePong, StreamID: 0, Payload: []byte("t")},
		} {
			t.Run(name, func(t *testing.T) {
				assert.NoError(t, web.ValidateClientShape(frame))
			})
		}
	})

	t.Run("недопустимые кадры", func(t *testing.T) {
		big := make([]byte, 65)

		for name, frame := range map[string]web.Frame{
			// Поток 0 служебный: по нему от клиента идёт только PONG.
			"DATA на потоке 0":      {Type: web.FrameData, StreamID: 0, Payload: []byte("x")},
			"OPEN на потоке 0":      {Type: web.FrameOpen, StreamID: 0},
			"PONG с длинным телом":  {Type: web.FramePong, StreamID: 0, Payload: big},
			"OPEN с нагрузкой":      {Type: web.FrameOpen, StreamID: 1, Payload: []byte("x")},
			"DATA без нагрузки":     {Type: web.FrameData, StreamID: 1},
			"WINDOW с нулём":        {Type: web.FrameWindow, StreamID: 1, Payload: web.WindowPayload(0)},
			"WINDOW кривой длины":   {Type: web.FrameWindow, StreamID: 1, Payload: []byte{1, 2}},
			"PING от клиента":       {Type: web.FramePing, StreamID: 1},
			"WELCOME от клиента":    {Type: web.FrameWelcome, StreamID: 1},
			"HELLO на живом потоке": {Type: web.FrameHello, StreamID: 1},
		} {
			t.Run(name, func(t *testing.T) {
				assert.ErrorIs(t, web.ValidateClientShape(frame), web.ErrInvalidShape)
			})
		}
	})
}

func TestValidateHello(t *testing.T) {
	limits := web.DefaultLimits()

	t.Run("ровно один HELLO версии 1", func(t *testing.T) {
		assert.True(t, web.ValidateHello(web.Encode(web.FrameHello, 0, []byte{1}), limits))
	})

	t.Run("чужая версия", func(t *testing.T) {
		assert.False(t, web.ValidateHello(web.Encode(web.FrameHello, 0, []byte{2}), limits))
	})

	t.Run("HELLO не на нулевом потоке", func(t *testing.T) {
		assert.False(t, web.ValidateHello(web.Encode(web.FrameHello, 1, []byte{1}), limits))
	})

	t.Run("лишний кадр рядом", func(t *testing.T) {
		body := append(
			web.Encode(web.FrameHello, 0, []byte{1}),
			web.Encode(web.FrameOpen, 1, nil)...,
		)
		assert.False(t, web.ValidateHello(body, limits))
	})

	t.Run("пустое тело", func(t *testing.T) {
		assert.False(t, web.ValidateHello(nil, limits))
	})
}

func TestWindowAmount(t *testing.T) {
	amount, err := web.WindowAmount(web.WindowPayload(4096))
	require.NoError(t, err)
	assert.Equal(t, uint32(4096), amount)

	_, err = web.WindowAmount(web.WindowPayload(0))
	assert.ErrorIs(t, err, web.ErrInvalidShape)
}
