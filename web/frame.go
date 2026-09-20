package web

import (
	"encoding/binary"
	"errors"
)

// Формат кадра задан Telegram Desktop, менять нельзя:
//
//	байт 0     - тип кадра
//	байты 1..3 - идентификатор логического потока, big-endian, 24 бита
//	байты 4..7 - длина полезной нагрузки, big-endian, 32 бита
//	далее      - сама нагрузка
//
// В одном HTTP-теле может лежать несколько кадров подряд.
const (
	// HeaderBytes - размер заголовка кадра.
	HeaderBytes = 8
	// MaxStreamID - потолок 24-битного идентификатора потока.
	MaxStreamID = 0x00ff_ffff
	// InitialStreamWindow - стартовый кредит потока в обе стороны.
	InitialStreamWindow = 4 * 1024 * 1024
	// DataChunkBytes - максимальный кусок данных, который отдаёт сервер.
	DataChunkBytes = 64 * 1024
)

// FrameType - код типа кадра.
type FrameType uint8

const (
	// FrameOpen открывает логический поток (одно MTProto-соединение).
	FrameOpen FrameType = 0x01
	// FrameData несёт байты потока.
	FrameData FrameType = 0x02
	// FrameClose закрывает поток.
	FrameClose FrameType = 0x03
	// FrameWindow возвращает израсходованный кредит.
	FrameWindow FrameType = 0x04
	// FramePing запрашивает признак жизни.
	FramePing FrameType = 0x05
	// FramePong отвечает на FramePing.
	FramePong FrameType = 0x06
	// FrameHello начинает сессию.
	FrameHello FrameType = 0x10
	// FrameWelcome подтверждает создание сессии.
	FrameWelcome FrameType = 0x11
	// FrameBye завершает сессию.
	FrameBye FrameType = 0x1f
)

// String даёт имя типа для логов.
func (f FrameType) String() string {
	switch f {
	case FrameOpen:
		return "OPEN"
	case FrameData:
		return "DATA"
	case FrameClose:
		return "CLOSE"
	case FrameWindow:
		return "WINDOW"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameHello:
		return "HELLO"
	case FrameWelcome:
		return "WELCOME"
	case FrameBye:
		return "BYE"
	default:
		return "UNKNOWN"
	}
}

func parseFrameType(value byte) (FrameType, bool) {
	switch FrameType(value) {
	case FrameOpen, FrameData, FrameClose, FrameWindow,
		FramePing, FramePong, FrameHello, FrameWelcome, FrameBye:
		return FrameType(value), true
	default:
		return 0, false
	}
}

// Frame - один разобранный кадр. Payload указывает внутрь исходного буфера,
// копии не делается: тело запроса живёт дольше разбора.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

// Ошибки разбора. Наружу клиенту они не показываются - любой сбой означает
// «это не наш клиент», и запрос уходит в заглушку.
var (
	// ErrEmptyBatch - пустое тело запроса.
	ErrEmptyBatch = errors.New("web: тело без кадров")
	// ErrTooManyFrames - кадров в теле больше разрешённого.
	ErrTooManyFrames = errors.New("web: слишком много кадров в теле")
	// ErrIncomplete - заголовок или нагрузка обрезаны.
	ErrIncomplete = errors.New("web: кадр обрезан")
	// ErrPayloadLimit - нагрузка больше разрешённой.
	ErrPayloadLimit = errors.New("web: нагрузка кадра превышает лимит")
	// ErrUnknownType - неизвестный код типа.
	ErrUnknownType = errors.New("web: неизвестный тип кадра")
	// ErrInvalidShape - кадр известного типа нарушает грамматику направления.
	ErrInvalidShape = errors.New("web: недопустимая форма кадра")
)

// Limits - границы, за которые клиент выйти не может.
//
// Нужны до всякой аллокации: тело приходит из сети, и «сколько скажут, столько
// и выделим» - прямой путь к исчерпанию памяти.
type Limits struct {
	MaxFramesPerBody   int
	MaxFramePayloadLen int
}

// DefaultLimits - разумные значения по умолчанию.
func DefaultLimits() Limits {
	return Limits{
		MaxFramesPerBody:   256,
		MaxFramePayloadLen: DataChunkBytes,
	}
}

// ParseAll разбирает все кадры тела, не копируя нагрузку.
func ParseAll(input []byte, limits Limits) ([]Frame, error) {
	if len(input) == 0 {
		return nil, ErrEmptyBatch
	}

	frames := make([]Frame, 0, 8)
	rest := input

	for len(rest) > 0 {
		if len(frames) >= limits.MaxFramesPerBody {
			return nil, ErrTooManyFrames
		}

		if len(rest) < HeaderBytes {
			return nil, ErrIncomplete
		}

		frameType, ok := parseFrameType(rest[0])
		if !ok {
			return nil, ErrUnknownType
		}

		streamID := uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])

		payloadLen := int(binary.BigEndian.Uint32(rest[4:HeaderBytes]))
		if payloadLen > limits.MaxFramePayloadLen {
			return nil, ErrPayloadLimit
		}

		frameLen := HeaderBytes + payloadLen
		if frameLen > len(rest) {
			return nil, ErrIncomplete
		}

		frames = append(frames, Frame{
			Type:     frameType,
			StreamID: streamID,
			Payload:  rest[HeaderBytes:frameLen],
		})

		rest = rest[frameLen:]
	}

	return frames, nil
}

// ValidateClientShape проверяет грамматику кадров, идущих ОТ клиента.
//
// Поток 0 - служебный: по нему клиент присылает только PONG. Всё остальное на
// нулевом потоке и любой кадр не той формы означает чужой или сломанный клиент.
func ValidateClientShape(frame Frame) error {
	if frame.StreamID == 0 {
		if frame.Type == FramePong && len(frame.Payload) <= 64 {
			return nil
		}

		return ErrInvalidShape
	}

	switch frame.Type {
	case FrameOpen, FrameClose:
		if len(frame.Payload) == 0 {
			return nil
		}

		return ErrInvalidShape
	case FrameData:
		if len(frame.Payload) > 0 {
			return nil
		}

		return ErrInvalidShape
	case FrameWindow:
		_, err := WindowAmount(frame.Payload)

		return err
	default:
		// PING от клиента тоже сюда: признак жизни запрашивает сервер.
		return ErrInvalidShape
	}
}

// ValidateHello проверяет самое первое тело сессии.
//
// Требуется ровно один кадр HELLO на нулевом потоке с нагрузкой [1] - это
// версия протокола. Ничего другого в первом теле быть не должно.
func ValidateHello(input []byte, limits Limits) bool {
	frames, err := ParseAll(input, limits)
	if err != nil {
		return false
	}

	return len(frames) == 1 &&
		frames[0].Type == FrameHello &&
		frames[0].StreamID == 0 &&
		len(frames[0].Payload) == 1 &&
		frames[0].Payload[0] == 1
}

// Encode собирает кадр целиком.
func Encode(frameType FrameType, streamID uint32, payload []byte) []byte {
	out := make([]byte, HeaderBytes+len(payload))
	out[0] = byte(frameType)
	out[1] = byte(streamID >> 16)
	out[2] = byte(streamID >> 8)
	out[3] = byte(streamID)
	binary.BigEndian.PutUint32(out[4:HeaderBytes], uint32(len(payload)))
	copy(out[HeaderBytes:], payload)

	return out
}

// WindowAmount читает прибавку кредита. Нулевая прибавка запрещена: она ничего
// не двигает, но заставляет сервер работать - дешёвый способ занять его ничем.
func WindowAmount(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, ErrInvalidShape
	}

	amount := binary.BigEndian.Uint32(payload)
	if amount == 0 {
		return 0, ErrInvalidShape
	}

	return amount, nil
}

// WindowPayload кодирует прибавку кредита.
func WindowPayload(amount uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, amount)

	return out
}
