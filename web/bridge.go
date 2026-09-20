package web

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"strings"
)

//go:embed bridge/runtime.js
var bridgeRuntime string

// bridgeDocument - страница, которую Telegram открывает в вебвью. Ничего
// лишнего: заголовок нейтральный, весь смысл в скрипте.
const bridgeDocument = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
__RUNTIME__
</script>
</body>
</html>
`

// PermissionsPolicy запрещает странице-мосту все возможности браузера: ей
// нужны только сетевые запросы к своему же серверу.
const PermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), " +
	"clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), " +
	"gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), " +
	"picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), " +
	"screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()"

// DefaultBridge собирает страницу-мост с одноразовым токеном.
type DefaultBridge struct{}

// Render возвращает документ и политику, разрешающую ровно один наш скрипт.
//
// Зачем такая узкая политика: страница исполняется в вебвью Telegram, и если
// сервер когда-нибудь начнёт отдавать чужой ответ (подмена, ошибка настройки),
// браузер не должен исполнить ничего, кроме скрипта с нашим одноразовым
// значением nonce. Сетевые запросы разрешены только к своему origin.
func (DefaultBridge) Render(host, bootstrapToken string) (string, string) {
	nonce := randomNonce()

	body := strings.ReplaceAll(bridgeDocument, "__RUNTIME__",
		strings.ReplaceAll(bridgeRuntime, "__TOKEN__", bootstrapToken))
	body = strings.ReplaceAll(body, "__NONCE__", nonce)

	// Политика максимально строгая и обязательно с sandbox.
	//
	// 20.09.2026: во ВСТРОЕННОМ вебвью Telegram (WKWebView) страница получала
	// порт, но клиент не присылал ни одного кадра и закрывал её; во внешнем
	// браузере та же страница работала. Разница с telemt была именно в наборе
	// заголовков и в отсутствии sandbox - приложение пускает трафик в страницу,
	// только если та ограничена по полной.
	csp := strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"child-src 'none'",
		"connect-src 'self'",
		"font-src 'none'",
		"form-action 'none'",
		"frame-ancestors http://127.0.0.1:*",
		"frame-src 'none'",
		"img-src 'none'",
		"manifest-src 'none'",
		"media-src 'none'",
		"object-src 'none'",
		"script-src 'nonce-" + nonce + "'",
		"style-src 'none'",
		"worker-src 'none'",
		"sandbox allow-same-origin allow-scripts",
	}, "; ")

	return body, csp
}

func randomNonce() string {
	var buf [18]byte

	// Ошибка системного генератора означает, что случайности в процессе нет;
	// тогда лучше пустой nonce - страница просто не исполнится, чем
	// предсказуемый, под который можно подставить чужой скрипт.
	if _, err := rand.Read(buf[:]); err != nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(buf[:])
}
