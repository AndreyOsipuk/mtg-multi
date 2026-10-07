// Portions of this file are adapted from telemt (https://github.com/telemt/telemt),
// Copyright (c) 2026 Telemt, licensed under the TELEMT LICENSE 3.3 (see
// web/LICENSE.telemt). This is a modified version, not official Telemt.
// Adapted: the bridge HTML document, the Content-Security-Policy, the
// Permissions-Policy and the nonce format (18 random bytes, base64url).
// Changes: rewritten in Go; the document carries a single script instead of
// telemt's eight; connect-src is 'self' only (no wss:// carrier); the
// diagnostic reporter is put into the page only when diagnostics are enabled.

package web

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"strings"
)

//go:embed bridge/runtime.js
var bridgeRuntime string

// servedRuntime - скрипт в том виде, в каком он уходит в страницу. Заголовок
// с лицензией остаётся в исходнике и в бинаре, но из страницы, отдаваемой
// клиенту, вырезается: копирайт чужого проекта в ответе - лишний признак того,
// кто его отдаёт.
var servedRuntime = stripLeadingComment(bridgeRuntime)

// stripLeadingComment вырезает первый блок строк "//" в самом начале скрипта
// вместе с пустыми строками после него. Больше ничего не трогает: остальные
// комментарии и весь код остаются как есть.
func stripLeadingComment(script string) string {
	rest := script

	for strings.HasPrefix(rest, "//") {
		end := strings.IndexByte(rest, '\n')
		if end == -1 {
			return ""
		}

		rest = rest[end+1:]
	}

	if len(rest) == len(script) {
		return script
	}

	return strings.TrimLeft(rest, "\r\n")
}

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
type DefaultBridge struct {
	// Diag вставляет в страницу отправителя диагностических отметок. Без него
	// страница к диагностике не обращается.
	Diag bool
}

// noReport - отправитель страницы без диагностики.
const noReport = "() => {}"

// diagReport шлёт короткую отметку в диагностику. Отправка ничего не ждёт и
// не мешает работе моста.
const diagReport = `(message) => {
    try {
      fetch(ORIGIN + '/api/v1/diag', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'text/plain' },
        body: message,
        cache: 'no-store',
        credentials: 'omit',
      }).catch(() => {});
    } catch (error) {
      // Диагностика не имеет права мешать работе моста.
    }
  }`

// Render возвращает документ и политику, разрешающую ровно один наш скрипт.
//
// Зачем такая узкая политика: страница исполняется в вебвью Telegram, и если
// сервер когда-нибудь начнёт отдавать чужой ответ (подмена, ошибка настройки),
// браузер не должен исполнить ничего, кроме скрипта с нашим одноразовым
// значением nonce. Сетевые запросы разрешены только к своему origin.
func (b DefaultBridge) Render(host, bootstrapToken string) (string, string) {
	nonce := randomNonce()

	report := noReport
	if b.Diag {
		report = diagReport
	}

	runtime := strings.ReplaceAll(servedRuntime, "__REPORT__", report)
	runtime = strings.ReplaceAll(runtime, "__TOKEN__", bootstrapToken)

	body := strings.ReplaceAll(bridgeDocument, "__RUNTIME__", runtime)
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
