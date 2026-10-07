// Portions of this file are adapted from telemt (https://github.com/telemt/telemt),
// Copyright (c) 2026 Telemt, licensed under the TELEMT LICENSE 3.3 (see
// web/LICENSE.telemt). This is a modified version, not official Telemt.
// Adapted: accepting the port from the parent (the checks of the
// tproxy-init message and of the 127.0.0.1 origin), the Android
// TelegramWebProxy shim and its polling, fail/status/traffic messages to the
// port, the /api/v1/session|up|down paths and the fetch options.
// Changes: a single script instead of telemt's eight modules; the bootstrap
// token is used as the session token (no separate session token); no
// sequence numbers, acks or cursors on /up and /down, no retries and no
// recovery (any failed request ends the bridge), no WebSocket carrier, no
// lanes, no queue limits on the page; the WELCOME frame is passed to
// Telegram as received, without telemt's shape check; the Android shim passes
// a received buffer as is instead of splitting it into frames; free-text
// diagnostic marks, put into the page only when the server enables them,
// instead of telemt's fixed diagnostic events; comments rewritten.

// Мост между Telegram Desktop и нашим HTTP-транспортом.
//
// Страницу открывает сам Telegram в вебвью по ссылке https://<хост>/?bridge=...
// Родитель присылает нам MessagePort сообщением {t:'tproxy-init',v:1}; на
// Android вместо порта появляется объект TelegramWebProxy. Дальше по порту
// ходят кадры (ArrayBuffer) - ровно те же, что мы шлём серверу, - и служебные
// сообщения о состоянии.
//
// Задача скрипта простая: перекладывать кадры из порта в POST /api/v1/up и из
// ответов POST /api/v1/down обратно в порт. Никакой криптографии здесь нет:
// внутри кадров уже обфусцированный MTProto, а снаружи настоящий TLS.
(() => {
  'use strict';

  const ORIGIN = location.origin;
  const TOKEN = '__TOKEN__';
  // Нативный мост приложения передаёт своё одноразовое значение во фрагменте
  // адреса. Оно не уходит на сервер (фрагмент вообще не отправляется), и им
  // страница представляется приложению - без этого оно кадры не шлёт.
  const NATIVE_NONCE = (/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash) || [])[1] || '';
  // Сколько ждём от Telegram первый кадр. Не дождались - мост бесполезен.
  const HELLO_WAIT_MS = 15000;

  let port = null;
  let closed = false;
  let pending = []; // кадры, ожидающие отправки
  let flushing = false;
  let sessionStarted = false; // HELLO от Telegram уже ушёл на сервер
  let sessionReady = false; // сервер ответил WELCOME, можно слать остальное
  let helloTimer = null;

  // Отметки для разбора: во встроенном вебвью Telegram нет консоли, поэтому
  // страница сама рассказывает серверу, докуда дошла. Отправитель сервер
  // вставляет в страницу только при включённой диагностике; иначе report
  // ничего не делает и страница не обращается к диагностике вовсе. Отметки
  // шлются по событиям, а не на каждый кадр данных.
  const report = __REPORT__;

  addEventListener('error', (event) => report('ошибка скрипта: ' + (event.message || '') + ' @' + (event.lineno || '?')));
  addEventListener('unhandledrejection', (event) => report('необработанный отказ: ' + String(event.reason)));
  // Нарушение политики безопасности не приходит в onerror отдельным событием -
  // а во встроенном вебвью это самый вероятный тихий отказ.
  addEventListener('securitypolicyviolation', (event) =>
    report('политика безопасности: нарушено ' + event.violatedDirective + ' на ' + event.blockedURI));

  const headers = () => ({
    'Authorization': 'Bearer ' + TOKEN,
    'Content-Type': 'application/octet-stream',
  });

  const status = (state) => {
    if (port && !closed) {
      try {
        port.postMessage({ t: 'status', state });
      } catch (error) {
        // Родитель мог уже уйти - это не повод падать.
      }
    }
  };

  const fail = () => {
    if (closed) return;
    closed = true;
    status('failed');

    try {
      if (port) port.postMessage({ t: 'close' });
    } catch (error) {
      // см. выше
    }

    try {
      if (port) port.close();
    } catch (error) {
      // см. выше
    }
  };

  const post = async (path, body) => {
    const response = await fetch(ORIGIN + path, {
      method: 'POST',
      headers: headers(),
      body: body ?? new Uint8Array(0),
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      // Тело ответа читаем целиком сами, поток не нужен.
      keepalive: false,
    });

    if (!response.ok) throw new Error('bad status ' + response.status);

    const type = response.headers.get('Content-Type') || '';
    // Сервер отвечает заглушкой (HTML), когда считает нас чужими. Это конец
    // сессии, а не временный сбой: повтор только добавит шума.
    if (!type.startsWith('application/octet-stream')) throw new Error('not a carrier response');

    return new Uint8Array(await response.arrayBuffer());
  };

  // Кадры от клиента копим и отправляем пачкой: один POST на каждый мелкий
  // кадр превратил бы обычную переписку в поток запросов.
  const flush = async () => {
    if (flushing || closed || !sessionReady) return;
    flushing = true;

    try {
      while (pending.length > 0 && !closed) {
        const batch = pending;
        pending = [];

        let total = 0;
        for (const frame of batch) total += frame.length;

        const body = new Uint8Array(total);
        let offset = 0;

        for (const frame of batch) {
          body.set(frame, offset);
          offset += frame.length;
        }

        await post('/api/v1/up', body);

        if (port) port.postMessage({ t: 'traffic', up: total, down: 0 });
      }
    } catch (error) {
      fail();
    } finally {
      flushing = false;
    }
  };

  // Длинный опрос: сервер придерживает ответ, пока данных нет, поэтому цикл не
  // крутится вхолостую.
  const pump = async () => {
    while (!closed) {
      let body;

      try {
        body = await post('/api/v1/down', null);
      } catch (error) {
        fail();

        return;
      }

      if (closed) return;

      if (body.length > 0) {
        const buffer = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength);

        try {
          port.postMessage(buffer, [buffer]);
          port.postMessage({ t: 'traffic', up: 0, down: body.length });
        } catch (error) {
          fail();

          return;
        }

        status('connected');
      }
    }
  };

  // Сессию открывает ПЕРВЫЙ кадр от Telegram - это его собственный HELLO.
  //
  // Свой HELLO слать нельзя: Telegram ждёт ответа именно на своё рукопожатие.
  // Проверено на ноде 20.09.2026 - при подставном HELLO клиент получал WELCOME
  // не на свой кадр, считал мост нерабочим, рвал длинный опрос и начинал всё
  // заново каждые две секунды (в логе nginx: session 200, down 499, и ни одного up).
  const startSession = async (hello) => {
    let welcome;

    try {
      welcome = await post('/api/v1/session', hello);
    } catch (error) {
      fail();

      return;
    }

    if (closed) return;

    if (welcome.length > 0) {
      const buffer = welcome.buffer.slice(welcome.byteOffset, welcome.byteOffset + welcome.byteLength);

      try {
        port.postMessage(buffer, [buffer]);
      } catch (error) {
        fail();

        return;
      }
    }

    sessionReady = true;
    status('connecting');
    pump();
    flush(); // кадры, пришедшие пока шло рукопожатие
  };

  const activate = (activePort) => {
    if (port || closed) return;

    port = activePort;

    port.onmessage = (event) => {
      const data = event.data;
      // Только первый кадр (HELLO от Telegram) и служебные сообщения: отметка
      // на каждый кадр данных удвоила бы число запросов.
      if (!sessionStarted || !(data instanceof ArrayBuffer)) {
        report('кадр из порта: тип=' + Object.prototype.toString.call(data) +
          ' размер=' + (data && (data.byteLength ?? data.length ?? '?')));
      }

      if (data instanceof ArrayBuffer) {
        if (!sessionStarted) {
          sessionStarted = true;

          if (helloTimer) {
            clearTimeout(helloTimer);
            helloTimer = null;
          }

          startSession(new Uint8Array(data));

          return;
        }

        pending.push(new Uint8Array(data));
        flush();

        return;
      }

      if (data && typeof data === 'object' && data.t === 'close') fail();
    };

    if (typeof port.start === 'function') port.start();

    report('порт принят, жду первый кадр');
    status('connecting');
    report('состояние connecting отправлено');
    helloTimer = setTimeout(() => {
      report('первый кадр так и не пришёл');
      fail();
    }, HELLO_WAIT_MS);
  };

  // Рабочий стол: порт приходит сообщением от родителя. Проверяем отправителя
  // строго - страница обязана принимать порт только от самого Telegram,
  // который держит свой сервер на localhost.
  addEventListener('message', (event) => {
    report('сообщение: origin=' + event.origin + ' от_родителя=' + (event.source === parent) +
      ' портов=' + ((event.ports && event.ports.length) || 0) +
      ' данные=' + (event.data && typeof event.data === 'object' ? JSON.stringify(event.data) : String(event.data)));

    if (event.source !== parent || port || closed) return;

    const data = event.data;
    if (data === null || typeof data !== 'object') return;

    const keys = Object.keys(data).sort();
    if (keys.length !== 2 || keys[0] !== 't' || keys[1] !== 'v') return;
    if (data.t !== 'tproxy-init' || data.v !== 1) return;
    if (!event.ports || event.ports.length !== 1) return;

    let source;

    try {
      source = new URL(event.origin);
    } catch (error) {
      return;
    }

    if (source.protocol !== 'http:' || source.hostname !== '127.0.0.1' || !source.port) return;
    if (source.origin !== event.origin) return;

    activate(event.ports[0]);
  });

  // Нативный мост приложения: порта нет, вместо него объект с тем же смыслом.
  //
  // Так работает ВСТРОЕННЫЙ вебвью - и на Android, и на macOS (проверено
  // 20.09.2026: во встроенном вебвью события message с портом не приходит
  // вовсе, только этот объект). Появляется он не мгновенно, поэтому недолго
  // опрашиваем. Без значения из фрагмента адреса подключаться нельзя: оно
  // и есть доказательство, что страница та самая.
  const discoverNative = () => {
    if (!NATIVE_NONCE) {
      report('нативный мост: значения во фрагменте адреса нет, жду порт от родителя');

      return;
    }

    const deadline = Date.now() + 10000;

    const probe = () => {
      if (port || closed) return;

      const androidBridge = globalThis.TelegramWebProxy;

      if (androidBridge && typeof androidBridge.postMessage === 'function') {
        const shim = {
          onmessage: null,
          start() {},
          close() {
            androidBridge.onmessage = null;
          },
          postMessage(value) {
            if (value instanceof ArrayBuffer) androidBridge.postMessage(value);
            else androidBridge.postMessage(JSON.stringify(value));
          },
        };

        androidBridge.onmessage = (event) => {
          let data = event.data;

          if (typeof data === 'string') {
            try {
              data = JSON.parse(data);
            } catch (error) {
              return;
            }
          }

          if (shim.onmessage) shim.onmessage({ data });
        };

        activate(shim);

        // Представляемся приложению: пока оно не получит своё значение
        // обратно, кадры не пойдут и страницу закроют.
        androidBridge.postMessage(JSON.stringify({ t: 'tproxy-android-init', v: 1, nonce: NATIVE_NONCE }));
        report('нативный мост: представились приложению');

        return;
      }

      if (Date.now() < deadline) setTimeout(probe, 100);
    };

    probe();
  };

  discoverNative();
  report('страница запущена: ' + navigator.userAgent + ' | нативное значение: ' + (NATIVE_NONCE ? 'есть' : 'нет'));

  addEventListener('pagehide', () => {
    report('страница закрывается');
    fail();
  }, { once: true });
})();
