# httptoolkit-mcp

MCP-сервер для перехвата и мокинга HTTP(S)-трафика. Построен на **Mockttp** -
том же движке, что и HTTP Toolkit, - поэтому самому десктоп-приложению он не
нужен: MCP сам поднимает перехватывающий proxy. Заточен под Android-эмуляторы
(Nox, MEmu, BlueStacks, LDPlayer) и настройку **только через adb**.

## Что умеет

- **Перехват** HTTP(S) через свой Mockttp-proxy (стабильный CA между перезапусками).
- **Разбор обмена**: request/response заголовки, request/response **cookies**,
  тело в форматах **text / json / hex / protobuf / base64**.
- **Глубокий protobuf-реверс** (для «грязных» API типа Spotify/YouTube): schema-less
  декод, который держит **все трактовки поля сразу** (вложенное сообщение / строка /
  байты), **авто-распаковка вложенных** gzip/zlib/zstd-блобов с рекурсивным декодом,
  снятие **gRPC**-framing, JSON-дерево для автоматизаций и **diff** двух сообщений по
  путям полей (чтобы видеть, что меняется: курсоры, токены, id).
  - **Spotify** - бинарный protobuf в теле (часто со сжатыми под-полями).
  - **YouTube/InnerTube** - JSON по HTTPS, где токены (`continuation`, `params`,
    `clickTrackingParams`) - это **base64url-protobuf внутри строк**. Декодер
    принимает base64url на входе и **сам разворачивает** такие токены, в т.ч.
    многослойные; `protobuf_diff` сравнивает их внутренности по путям.
- **Правила**: мок-ответы, инъекция ошибок (reset/timeout/close), задержки,
  редиректы, модификация заголовков/тела запроса.
- **Анализ/экспорт**: фильтр, полнотекстовый поиск, экспорт **HAR** и импорт HAR
  (например, из самого HTTP Toolkit) для анализа в Claude.
- **adb-автоматизация**: установка CA в **системное** хранилище и проброс прокси
  без UI, с автодетектом root-режима и пресетами портов эмуляторов. Поддержка
  Android **7/9** (прямая запись), **10-13** (tmpfs-overlay), **14** (APEX
  `conscrypt` + namespace-наложение).
- **Прозрачный перехват** через `iptables` DNAT - весь TCP :80/:443 уходит на
  прокси без компаньон-приложения и без VPN-диалога (adb-аналог VPN-режима HTTP
  Toolkit). Mockttp определяет цель по Host/SNI.
- **WebSocket**: перехват ws/wss, сообщения обоих направлений (sent/received) с
  телом в любом формате (включая protobuf) + код/причина закрытия.

## Установка

```bash
npm install
npm run build
```

Требуется `openssl` в PATH (для вычисления `subject_hash_old` имени системного серта).

## Подключение к Claude Desktop

В `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "httptoolkit": {
      "command": "node",
      "args": ["/absolute/path/to/httptoolkit_mcp/dist/index.js"],
      "env": {
        "HTMCP_ADB_PATH": "/path/to/adb"
      }
    }
  }
}
```

Переменные окружения:

- `HTMCP_ADB_PATH` - путь к adb. Можно не задавать: сервер сам ищет adb от
  Nox/MEmu/BlueStacks/LDPlayer/Genymotion/Android SDK, затем `adb` из PATH.
- `HTMCP_CERT_DIR` - где хранить CA (по умолчанию `./certs`).

## Типовой сценарий (эмулятор)

1. `proxy_start` - поднять proxy (по умолчанию порт 8000). В ответе будут
   локальные IP машины.
2. `adb_connect` с пресетом (`nox` / `memu` / `bluestacks` / `ldplayer`) или
   `host:port`. Список - `list_emulator_presets`.
3. Настройка устройства одним вызовом - на выбор:
   - `adb_setup_transparent` (`hostIp`, `port`) - **рекомендуется**: ставит CA и
     включает прозрачный iptables-перехват (ловит всё, без диалогов).
   - `adb_setup` - то же, но через системный `http_proxy` (проще, но ловит
     только приложения, уважающие proxy).
   Перезагрузи эмулятор/приложение, если серт не подхватился.
4. Гоняй трафик в эмуляторе -> `list_traffic`, `search_traffic`, `get_exchange`
   (с `bodyFormat: protobuf` для protobuf-API), `export_har`.
5. Мокинг: `add_mock_rule`, `add_error_rule`, `add_delay_rule`,
   `add_redirect_rule`, `add_modify_request_rule`.

## Про «без root» - честно

Запись системного сертификата **в принципе требует root-привилегий** на уровне
ОС: писать в `/system/etc/security/cacerts/` (или накладывать туда tmpfs)
нельзя без root-доступа. Фокус в том, что **на эмуляторах этот доступ даётся
через adb без установки Magisk**:

- **Nox / MEmu** - `adbd` уже работает как root, `adb root` проходит из коробки.
- **BlueStacks / LDPlayer** - включи тумблер **Root** в настройках эмулятора,
  дальше работает `su` (Magisk не нужен).
- **AOSP/Genymotion** - `google_apis`-образы пускают `adb root`; `Google Play`-образы - нет.

То есть «чисто на adb, без Magisk» - да; но adb должен иметь root-доступ,
который эмулятор предоставляет сам. Установщик автоматически выбирает режим
(`adb root` -> прямая запись на Android 7/9; `su` + tmpfs-overlay на 10/11/12).

> **Системный** серт лучше user-серта не только тем, что ему доверяют все
> приложения, но и тем, что **анти-MITM проверки user-store его не видят**.

## Классификатор блобов

`classify_blob` по неизвестным байтам (тело обмена или вставленный hex/base64)
говорит, что это: энтропия + magic-байты + пробы JSON/protobuf/base64/gRPC.
Главное - он сразу отсекает **то, что декодировать бессмысленно**: высокоэнтропийный
шифротекст. Подсказывает следующий шаг (`decode_protobuf`, распаковка, base64).

## Шифрованные транспорты (WhatsApp и т.п.) - не декодируются

Если приложение шифрует трафик **на своём уровне** (WhatsApp: Noise Protocol +
Signal E2E), пассивный MITM-перехват - даже с нашим системным CA - даёт только
**шифротекст**. Это не «непонятный формат», а данные на ключах, которых у прокси
нет. `classify_blob` помечает такой трафик прямо.

Декодировать его перехватом нельзя в принципе. Рабочий путь - **стать клиентом**
(реализация протокола: Baileys/whatsmeow - pairing по QR, свои Noise/Signal
ключи), что является отдельным классом задач и в этот MITM-инструмент не входит.
Frida/root-хук на расшифрованные функции отпадает: integrity-аттестация на
регистрации палит и root, и эмулятор, и сам системный CA.

## Ограничение: pinning

Если приложение **жёстко пинит** сертификат (хардкод в коде), системный CA не
поможет - нужен Frida/патч APK, что вне adb-only сценария. Но приложения,
полагающиеся на системный trust-store (Яндекс.Музыка, YouTube и большинство
обычных), перехватываются полностью.

## Реверс protobuf-API (например, Spotify)

Сценарий «дать Claude глаза», чтобы он собрал понимание API для автоматизации:

1. Перехвати мобильный трафик (`adb_setup_transparent`) - у мобильного API чистый
   protobuf/JSON и меньше анти-фрод триггеров, чем у web/desktop.
2. `list_traffic` / `search_traffic` -> найди нужный запрос.
3. `decode_protobuf` `{ id, side: "response", output: "json" }` - получишь дерево,
   где у каждого поля видны **все** трактовки (message/string/bytes) и распакованные
   gzip/zstd-вложения. Для gRPC добавь `grpc: true`.
4. Сделай два похожих запроса (например, разные страницы/треки) и
   `protobuf_diff` `{ a, b, side: "response" }` - увидишь, какие поля меняются
   (курсоры, токены, id), а какие постоянны. Это и есть карта для автоматизации.
5. Проверяй гипотезы запросов через `add_modify_request_rule` / `add_mock_rule`.

## Тесты

```bash
npm run build && node test/smoke.mjs        # ядро: перехват, правила, HAR, cookies
node test/ws-smoke.mjs                        # WebSocket-перехват сквозь прокси
node test/protobuf-smoke.mjs                  # protobuf: gzip-вложения, gRPC, diff, base64url-токены
node test/classify-smoke.mjs                  # классификатор: JSON/protobuf/gzip/шифротекст
node test/mcp-handshake.mjs                  # MCP stdio handshake + tools/list
```

## Инструменты (33)

Прокси: `proxy_start`, `proxy_stop`, `proxy_status`, `get_ca_certificate`.
Трафик: `list_traffic`, `search_traffic`, `get_exchange`, `get_ws_messages`,
`get_body`, `clear_traffic`, `export_har`, `import_har`.
Protobuf: `decode_protobuf`, `protobuf_diff`, `classify_blob`.
Правила: `add_mock_rule`, `add_error_rule`, `add_delay_rule`,
`add_redirect_rule`, `add_modify_request_rule`, `list_rules`, `remove_rule`,
`clear_rules`.
ADB/устройство: `adb_devices`, `adb_connect`, `list_emulator_presets`,
`adb_install_cert`, `adb_set_proxy`, `adb_clear_proxy`, `adb_setup`,
`adb_enable_transparent`, `adb_disable_transparent`, `adb_transparent_status`,
`adb_setup_transparent`.
