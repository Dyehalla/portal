# Portal

Portal соединяет сервисы приложения через аутентифицированный QUIC поверх UDP.
Файлы, управление и будущие сервисы используют независимые надёжные потоки;
виртуальные IP, TUN и пользовательский TCP/IP-стек для этого не нужны.
`net` содержит транспорт Quinn и нативный протокол операций.
`runtime` запускает сервисы и локальный HTTP API на одном Tokio runtime.
`wireguard` сохранён как отдельная библиотека для будущего VPN; runtime сервисов
не запускает WireGuard Device и не зависит от этой библиотеки.

Подробная карта модулей, потоков данных и точек расширения: [docs/CODE_MAP.md](docs/CODE_MAP.md).

## Запуск

```sh
cargo build -p portal-runtime -p portal-cli --release
install -d -m 700 ./portal-state
target/release/portal keygen --private-key-file ./portal-state/device.key
```

`keygen` сохраняет 32-байтный seed Ed25519 с правами 0600 без перезаписи
существующего файла и печатает публичный ключ в hex. Runtime создаёт из него
самоподписанный TLS-сертификат. Обе стороны проверяют зарегистрированные публичные
ключи и TLS-подтверждение владения приватным ключом. Сертификат служит контейнером
ключа: доверие задаётся ключом устройства, а не DNS-именем или публичным CA.
0-RTT выключен. Один endpoint может принимать и инициировать соединения.

Создайте `./portal-state/portal.json`:

```json
{
  "private_key_file": "device.key",
  "listen": "0.0.0.0:51820",
  "api_listen": "127.0.0.1:51821",
  "api_token_file": "api.token",
  "services": [
    {
      "type": "files",
      "root": "share",
      "allowed_downloaders": ["PUBLIC_KEY_OF_READER_HEX"]
    }
  ]
}
```

Создайте общую папку `./portal-state/share`, замените ключ читателя настоящим.
Для устройства без файлового сервиса используйте `services: []`.

```sh
PORTAL_CONFIG=./portal-state/portal.json target/release/portal-runtime
```

Runtime не принимает CLI-команд и аргументов. Без `PORTAL_CONFIG` он читает
`portal.json` в текущем каталоге. Относительные пути разрешаются рядом с JSON-файлом.
Обязательные поля: `private_key_file`, `listen`. Неизвестные поля отклоняются.
UDP `listen` используется всеми QUIC-сервисами и исходящими соединениями.
По умолчанию API слушает 127.0.0.1:51821, token-файл — `portal-UID.token` во
временном каталоге. Для нескольких runtime задайте разные порты и token-файлы.
Runtime-процесс пока поддерживает Linux; транспорт `net` использует переносимый Quinn.

## Регистрация пиров

На обоих устройствах зарегистрируйте публичный ключ другой стороны. Endpoint —
настоящий доступный UDP-адрес, а не виртуальный IP. Для инициатора соединения он
обязателен; принимающей стороне достаточно доверенного ключа.

```sh
target/release/portal peer upsert \
  --token-file ./portal-state/api.token \
  --public-key PEER_PUBLIC_KEY_HEX \
  --endpoint 192.168.1.20:51820
target/release/portal status --token-file ./portal-state/api.token
target/release/portal list --token-file ./portal-state/api.token
```

Доступны также `peer remove`, `endpoint set|clear`, `health`, `services-reload`,
`shutdown`, `stats`, `peer-stats`. Счётчики относятся к активным QUIC-соединениям. Все управляющие команды используют локальный HTTP API, по умолчанию
127.0.0.1:51821. Таблица доверенных пиров хранится в памяти. Изменение или удаление
пира закрывает его текущие QUIC-соединения. Права сервиса задаются отдельно от
доверия к ключу: регистрация пира сама по себе не разрешает чтение файлов.
Обнаружение пиров, NAT traversal и relay пока не реализованы.

## Файлы и веб-интерфейс

Файловый сервис встроен в `portal-runtime` и включается записью `files` в
`services`. Отдельного файлового бинарника нет. Веб-интерфейс обращается к
локальному HTTP API, а runtime выполняет нативную QUIC-операцию на пире.
Браузер не подключается к QUIC endpoint напрямую.

| Локальный HTTP маршрут (POST) | JSON |
|---|---|
| `/api/v1/files/resources` | `{"peer":"PUBLIC_KEY_HEX"}` |
| `/api/v1/files/list` | `{"peer":"PUBLIC_KEY_HEX","path":"","offset":0,"limit":100}` |
| `/api/v1/files/metadata` | `{"peer":"PUBLIC_KEY_HEX","path":"report.pdf"}` |
| `/api/v1/files/download` | `{"peer":"PUBLIC_KEY_HEX","path":"report.pdf"}` |

Нужны `Authorization: Bearer TOKEN` и `Content-Type: application/json`.
Сервер проверяет loopback-источник, Host, Origin и токен. Веб-клиент должен
работать с того же origin. Скачивание возвращает поток с Content-Length и
Content-Disposition; остальные операции — JSON. Ошибка QUIC-соединения даёт 502.
Токен локального API никогда не пересылается пиру.

Например, просмотр каталога из веб-интерфейса на том же origin:

```js
const response = await fetch("/api/v1/files/list", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ peer: peerPublicKey, path: "documents" }),
});
if (!response.ok) throw new Error(`File request failed: ${response.status}`);
const { entries, next_offset } = await response.json();
```

Управляющий API: `POST /api/v1/command`, например `{"operation":"status"}`.
`peer_upsert` принимает `public_key` и необязательный `endpoint`.
Другие операции: `peer_remove`, `endpoint_set`, `endpoint_clear`, `health`,
`list`, `stats`, `peer_stats`, `services_reload`, `shutdown`. Ответ: `{"message":"..."}`.

Файловый сервис публикует один ресурс `files` только для разрешённых ключей.
Пустой путь означает корень. Список сортируется по имени, `limit` — 1–1000,
каталоги более 10000 записей отклоняются с 429. Запись и загрузка не реализованы.
Скачивание открывает файл и отправляет размер, имя и байты в одном QUIC-потоке:
отдельные одноразовые HTTP-билеты больше не нужны. Одновременно допускается
128 файловых скачиваний. Runtime проверяет размер и обрыв потока;
сохранением скачивания на устройстве пользователя управляет веб-клиент.

Абсолютные пути, `..` и симлинки вне общей папки отклоняются.
TODO: устранить кроссплатформенным способом гонку между canonicalize и открытием
файла/каталога. Подмена пути симлинком между проверкой и доступом пока возможна.

## Протокол и сервисы

ALPN: `portal-rpc/1`. Это собственный прикладной протокол поверх стандартного QUIC,
не HTTP/3. Каждая операция использует новый двунаправленный поток одного
переиспользуемого соединения с пиром. Запрос: 4-байтная длина big-endian и JSON
`{"service":"files","operation":"list","payload":{"path":""}}`, затем FIN.
Ответ: такая же рамка с `status`, `length`, `file_name`, затем ровно `length`
байт и FIN. Статусы совпадают с HTTP-кодами для прозрачного локального API.
Достоверная идентичность берётся из TLS; ключ в payload не заменяет её.

Лимиты: запрос 16 КиБ, заголовок ответа 4 КиБ, JSON-ответ 1 МиБ; 32 входящих
двунаправленных потока на соединение, 128 принимаемых соединений, 256 активных
операций на endpoint. Буферы приёма — 1 МиБ на поток, 8 МиБ на соединение.
Подключение, включая ожидание очереди, ограничено 10 секундами, обработка
операции и прогресс передачи — 30 секундами. Клиент ждёт заголовок ответа
до 60 секунд, чтобы получить серверный 504 при таймауте обработчика.
Надёжность, flow control и congestion control обслуживает Quinn.

`RuntimeConfig.services` содержит `ServiceRegistration`. Фабрика получает
`ServiceContext` с сетью и возвращает `ServiceImplementation`: обработчик
`portal_net::Service` и необязательную фоновую задачу. Для добавления другого
сервиса общий сервер менять не требуется. Сервисы сами проверяют свои права.

```rust
config.services.push(portal_runtime::ServiceRegistration::new("example", |_| async {
    let service = portal_net::Service::new("example", |peer, request| async move {
        // Проверить разрешения peer (PeerKey) и параметры request.payload.
        portal_net::Response::json(&serde_json::json!({"ok": true})).unwrap()
    });
    Ok(portal_runtime::ServiceImplementation::new(service))
}));
```

JSON пока знает встроенный сервис `files`; другие типы добавляются в декодер.
Регистрация не является загрузчиком динамических библиотек.

## Перезагрузка

Измените `services` в исходном JSON, затем выполните `portal services-reload`
с обычными `--api` и `--token-file`. HTTP-операция: `services_reload`.
Ответ приходит после переключения. Новые сервисы готовятся до остановки старых;
неверный JSON или недоступная папка оставляют старые сервисы работать.
Переключение закрывает входящие соединения сервисов; следующий запрос открывает
новое QUIC-соединение. Ключ устройства, endpoint, доверенные пиры и локальный API
сохраняются. Для отключения сервисов используйте `services: []`.
Перезагрузка требует `RuntimeConfig.config_path` и восстанавливает список из JSON.
Регистрации, добавленные программно, из JSON не восстанавливаются.

## Потоки и проверки

Локальный API, Quinn, операции и фоновые задачи сервисов используют один Tokio
runtime. Отдельного потока `portal-net` и WG workers в приложении больше нет.
Главный поток управляет жизненным циклом; файлы могут задействовать blocking-пул Tokio.

```sh
cargo test --workspace
cargo test -p portal-net -p portal-files -- --include-ignored
cargo build -p portal-runtime -p portal-cli
python3 runtime/scripts/check-quic.py
```

Сетевые тесты требуют локальных UDP-сокетов. Они проверяют IPv4/IPv6,
независимость потоков, TLS-привязку ключей, отказ неизвестному пиру, отзыв
подключённого пира, файловые права, пути и потоковую передачу 300 КБ.
Проверка двух runtime покрывает файловый HTTP API для веб-клиента, перезагрузку и остановку.

## Миграция с WireGuard + smoltcp

Удалите из JSON `addresses`, `mtu`, `workers`, `handshake_rate_limit`, `dual_stack`
и `peer_http_listen`. `listen` теперь обозначает QUIC UDP endpoint.
В `allowed_downloaders` замените IP-адреса публичными Ed25519-ключами.
Файловые операции доступны через локальный HTTP API; endpoint задаётся в таблице пиров.
WireGuard PSK, keepalive и AllowedIPs больше не относятся к сервисным соединениям.

Публичные ключи теперь Ed25519, а не X25519 WireGuard. Старые публичные ключи
несовместимы: создайте новые ключи через `portal keygen` и зарегистрируйте их
на обоих устройствах. Порты сервиса больше не отделены от порта транспорта.
WireGuard-библиотека остаётся самостоятельной и использует собственные X25519-ключи.
