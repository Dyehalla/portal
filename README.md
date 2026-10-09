# portal

`portal` — библиотека для встраивания WireGuard-сетей в приложение виртуальных сетей. Публичная единица управления — `Device`: он владеет каналом IP-пакетов, UDP-портом, списком пиров и worker-потоками.

Протокол и криптография основаны на BoringTun 0.7.1. Небольшой локальный fork в `wireguard/vendor/boringtun` добавляет типизированную границу между разбором входящего пакета, проверкой MAC/cookie на уровне устройства и обработкой состояния туннеля.

## Публичный API

Библиотека экспортирует `Device`, типы конфигурации и статистики, а также `PeerKey` и `AllowedIp`:

```rust
use portal::{AllowedIp, Device, DeviceConfig, PeerConfig, PeerKey};
use std::time::Duration;

fn run(device_key: PeerKey, peer_key: PeerKey) -> Result<(), Box<dyn std::error::Error>> {
    // Ключи — 32 байта в сыром формате WireGuard; приложение загружает их из своей конфигурации.
    let mut config = DeviceConfig::new(
        device_key,
        "0.0.0.0:51820".parse()?,
    );
    config.workers = 4;
    // По умолчанию также включены dual_stack и лимит рукопожатий 100 в секунду.

    let mut device = Device::new(config)?;
    let allowed_ip: AllowedIp = "10.20.0.0/24".parse()?;
    device.upsert_peer(PeerConfig {
        public_key: peer_key,
        preshared_key: None,
        endpoint: Some("198.51.100.10:51820".parse()?),
        persistent_keepalive: Some(Duration::from_secs(25)),
        allowed_ips: vec![allowed_ip],
    })?;

    // Здесь приложение использует устройство.
    device.shutdown()?;
    Ok(())
}
```

### Устройство

`DeviceConfig::new(private_key, listen)` задаёт приватный ключ и UDP-адрес прослушивания. Адрес с портом `0` просит ОС выбрать свободный порт; фактический адрес возвращает `Device::listen_addr()`. Конфигурацию можно настроить до вызова `Device::new()` через публичные поля:

- `dual_stack` — привязать wildcard-сокет для второго семейства IP на том же порту; включено по умолчанию.
- `workers` — число packet worker-потоков. По умолчанию используется число доступных CPU (не более 256); допустимо от 1 до 256.
- `handshake_rate_limit` — порог рукопожатий в секунду до запроса cookie; по умолчанию 100.

`Device::new(config)` открывает внутренний канал IP-пакетов и UDP-сокеты и запускает worker-потоки. `public_key()` возвращает открытый ключ устройства. `health()` сообщает об остановке устройства или ошибке worker-потока. `shutdown()` будит и дожидается завершения потоков; повторный вызов безопасен, а `Drop` также вызывает остановку.

### Пиры и маршруты

`PeerConfig` описывает `public_key`, необязательные `preshared_key`, `endpoint` и `persistent_keepalive`, а также список `allowed_ips`. Keepalive задаётся целым числом секунд от 1 до 65535. `upsert_peer()` добавляет пира или обновляет его конфигурацию и маршруты. При обновлении `endpoint: None` сохраняет уже установленный endpoint; чтобы удалить его, вызовите `clear_peer_endpoint()`. `set_peer_endpoint()` задаёт или меняет endpoint. `remove_peer()` удаляет пира вместе с его маршрутами.

`AllowedIp` можно создать через `AllowedIp::new(ip, prefix_len)` или разобрать из строки, например `"10.20.0.0/24"`. Адрес сети нормализуется обнулением host-битов. Методы `network()`, `prefix_len()` и `contains(ip)` позволяют читать и проверять префикс. Эти маршруты используются библиотекой для выбора пира для исходящего IP-пакета и проверки адреса источника расшифрованного входящего пакета. Для совпадающих префиксов действует один владелец; для разных префиксов выбирается наиболее специфичный.

Если для пира ожидает отправки рукопожатие, установка endpoint может инициировать его отправку. Такие отправки выполняются по возможности: ошибки учитываются в `DeviceStats::udp_send_errors`.

### Статистика и ошибки

`stats()` возвращает общие счётчики `DeviceStats`: принятые UDP- и внутренних IP-пакетов, отброшенные пакеты, ошибки отправки таймерных пакетов и прочих UDP-пакетов. `peer_stats(&key)` возвращает `PeerStats` конкретного пира. Счётчики `tx_packets`/`tx_bytes` отражают внутренние IP-пакеты, принятые BoringTun к отправке, а `rx_packets`/`rx_bytes` — аутентифицированные расшифрованные пакеты, успешно переданные пользовательскому стеку; `tx` не подтверждает доставку удалённой стороной.

Методы управления возвращают `DeviceError`: среди вариантов — некорректные параметры, отсутствие пира, исчерпание индексов, остановка устройства, ошибка ввода-вывода или сбой worker-потока. Ошибку разбора префикса представляет `AllowedIpParseError`.

## Пользовательская сеть

Модуль `net` (`portal-net`) содержит пользовательский TCP/IP-стек на smoltcp,
виртуальные TCP listener/stream и адаптеры HTTP для Axum и Hyper.
`Device::packet_port()` соединяет стек с WireGuard: исходящие IP-пакеты
шифруются для выбранного пира, входящие проходят проверку ключа и AllowedIPs.

Runtime назначает виртуальные адреса только этому стеку. Системные интерфейсы,
адреса и маршруты не создаются; root, TUN и iproute2 для запуска не нужны.
Сервисы приложения используют `Net::listen` и `Net::connect`. Сейчас реализован
TCP по IPv4 и IPv6; прикладные UDP-сокеты и VPN ещё не реализованы.
Транспортный backend WireGuard пока поддерживает Linux.

Стек ограничен 128 TCP-сокетами и буферами по 64 КиБ на направление.
Внутренний канал пакетов ограничен буферами ОС; при перегрузке пакеты могут
отбрасываться, TCP выполняет повторную передачу. Статистика доступна через
`Net::dropped_packets()`. При остановке закрываются listener и соединения.

```sh
cargo test -p portal-net -- --include-ignored
```

Тесты связывают два WireGuard-устройства через локальный UDP и проверяют
передачу 300 КБ по виртуальному TCP для IPv4 и IPv6 без TUN.

## Runtime и CLI

`portal-runtime` — отдельный foreground daemon: он владеет `Device` и
пользовательским стеком `Net`. `portal-cli` — отдельный бинарник `portal`, который управляет
локальным runtime через HTTP API на loopback-адресе. API предназначен для CLI и
веб-клиента; прикладной HTTP API между пирами отдельно от управления
локальным `Device`.

```sh
cargo build -p portal-runtime -p portal-cli --release
install -d -m 700 ./portal-state
target/release/portal keygen --private-key-file ./portal-state/device.key
cat > ./portal-state/portal.json <<'EOF'
{
  "private_key_file": "device.key",
  "listen": "0.0.0.0:51820",
  "api_listen": "127.0.0.1:51821",
  "api_token_file": "api.token",
  "addresses": ["10.20.0.1/32"],
  "mtu": 1420
}
EOF
PORTAL_CONFIG=./portal-state/portal.json target/release/portal-runtime
```

Runtime не принимает CLI-команд и аргументов. Он читает JSON из `PORTAL_CONFIG`
или `portal.json` в текущем каталоге. Относительные пути разрешаются относительно
файла конфигурации. Обязательные поля: `private_key_file`, `listen`, `addresses`.
Дополнительно: `mtu` (1420), `workers`, `handshake_rate_limit`, `dual_stack` (true),
`api_listen` (127.0.0.1:51821), `api_token_file`, `peer_http_listen`, `files`.
Неизвестные поля отклоняются. Генерация ключа находится в отдельном CLI.

`keygen` создаёт raw-файл приватного ключа с режимом `0600` и печатает открытый
ключ в hex. `portal-runtime` запускает WireGuard и пользовательский стек с указанными
виртуальными адресами и MTU, затем слушает локальный HTTP API только на loopback. Случайный bearer-
токен записывается в файл с режимом `0600` и удаляется при штатной остановке.
Для веб-клиента токен можно прочитать с правами владельца runtime и передать в
`Authorization: Bearer ...`; не встраивайте его в общедоступные frontend-файлы.
Runtime остаётся отдельным процессом. CLI обращается к тому же API, что и веб-клиент:

```sh
target/release/portal peer upsert \
  --api 127.0.0.1:51821 \
  --token-file ./portal-state/api.token \
  --public-key PUBLIC_KEY_HEX \
  --endpoint 198.51.100.10:51820 \
  --keepalive 25 \
  --allowed-ip 10.20.0.2/32
target/release/portal status --api 127.0.0.1:51821 --token-file ./portal-state/api.token
target/release/portal peer-stats \
  --api 127.0.0.1:51821 \
  --token-file ./portal-state/api.token \
  --public-key PUBLIC_KEY_HEX
target/release/portal shutdown --api 127.0.0.1:51821 --token-file ./portal-state/api.token
```

API v1 принимает `POST /api/v1/command` с JSON-телом `{"operation":"status"}` и
заголовком `Authorization: Bearer <token>`. Доступны операции `peer_upsert`,
`peer_remove`, `endpoint_set`, `endpoint_clear`, `status`, `health`, `stats`,
`peer_stats`, `list` и `shutdown`. Например, веб-клиент может отправить ту же
команду через `fetch` с bearer-токеном:

```js
const response = await fetch("http://127.0.0.1:51821/api/v1/command", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ operation: "status" }),
});
const result = await response.json();
```

Для `peer_upsert` тело содержит `public_key`, необязательные `preshared_key`,
`endpoint`, `keepalive_seconds` и массив строк `allowed_ips`. Другие операции:
`peer_remove`, `endpoint_set`, `endpoint_clear`, `peer_stats`, `status`, `health`,
`stats`, `list` и `shutdown`; ключи задаются 64 символами hex.
Ошибки возвращают HTTP-статус и JSON `{"message":"..."}`. Браузерный клиент
должен работать с того же origin; listener нельзя переносить на публичный или
туннельный интерфейс.

Также доступны `peer remove`, `endpoint set|clear`, `list`, `stats` и `health`.
`AllowedIPs` задают выбор пира и проверку источника внутри WireGuard.
Конфигурация пиров хранится в памяти; после перезапуска их нужно добавить снова.
`upsert` заменяет `preshared_key` и `persistent_keepalive`; если PSK не передан,
он сбрасывается. По умолчанию файл API-токена находится в системном временном
каталоге под именем `portal-UID.token`; несколько runtime одного пользователя
должны использовать разные `api_token_file` и `api_listen`.

## Передача файлов между пирами

`portal-files` — прикладной сервис поверх настроенной WireGuard-сети.
HTTP + JSON проверяет доступ пира, выдаёт одноразовые билеты на скачивание и
метаданные файлов и папок. Этот же HTTP-listener передаёт байты файлов.
Трафик защищает WireGuard; listener работает на виртуальном IP внутри `Net`.
Контракт JSON описан типами в `files/src/models.rs`, маршруты — в `files/src/api.rs`.
Для сборки достаточно Rust toolchain.

```sh
cargo build -p portal-runtime -p portal-files --release
```

Файловый сервис запускает `portal-runtime` вместе с Device. На пире `10.20.0.1` добавьте в JSON-конфигурацию runtime:

```json
{
  "peer_http_listen": "10.20.0.1:8080",
  "files": {
    "root": "share",
    "allowed_downloaders": ["10.20.0.2"]
  }
}
```

С другого разрешённого пира запросите файл по относительному пути внутри
`./share` и укажите локальное имя для результата:

```sh
target/release/portal-files download \
  --peer PUBLIC_KEY_HEX --api-token-file ./portal-state/api.token \
  --path documents/report.pdf \
  --output ./report.pdf
```

CLI и веб-интерфейс обращаются к локальному runtime, который отправляет HTTP
запросы пиру через пользовательский стек. Обычный системный `curl` не имеет
доступа к виртуальным адресам; используйте локальный API, описанный ниже.
На обоих устройствах должны быть зарегистрированы ключи и точные AllowedIPs
друг друга (`/32` для IPv4 или `/128` для IPv6).

`POST /v1/downloads` возвращает `download_url`, `file_name`, `size_bytes` и
`expires_at_unix_seconds`. `GET /v1/download/:ticket` отдаёт файл один раз тому же
пиру. Ошибки авторизации — HTTP 403, неверный путь — 400, отсутствующий файл — 404,
переполнение лимита — 429, недоступный путь — 404. Ошибки прикладных обработчиков
имеют JSON `{"error":"..."}`; некорректный JSON/Content-Type отклоняет HTTP framework.

Сервис отклоняет абсолютные пути и `..`, а также проверяет, что разрешённый
симлинк остаётся внутри корневой папки.
TODO: устранить гонку между проверкой пути и открытием файла кроссплатформенным
способом: подмена файла или родительской директории симлинком в этот промежуток
может привести к чтению вне общей папки.

Билеты действуют пять минут и очищаются раз в секунду. Одновременно допускается
128 билетов и активных скачиваний в сумме. Клиент ограничивает подключение десятью
секундами, согласование и ожидание HTTP-ответа — тридцатью; скачивание прерывается после
тридцати секунд без новых данных, а частичный файл удаляется. При остановке runtime
даёт серверам пять секунд на завершение, затем отменяет оставшиеся соединения.

Разрешение пока задаётся целиком на
скачивание по туннельному IP; адрес пира должен быть закреплён за его WireGuard
ключом через `AllowedIPs`. Peer HTTP-listener открывается только внутри пользовательского стека. В этой версии реализовано скачивание; загрузка и права
на отдельные файлы пока не входят в контракт.


## HTTP API файлового проводника

Файловый сервис работает только через HTTP поверх WireGuard. Он публикует один
ресурс `files`, соответствующий `files.root`. Локальный путь сервера не раскрывается.
Разрешение `files.allowed_downloaders` теперь включает просмотр и чтение файлов.
Запись, загрузка, переименование и удаление пока не реализованы.

Peer API:

| Метод и маршрут | Запрос | Результат |
|---|---|---|
| GET `/v1/resources` | — | Разрешённые ресурсы: `id`, `name`, `read_only` |
| POST `/v1/files/list` | `{"path":"","offset":0,"limit":100}` | `path`, `entries`, `next_offset` |
| POST `/v1/files/metadata` | `{"path":"report.pdf"}` | Имя, относительный путь, тип, размер, время изменения |
| POST `/v1/downloads` | `{"path":"report.pdf"}` | Одноразовый URL и параметры скачивания |
| GET `/v1/download/:ticket` | — | Поток байтов файла |

Пустой путь означает корень общей папки. Пагинация сортирует записи по имени;
`limit` — 1–1000, по умолчанию 100. Каталоги более 10000 записей отклоняются с 429.
`next_offset` равен null на последней странице. Между запросами каталог может измениться.
Типы записей: `file`, `directory`, `symlink`, `other`. Имена должны быть UTF-8.
Симлинки в списке не раскрывают метаданные своей цели; переход и чтение проверяют
принадлежность цели общей папке. Сохраняется описанный выше TODO о гонке файловых путей.

CLI использует peer API через локальный runtime:

```sh
portal-files resources --peer PUBLIC_KEY_HEX --api-token-file ./portal-state/api.token
portal-files ls --peer PUBLIC_KEY_HEX --api-token-file ./portal-state/api.token --path documents --limit 100
portal-files stat --peer PUBLIC_KEY_HEX --api-token-file ./portal-state/api.token --path documents/report.pdf
```

Локальный API для веб-интерфейса принимает POST на:

```text
/api/v1/files/resources
/api/v1/files/list
/api/v1/files/metadata
/api/v1/files/download
```

Нужны `Authorization: Bearer TOKEN` и `Content-Type: application/json`, как для
`/api/v1/command`. Браузер должен использовать тот же origin, что локальный API.
JSON содержит `peer` — публичный ключ зарегистрированного пира, `port` — порт его
HTTP API (по умолчанию 8080), и поля выбранной операции. Например:

```json
{"peer":"PUBLIC_KEY_HEX","port":8080,"path":"documents","offset":0,"limit":100}
```

Адрес выбирается из точного host AllowedIP пира (`/32` или `/128`). Если таких
адресов несколько, добавьте `tunnel_ip`, совпадающий с одним из них. Произвольные URL,
незарегистрированные пиры и только сетевые префиксы не принимаются. Удалённый пир
должен разрешить туннельный IP запрашивающего runtime. Локальный bearer token пиру
не пересылается. Runtime освобождает блокировку своего состояния перед сетью.

`/api/v1/files/download` сразу возвращает поток файла с `Content-Disposition`;
браузер вызывает его через fetch с заголовком авторизации. Peer-билет получает и
использует сам runtime. Удалённые ошибки сохраняют HTTP status, ошибки соединения
дают 502. Скачивание ограничивает ожидание данных, проверяет объявленный размер и
не загружает весь файл в память. Локальный сервер ограничивает завершение пятью секундами.

Проверка HTTP API на loopback:

```sh
cargo test -p portal-files -- --include-ignored
```

Она проверяет чтение, browsing API, транспортные разрешения, запрет подмены IP,
одноразовость билетов и потоковую пересылку для веб-интерфейса. Отдельный тест
проверяет просмотр и скачивание 300 КБ через два WireGuard-устройства и `Net`.

Проверка двух runtime и файлового CLI без root:

```sh
cargo build -p portal-runtime -p portal-cli -p portal-files
python3 runtime/scripts/check-userspace.py
```
