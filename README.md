# portal

`portal` — библиотека для встраивания WireGuard-интерфейсов в приложение виртуальных сетей. Публичная единица управления — `Device`: он владеет интерфейсом, UDP-портом, списком пиров и worker-потоками.

Протокол и криптография основаны на BoringTun 0.7.1. Небольшой локальный fork в `wireguard/vendor/boringtun` добавляет типизированную границу между разбором входящего пакета, проверкой MAC/cookie на уровне устройства и обработкой состояния туннеля.

Проект сейчас содержит только сетевую основу: WireGuard, TUN, маршруты и
локальный API управления, а также отдельный HTTPS-координатор. Прикладные сервисы
удалены. Runtime подключён к HTTPS-координатору: регистрация, карты сети,
локальные TCP-разрешения, сроки действия и P2P-согласование. P2P discovery,
hole punching, реле и exit nodes ещё предстоит реализовать.
Запуск агента: [управляемый runtime](docs/RUNTIME.md).

Веб-панель агента доступна на `http://127.0.0.1:51821/`: состояние устройства,
пиры, TCP-разрешения, статистика и P2P-запрос. Вход выполняется токеном локального
API из `api_token_file`; отдельная сборка фронтенда не требуется.
Команда `sudo target/release/portal web` печатает готовую ссылку для входа,
чтобы не копировать токен вручную.
Последовательность работ: [план сетевой составляющей](docs/NETWORK_PLAN.md).

В workspace пять частей: `wireguard/` — библиотека `Device`, `runtime/` — сетевой
агент и операции Linux, `cli/` — диагностический клиент локального API,
`net/` — общие модели, HTTPS-клиент и компиляция политик;
`coordinator/` — HTTPS API регистрации, политик, карт сети и согласования P2P
с long polling.
Жизненный цикл агента находится в `runtime/src/runtime.rs`.

Координатор автоматически создаёт сеть и учётную запись `admin` при первом
запуске. Регистрация пользователей открытая; доступом к устройствам управляют
их владельцы. Инструкция запуска, пример TLS-конфигурации и протокол:
[HTTPS-координатор](docs/COORDINATOR.md).

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
        "wg0",
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

`DeviceConfig::new(private_key, listen, tun_name)` задаёт приватный ключ, UDP-адрес прослушивания и имя TUN-интерфейса. Адрес с портом `0` просит ОС выбрать свободный порт; фактический адрес возвращает `Device::listen_addr()`. Конфигурацию можно настроить до вызова `Device::new()` через публичные поля:

- `dual_stack` — привязать wildcard-сокет для второго семейства IP на том же порту; включено по умолчанию.
- `workers` — число packet worker-потоков. По умолчанию используется число доступных CPU (не более 256); допустимо от 1 до 256.
- `handshake_rate_limit` — порог рукопожатий в секунду до запроса cookie; по умолчанию 100.

`Device::new(config)` открывает TUN и UDP-сокеты и запускает worker-потоки. `public_key()` возвращает открытый ключ устройства. `health()` сообщает об остановке устройства или ошибке worker-потока. `shutdown()` будит и дожидается завершения потоков; повторный вызов безопасен, а `Drop` также вызывает остановку.

### Пиры и маршруты

`PeerConfig` описывает `public_key`, необязательные `preshared_key`, `endpoint` и `persistent_keepalive`, а также список `allowed_ips`. Keepalive задаётся целым числом секунд от 1 до 65535. `upsert_peer()` добавляет пира или обновляет его конфигурацию и маршруты. При обновлении `endpoint: None` сохраняет уже установленный endpoint; чтобы удалить его, вызовите `clear_peer_endpoint()`. `set_peer_endpoint()` задаёт или меняет endpoint. `remove_peer()` удаляет пира вместе с его маршрутами.

`AllowedIp` можно создать через `AllowedIp::new(ip, prefix_len)` или разобрать из строки, например `"10.20.0.0/24"`. Адрес сети нормализуется обнулением host-битов. Методы `network()`, `prefix_len()` и `contains(ip)` позволяют читать и проверять префикс. Эти маршруты используются библиотекой для выбора пира для исходящего IP-пакета и проверки адреса источника расшифрованного входящего пакета. Для совпадающих префиксов действует один владелец; для разных префиксов выбирается наиболее специфичный.

Если для пира ожидает отправки рукопожатие, установка endpoint может инициировать его отправку. Такие отправки выполняются по возможности: ошибки учитываются в `DeviceStats::udp_send_errors`.

### Статистика и ошибки

`stats()` возвращает общие счётчики `DeviceStats`: принятые UDP- и TUN-пакеты, отброшенные пакеты, ошибки отправки таймерных пакетов и прочих UDP-пакетов. `peer_stats(&key)` возвращает `PeerStats` конкретного пира. Счётчики `tx_packets`/`tx_bytes` отражают внутренние IP-пакеты, принятые BoringTun к отправке, а `rx_packets`/`rx_bytes` — аутентифицированные расшифрованные пакеты, успешно записанные в TUN; `tx` не подтверждает доставку удалённой стороной.

Методы управления возвращают `DeviceError`: среди вариантов — некорректные параметры, отсутствие пира, исчерпание индексов, остановка устройства, ошибка ввода-вывода или сбой worker-потока. Ошибку разбора префикса представляет `AllowedIpParseError`.

## Ограничения платформы

Сейчас поддерживается Linux. Библиотека открывает TUN-интерфейс и управляет WireGuard-трафиком, но приложение должно само назначить интерфейсу IP-адреса и MTU и настроить маршруты операционной системы. `AllowedIp` задаёт внутренние маршруты WireGuard и не настраивает маршруты хоста.

## Проверка совместимости с Linux WireGuard

Скрипт `wireguard/scripts/check-kernel-interop.sh` поднимает два временных network namespace, соединённых veth-парой: в одном работает `portal`, в другом — WireGuard-интерфейс ядра. Он проверяет обмен IPv4- и IPv6-пакетами в обоих направлениях и удаляет созданные ресурсы при завершении.

Для запуска нужны Linux с доступным `/dev/net/tun`, включённая поддержка WireGuard в ядре, `iproute2`, `wireguard-tools`, `ping`, Cargo и права root:

```sh
cargo build -p portal --example wireguard_interop
sudo ./wireguard/scripts/check-kernel-interop.sh
```

Чтобы проверить соединение с предварительным общим ключом:

```sh
cargo build -p portal --example wireguard_interop
sudo WITH_PSK=1 ./wireguard/scripts/check-kernel-interop.sh
```

## Runtime и CLI

`portal-runtime` — отдельный foreground daemon: он владеет `Device` и настраивает
Linux TUN-интерфейс. `portal-cli` — отдельный бинарник `portal`, который управляет
локальным runtime через HTTP API на loopback-адресе. Этот API использует и
встроенная веб-панель. Прикладные сервисы пока удалены; сетевой агент поддерживает
ручной режим и подключение к HTTPS-координатору.

```sh
cargo build -p portal-runtime -p portal-cli --release
sudo target/release/portal-runtime
```

Все флаги запуска необязательны. Без аргументов (или с одной командой `run`)
используется `/etc/portal/runtime.json`, если он есть; иначе запускается ручной
режим: `portal0`, UDP `0.0.0.0:51820`, API `127.0.0.1:51821`, MTU `1420`.
Ключ `/etc/portal/device.key` создаётся при первом ручном запуске и сохраняется
для следующих. Адреса TUN по умолчанию не назначаются; пример переопределения:
`sudo target/release/portal-runtime run --address 10.20.0.1/24`.
Полная [таблица значений по умолчанию](docs/RUNTIME.md#запуск-без-параметров).

`keygen` без флагов создаёт `/etc/portal/device.key` с режимом `0600`, печатает
публичный ключ в hex и не перезаписывает существующий файл. `portal-runtime run`
поднимает устройство, настраивает MTU, адреса и
состояние интерфейса, затем слушает HTTP API только на loopback. Случайный bearer-
токен записывается в файл с режимом `0600` и удаляется при штатной остановке.
Для веб-клиента токен можно прочитать с правами владельца runtime и передать в
`Authorization: Bearer ...`; не встраивайте его в общедоступные frontend-файлы.
Runtime остаётся отдельным процессом. CLI обращается к тому же API, что и веб-клиент:

```sh
sudo target/release/portal peer upsert \
  --api 127.0.0.1:51821 \
  --token-file /run/portal.token \
  --public-key PUBLIC_KEY_HEX \
  --endpoint 198.51.100.10:51820 \
  --keepalive 25 \
  --allowed-ip 10.20.0.2/32
sudo target/release/portal status --api 127.0.0.1:51821 --token-file /run/portal.token
sudo target/release/portal peer-stats \
  --api 127.0.0.1:51821 \
  --token-file /run/portal.token \
  --public-key PUBLIC_KEY_HEX
sudo target/release/portal shutdown --api 127.0.0.1:51821 --token-file /run/portal.token
```

API v1 принимает `POST /api/v1/command` с JSON-телом `{"operation":"status"}` и
заголовком `Authorization: Bearer <token>`. Доступны операции `peer_upsert`,
`peer_remove`, `endpoint_set`, `endpoint_clear`, `status`, `health`, `stats`,
`peer_stats`, `list`, `connect` и `shutdown`. Например, веб-клиент может отправить ту же
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
При изменении `AllowedIPs` runtime добавляет или удаляет соответствующие host-маршруты
через TUN. Если такой точный маршрут уже существует через этот интерфейс, runtime его
не удаляет при завершении. Конфигурация пиров хранится в памяти процесса, поэтому
после перезапуска их нужно добавить снова. `upsert` полностью заменяет `preshared_key`
и `persistent_keepalive`; если PSK не передан, он будет сброшен.

Runtime требует Linux, `iproute2` и права на создание TUN-интерфейса и настройку
маршрутов. По умолчанию автоматическая установка маршрутов `0.0.0.0/0` и `::/0`
отклоняется: полноценный full-tunnel требует policy routing, чтобы UDP-пакеты
WireGuard к endpoint не попали обратно в туннель. Для такого режима используйте
`--no-auto-routes` и настройте маршруты отдельно. CLI также не меняет системный
IP forwarding и firewall. CLI не содержит реализацию `Device` или команды
настройки Linux-интерфейса.
