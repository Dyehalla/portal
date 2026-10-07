# portal

`portal` — библиотека для встраивания WireGuard-интерфейсов в приложение виртуальных сетей. Публичная единица управления — `Device`: он владеет интерфейсом, UDP-портом, списком пиров и worker-потоками.

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
локальным runtime через HTTP API на loopback-адресе. API предназначен для CLI и
веб-клиента; прикладной HTTP API между пирами отдельно от управления
локальным `Device`.

```sh
cargo build -p portal-runtime -p portal-cli --release
sudo install -d -m 700 /etc/portal
sudo target/release/portal-runtime keygen --private-key-file /etc/portal/device.key
sudo target/release/portal-runtime run \
  --tun portal0 \
  --private-key-file /etc/portal/device.key \
  --listen 0.0.0.0:51820 \
  --api-listen 127.0.0.1:51821 \
  --api-token-file /run/portal.token \
  --address 10.20.0.1/24 \
  --mtu 1420
```

`keygen` создаёт raw-файл приватного ключа с режимом `0600` и печатает открытый
ключ в hex. `portal-runtime run` поднимает устройство, настраивает MTU, адреса и
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

## Передача файлов между пирами

`portal-files` — прикладной сервис поверх настроенной WireGuard-сети.
HTTP + JSON проверяет доступ пира, выдаёт одноразовые билеты на скачивание и
параметры подключения к SMB. Этот же HTTP-listener передаёт байты файлов.
Трафик защищает WireGuard; listener привязывается к туннельному IP.
Контракт JSON описан типами в `files/src/models.rs`, маршруты — в `files/src/api.rs`.
Для сборки достаточно Rust toolchain.

```sh
cargo build -p portal-runtime -p portal-files --release
```

Файловый сервис запускает `portal-runtime` вместе с Device. На пире `10.20.0.1`
добавьте параметры HTTP и файлового сервиса к обычной команде запуска runtime:

```sh
sudo target/release/portal-runtime run \
  --tun portal0 \
  --private-key-file /etc/portal/device.key \
  --listen 0.0.0.0:51820 \
  --address 10.20.0.1/24 \
  --peer-http-listen 10.20.0.1:8080 \
  --files-root /srv/portal-share \
  --files-allow-download 10.20.0.2
```

С другого разрешённого пира запросите файл по относительному пути внутри
`/srv/portal-share` и укажите локальное имя для результата:

```sh
target/release/portal-files download \
  --peer http://10.20.0.1:8080 \
  --path documents/report.pdf \
  --output ./report.pdf
```

HTTP API доступен напрямую, без CLI:

```sh
curl http://10.20.0.1:8080/v1/shares
curl -H 'Content-Type: application/json' \
  -d '{"path":"documents/report.pdf"}' http://10.20.0.1:8080/v1/downloads
```

`POST /v1/downloads` возвращает `download_url`, `file_name`, `size_bytes` и
`expires_at_unix_seconds`. `GET /v1/download/:ticket` отдаёт файл один раз тому же
пиру. Ошибки авторизации — HTTP 403, неверный путь — 400, отсутствующий файл — 404,
переполнение лимита — 429, выключенный backend — 501. Ошибки прикладных обработчиков
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
ключом через `AllowedIPs`. Peer HTTP-listener следует открывать только на
туннельном интерфейсе. В этой версии реализовано скачивание; загрузка и права
на отдельные файлы пока не входят в контракт.


## Пробная интеграция SMB (Linux)

Runtime может поднять одну общую папку только для чтения через отдельный процесс
Samba. Нужны `smbd` и `testparm` из пакета Samba. По умолчанию Samba работает
от текущего пользователя; если runtime запущен через `sudo`, выбирается пользователь,
вызвавший `sudo`. `--smb-user USER` задаёт другой существующий Linux-аккаунт;
непривилегированный runtime может использовать только собственный аккаунт.
При запуске runtime от root без информации о sudo нужно явно указать
непривилегированный `--smb-user` или включить `--smb-as-root`.

Runtime перед запуском Samba снимает root-права с дочернего процесса, назначает UID,
GID и группы выбранного пользователя. Учётная запись должна иметь право читать
папку и проходить по её родительским директориям. Runtime не создаёт системных
пользователей. Его настройка WireGuard по-прежнему требует соответствующих прав.
SMB-пароль задаётся отдельно от пароля Linux; файл пароля должен принадлежать
пользователю runtime или выбранному пользователю Samba и иметь режим `0600`.
Одна строка содержит пароль. База SMB-паролей создаётся напрямую в приватной
папке процесса; запуск `smbpasswd` с root-правами не требуется.

Например, сохраните пароль без отображения в терминале:

```sh
sudo bash -c 'umask 077; read -r -s -p "SMB password: " smb_password; printf "\n" >&2; printf "%s\n" "$smb_password" > /etc/portal/smb.password'
```

Добавьте параметры к обычному запуску runtime. Замените `reader` существующим
непривилегированным Linux-пользователем, которому доступен `/srv/portal-share`:

```sh
sudo target/release/portal-runtime run \
  --tun portal0 \
  --private-key-file /etc/portal/device.key \
  --listen 0.0.0.0:51820 \
  --address 10.20.0.1/24 \
  --peer-http-listen 10.20.0.1:8080 \
  --smb-root /srv/portal-share \
  --smb-name documents \
  --smb-listen 10.20.0.1 \
  --smb-user reader \
  --smb-password-file /etc/portal/smb.password \
  --smb-allow-peer 10.20.0.2
```

Добавьте пир `10.20.0.2` через `portal peer upsert` с его ключом, endpoint и
`--allowed-ip 10.20.0.2/32`. `--smb-allow-peer` можно повторять; IP разрешённого пира
должен быть закреплён за его ключом через AllowedIPs. Listener использует только
IP, назначенный TUN через `--address`. По умолчанию используется TCP 1445;
`--smb-port PORT` задаёт другой порт. Уже занятый порт отклоняется.
Если firewall блокирует соединение, разрешите выбранный TCP-порт на TUN от выбранных пиров;
runtime не меняет firewall.

Для проверки непривилегированной Samba на Linux:

```sh
smbclient //10.20.0.1/documents -p 1445 -U reader
```

Нестандартный порт должен поддерживаться SMB-клиентом. Некоторые стандартные
файловые клиенты требуют порт 445. Для запуска на нём можно использовать
`--smb-port 445`, если у процесса Samba уже есть право привязки к этому порту.
Runtime не выдаёт дополнительные capabilities и не перенаправляет порты автоматически.

Опциональный запуск Samba от root: добавьте `--smb-as-root` к запуску привилегированного
runtime. Тогда порт по умолчанию — 445, если `--smb-port` не указан. Этот флаг сам
не вызывает `sudo` и не повышает права непривилегированного runtime. На стандартном
порту адрес подключения — `smb://10.20.0.1/documents` (macOS/iOS)
или `\\10.20.0.1\documents` (Windows). Логин и пароль остаются отдельными от режима запуска.

Каждый запуск создаёт отдельные конфигурацию, базу паролей и состояние Samba в
приватной временной директории; системный `smb.conf` и системная база Samba не меняются.
При завершении runtime останавливает собственный процесс Samba и удаляет временное
состояние. При аварийном SIGKILL автоматическая очистка не гарантируется.
SMB1, гостевой доступ, запись и переход по симлинкам выключены. Для этой первой
версии используется одна учётная запись для всех разрешённых пиров; динамическое
управление шарами, отдельные учётные записи на пир и автоматический маунт ещё не реализованы.
SMB управляется `portal-files::FileService` и согласуется через общий peer HTTP API.
`--smb-root` требует `--peer-http-listen`; HTTP-скачивание можно не включать.
Listener должен использовать адрес туннельного интерфейса.

`GET /v1/shares` возвращает только разрешённые туннельному IP шары: имя, IP, порт
и read-only. `POST /v1/smb/connections` с JSON `{"share_name":"documents"}` повторно
проверяет разрешение и возвращает `share`, `username`, `password`.
IP берётся из TCP-соединения; `X-Forwarded-For` и поля JSON не задают личность пира.
Разрешения SMB и скачивания независимы. Пароль нельзя логировать или передавать
через незашифрованную внешнюю сеть. Ответы содержат `Cache-Control: no-store`.

```sh
cargo run -p portal-files -- smb-list --peer http://10.20.0.1:8080
cargo run -p portal-files -- smb-connect --peer http://10.20.0.1:8080 --share documents
```

`smb-connect` на Unix открывает интерактивный `smbclient` с согласованными параметрами.
Пароль не выводится и не попадает в аргументы процесса: используется временный файл
0600 в каталоге 0700, который удаляется при обычном завершении клиента. Требуется установленный
`smbclient`. Это открытие клиентской сессии, а не системный маунт. Для интеграции
с нативным клиентом доступны библиотечные функции `list_shares` и
`prepare_smb_connection`; автоматический маунт для каждой ОС пока не реализован.
Клиент ожидает числовой туннельный IP в peer HTTP URL и проверяет совпадение с SMB-хостом.

Учётные данные общие для разрешённых пиров и действуют до изменения пароля
сервера; этот запрос не выдаёт одноразовый билет. TODO: отдельные учётные записи на пир,
ротация паролей и отзыв активных SMB-сессий. Linux-код сервера изолирован в
`files/src/platform/linux/smb.rs`.

Для end-to-end проверки в отдельных network namespace:

```sh
cargo build -p portal-runtime -p portal-cli
# Непривилегированная Samba, привилегированная настройка WireGuard:
sudo env SMB_TEST_USER=reader bash runtime/scripts/check-smb.sh
# Samba от root:
sudo env SMB_TEST_USER=reader SMB_AS_ROOT=1 bash runtime/scripts/check-smb.sh
```

Тест требует `/dev/net/tun`, kernel WireGuard, `ip`, `wg`, Samba и `smbclient`.
Он проверяет чтение файла через WireGuard, запрет записи, симлинков и гостевого
доступа, запрет доступа пира без SMB-разрешения, привязку listener к туннельному
адресу и завершение runtime.

Проверка Samba без root и без WireGuard на loopback (запускается от обычного пользователя):

```sh
cargo test -p portal-files rootless_samba_serves_files -- --ignored
```

Она проверяет HTTP-обнаружение и выдачу учётных данных, UID процесса Samba, чтение файла с полученными учётными данными, запрет записи и симлинков и остановку.
