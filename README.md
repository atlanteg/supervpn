# supervpn

Прозрачный L2 VPN с автоматическим восстановлением потерь пакетов (FEC) и fallback на TLS/TCP.

Два бинарника: **сервер** (Linux) и **клиент** (Windows, macOS).

## Скачать

**[supervpn-dist.zip](https://github.com/atlanteg/supervpn-releases/releases/latest/download/supervpn-dist.zip)**
— Linux сервер + Windows клиент + macOS клиент (arm64 / amd64), все конфиги и TAP-драйвер.

Текущая версия: см. [releases](https://github.com/atlanteg/supervpn-releases/releases/latest).

---

## Как это работает

```
[Клиент A — bridge mode]              [Сервер Linux]
  169.254.x.x NIC                       UDP :5555
  Npcap/BPF/TAP ──► FEC encode ──►     TLS :443 (fallback)
                                             │
                                         Hub 1 (L2 switch)
                                         MAC-таблица
                          ◄── FEC decode ──┤
                                           │
                               [Клиент B — direct mode]
                                 TAP «supervpn-tap»
                                 192.168.5.1/24
```

**Bridge mode** — клиент находит интерфейс с адресом `169.254.0.0/16` (APIPA) и прозрачно
форвардит весь L2-трафик в хаб. Никаких ручных маршрутов. Захват кадров:

| Платформа | Метод | Примечание |
|---|---|---|
| Windows | Npcap (primary) | `promisc=1`; NDIS-loopback инжектированных кадров подавляется |
| Windows | NDISUIO (fallback) | `OID_GEN_CURRENT_PACKET_FILTER = PROMISCUOUS` |
| Windows | tap+Windows Bridge (fallback) | Bridge ставит promiscuous сам |
| macOS | BPF | `BIOCPROMISC` + `BIOCSSEESENT=0` |
| Linux | kernel TAP | bridge ставит promiscuous сам |

**Direct mode** — если 169.254-интерфейса нет, клиент открывает TAP-адаптер `supervpn-tap`
(L2, полные Ethernet-кадры). Участвует в L2-домене хаба наравне с bridge-клиентами —
ARP, unicast и broadcast работают прозрачно. После запуска назначить IP вручную:
```
netsh interface ip set address "supervpn-tap" static 192.168.5.1 255.255.255.0
```

TAP-драйвер (`tap-driver/`) устанавливается **автоматически** при первом запуске если не установлен.
Требует запуска от Администратора.

**Hub** — изолированный L2-коммутатор: учит MAC-адреса из каждого входящего кадра,
извлекает IP из ARP и IPv4-заголовков, делает unicast/broadcast/flood. Таблица MAC→IP
видна в `/status` и полезна для диагностики форвардинга.

**FEC** — Reed-Solomon над GF(2⁸): на K пакетов добавляется R repair-символов, любые ≤R
потерь в блоке восстанавливаются без retransmit. По умолчанию K=20, R=6.
Streaming delivery: пакеты до пробела возвращаются немедленно, не ждут весь блок.

**Transport** — UDP primary; при недоступности — автоматический fallback на TLS 1.3/TCP
(configurable SNI). Каждые 5 минут TLS-клиент зондирует UDP и переключается обратно.

**Knock-and-dial** — перед каждой UDP auth-попыткой клиент отправляет N случайных пакетов
с того же сокета (тот же 5-tuple), праймируя NAT/firewall. Затем несколько knock→auth циклов.

**Авто-обновление** — при старте клиент проверяет последний релиз (GitHub API). Зеркало
для скачивания берётся автоматически из адреса сервера (`http://server_host:9090/update`).
Сервер сам скачивает клиентские бинарники в `dist/` при старте и раздаёт их клиентам.

---

## Особенности

| | |
|---|---|
| Прозрачный L2 мост | bridge mode не требует настройки IP или маршрутов |
| Автонастройка Windows | TAP переименовывается и Network Bridge создаётся автоматически |
| FEC без retransmit | восстанавливает до R потерь в блоке, стриминг без ожидания |
| FEC-статистика в логах | keepalive каждые 25s показывает data/repair/recovered/lost |
| UDP + TLS fallback | работает через ТСПУ, корпоративные firewall |
| Быстрый реконнект | фиксированная пауза 2s при дисконнекте, без экспоненциального backoff |
| Knock-and-dial | праймирование NAT перед auth одним сокетом |
| AES-128-GCM | per-session random salt, counter-based nonce, replay window 512 |
| Multi-hub | независимые L2-домены на одном сервере |
| Kick + blocklist | принудительный дисконнект через HTTP API с блокировкой на 5 минут |
| HTTP status API | JSON /status на сервере и клиенте; MAC/IP-таблица хаба |
| Авто-обновление | GitHub Releases + fallback-зеркало на сервере; сервер авто-скачивает клиентов |
| Авторелиз CI | каждый push в main = новый релиз в GitHub Releases |

---

## Платформы

| Компонент | Платформа | Адаптер | Статус |
|---|---|---|---|
| `supervpn-server` | Linux amd64 | — | готово |
| `supervpn-client` | Windows amd64 | tap-windows6 TAP (direct + bridge), Npcap / NDISUIO (bridge capture) | готово |
| `supervpn-client` | macOS arm64/amd64 | utun (direct) / BPF (bridge, root) | готово |

---

## Быстрый старт

### 1. Сервер (Linux)

Генерируем bcrypt hash пароля:

```bash
./supervpn-server hashpw mypassword
# $2a$10$...
```

Конфиг `/etc/supervpn/server.toml`:

```toml
listen        = "0.0.0.0:5555"
listen_tcp    = "0.0.0.0:443"
status_listen = "0.0.0.0:9090"   # доступен клиентам — нужен для зеркала обновлений

[fec]
k = 20
r = 6

[[hub]]
id   = 1
name = "office"

  [[hub.user]]
  login         = "alice"
  password_hash = "$2a$10$..."   # supervpn-server hashpw alice

  [[hub.user]]
  login         = "bob"
  password_hash = "$2a$10$..."
```

Запуск:

```bash
./supervpn-server -config /etc/supervpn/server.toml
# supervpn-server b108 starting: UDP=0.0.0.0:5555 hubs=1
# listening TLS/TCP 0.0.0.0:443
# update mirror: downloading  supervpn-client-windows-amd64.exe  (release b108) ...
# update mirror: ready  supervpn-client-windows-amd64.exe  (4521984 bytes)
# ...
# update mirror ready — clients: update_mirrors = ["http://0.0.0.0:9090/update"]
```

При старте сервер автоматически скачивает клиентские бинарники в `dist/` (рядом с бинарником)
и начинает раздавать их клиентам как зеркало обновлений.

### 2. Клиент

```toml
# client.toml
server        = "vpn.example.com:5555"
server_tcp    = "vpn.example.com:443"
status_listen = "127.0.0.1:9191"
hub_id        = 1
login         = "alice"
password      = "mypassword"

# transport = "auto"   # auto (default) | udp | tcp

[tls]
sni = "microsoft.com"   # SNI в TLS ClientHello

[udp]
knock_count = 3
knock_size  = 16
attempts    = 3

# update_mirrors не нужен — автоматически выводится из адреса сервера:
# http://vpn.example.com:9090/update
```

```bash
# Windows
supervpn-client.exe -config client.toml

# macOS (bridge mode требует root)
sudo supervpn-client -config client.toml

# Без конфига
supervpn-client -server vpn.example.com:5555 -login alice -password mypassword

# Форсировать TLS (пропустить UDP пробы)
supervpn-client -config client.toml -transport tcp

# UDP only (без fallback)
supervpn-client -config client.toml -transport udp
```

При старте клиент автоматически проверяет обновления и перезапускается если найдена новая версия:

```
update: mirror auto-set to http://vpn.example.com:9090/update
update: checking for updates (current: b108) ...
update: already up to date (b108)
supervpn-client b108: server=vpn.example.com:5555 hub=1 login=alice
```

При старте клиент пишет режим работы и keepalive-статистику каждые 25 секунд:

```
# Bridge mode (Windows) — Network Bridge создаётся автоматически:
bridge: creating Windows Network Bridge ("Ethernet" ↔ "supervpn-tap") ...
bridge: Network Bridge "Network Bridge" ready
bridge mode: bridging local NIC "Ethernet" (addr=169.254.3.7 mac=84:a6:c8:d1:06:bf) → "supervpn-tap"
session 469949699 active via udp
keepalive: ping #1 sent, last pong 0s ago | FEC data=0 repair=0 recovered=0 lost=0
keepalive: pong received from server
keepalive: ping #2 sent, last pong 24s ago | FEC data=1247 repair=62 recovered=3 lost=0

# Bridge mode (macOS) — BPF напрямую на NIC, без виртуального адаптера:
bridge mode: bridging local NIC "en0" (addr=169.254.3.7 mac=00:11:22:33:44:55) → "en0"
session 469949699 active via udp

# Direct mode (нет 169.254 интерфейса):
direct mode: opened "supervpn-tap" (L2 TAP — participates in hub L2 domain)
# Назначить IP: netsh interface ip set address "supervpn-tap" static 192.168.5.1 255.255.255.0
```

`FEC recovered` — пакеты, потерянные при передаче и восстановленные из repair-символов без retransmit.
`FEC lost` — блоки с потерями больше R (невосстановимые); при нормальных условиях = 0.

---

## Конфигурация

### Сервер (`server.toml`)

| Ключ | Тип | Default | Описание |
|---|---|---|---|
| `listen` | string | — | UDP адрес, напр. `0.0.0.0:5555` |
| `listen_tcp` | string | — | TLS/TCP адрес, напр. `0.0.0.0:443` |
| `status_listen` | string | — | HTTP status API + зеркало обновлений, напр. `0.0.0.0:9090` |
| `update_dir` | string | `dist/` рядом с бинарником | Директория с клиентскими бинарниками для зеркала |
| `fec.k` | int | 20 | Data-пакетов в FEC блоке |
| `fec.r` | int | 6 | Repair-пакетов в FEC блоке |
| `tls.cert_file` | string | — | PEM cert (если пусто — auto self-signed) |
| `tls.key_file` | string | — | PEM key |
| `[[hub]]` | — | — | Секция хаба (можно несколько) |
| `hub.id` | uint16 | — | Уникальный ID хаба |
| `hub.name` | string | — | Имя хаба |
| `[[hub.user]]` | — | — | Пользователь хаба |
| `hub.user.login` | string | — | Логин |
| `hub.user.password_hash` | string | — | bcrypt hash (`hashpw`) |

### Клиент (`client.toml`)

| Ключ | Тип | Default | Описание |
|---|---|---|---|
| `server` | string | — | UDP адрес сервера |
| `server_tcp` | string | `host:443` | TLS/TCP адрес (если не задан — `host` из `server` + `:443`) |
| `hub_id` | uint16 | 1 | ID хаба |
| `login` | string | — | Логин |
| `password` | string | — | Пароль |
| `transport` | string | `auto` | `auto` / `udp` / `tcp` |
| `mode` | string | `auto` | Режим адаптера: `auto` — автодетект 169.254 и bridge; `direct` — принудительно TUN без bridge; `bridge` — принудительно bridge (ошибка если нет 169.254) |
| `tun_name` | string | `supervpn` | Имя TUN в direct mode (macOS/Linux; на Windows игнорируется) |
| `bridge.tap_name` | string | `supervpn-tap` | Имя TAP-адаптера (bridge и direct mode на Windows) |
| `bridge.nic` | string | — | Имя физического NIC для bridge-режима (если пусто — автодетект по 169.254.x.x, адаптеры с `*` в имени пропускаются) |
| `status_listen` | string | — | HTTP status API клиента |
| `update_mirrors` | []string | авто из `server` | Зеркала для скачивания обновлений; если не задано — `http://server_host:9090/update` |
| `fec.k` | int | 20 | Data-пакетов (должно совпадать с сервером) |
| `fec.r` | int | 6 | Repair-пакетов (должно совпадать с сервером) |
| `tls.sni` | string | хост сервера | SNI в ClientHello |
| `udp.knock_count` | int | 3 | Knock-пакетов перед auth |
| `udp.knock_size` | int | 16 | Размер knock-пакета (байт) |
| `udp.attempts` | int | 3 | Попыток UDP перед TLS fallback |

**Флаги командной строки** перекрывают конфиг:

```
-config       путь к .toml
-server       UDP адрес (host:port)
-server-tcp   TCP адрес (host:port)
-hub          ID хаба
-login        логин
-password     пароль
-transport    auto | udp | tcp
```

---

## HTTP Status API

### `GET http://127.0.0.1:9090/status` (сервер)

```json
{
  "version": "b108",
  "uptime": "2h15m30s",
  "udp_listen": "0.0.0.0:5555",
  "udp_listen_2": "0.0.0.0:5556",
  "tcp_listen": "0.0.0.0:443",
  "tcp_listen_2": "0.0.0.0:444",
  "tcp_listener_up": true,
  "tcp2_listener_up": true,
  "hubs": [
    {
      "id": 1,
      "name": "office",
      "clients": [
        {
          "session_id": 3141592653,
          "login": "alice",
          "remote_addr": "1.2.3.4:51234",
          "secondary_addr": "1.2.3.4:51235",
          "mode": "udp",
          "connected_at": "2026-05-15T10:00:00Z",
          "last_seen": "2026-05-15T12:14:58Z",
          "duration": "2h14m58s",
          "frames_rx": 1024,
          "frames_tx": 980,
          "hub_send_calls": 1024
        }
      ],
      "mac_table": [
        {
          "mac": "00:ff:ee:71:d2:3c",
          "ip": "192.168.5.1",
          "login": "alice",
          "session_id": 3141592653,
          "expires_in": "4m32s"
        },
        {
          "mac": "a4:c3:f0:11:22:33",
          "ip": "192.168.5.3",
          "login": "",
          "session_id": 3141592653,
          "expires_in": "2m11s"
        }
      ]
    }
  ],
  "update_mirror": {
    "url": "http://0.0.0.0:9090/update",
    "assets": {
      "supervpn-client-windows-amd64.exe": "ok (4521984 bytes)",
      "supervpn-client-darwin-arm64": "ok (5234688 bytes)",
      "supervpn-client-darwin-amd64": "ok (5190144 bytes)"
    }
  }
}
```

`tcp_listener_up` / `tcp2_listener_up` — `true` если соответствующий TLS/TCP listener поднялся.  
`udp_listen_2` / `tcp_listen_2` — адреса вторичных слушателей (порт+1) для dual-path транспорта.  
`secondary_addr` — адрес клиента на вторичном пути; пусто если клиент подключён по одному каналу.  
`frames_rx` — Ethernet фреймов получено от клиента и отправлено в hub.  
`frames_tx` — Ethernet фреймов отправлено клиенту из hub.  
`hub_send_calls` — сколько раз hub вызвал Send для этого клиента (до FEC-кодирования).  
`mac_table` — текущая MAC-таблица хаба: для каждого MAC — последний виденный IP (из ARP/IPv4),
логин владельца (пусто если это физическое устройство за bridge-клиентом), TTL записи.  
`update_mirror.assets` — какие клиентские бинарники готовы к раздаче.

### `GET http://127.0.0.1:9191/status` (клиент)

```json
{
  "version": "b108",
  "uptime": "45m10s",
  "state": "connected",
  "session": {
    "session_id": 3141592653,
    "server": "vpn.example.com:5555",
    "hub_id": 1,
    "login": "alice",
    "mode": "udp",
    "secondary_addr": "vpn.example.com:5556",
    "connected_at": "2026-05-15T11:30:00Z",
    "duration": "45m10s"
  }
}
```

`state`: `starting` | `connecting` | `connected` | `reconnecting`  
`mode`: `udp` | `tls`  
`secondary_addr`: адрес вторичного пути (порт+1); отсутствует если dual-path не установлен

### `POST http://127.0.0.1:9090/api/hubs/{hub_id}/kick/{session_id}`

```bash
curl -X POST http://127.0.0.1:9090/api/hubs/1/kick/3141592653
# {"status":"ok","session_id":3141592653,"login":"alice"}
```

Логин блокируется на 5 минут после kick.

---

## Авто-обновление

Клиент при старте проверяет последний релиз и перезапускается если доступна новая версия.

**Порядок источников:**
1. GitHub API (`api.github.com/repos/atlanteg/supervpn-releases/releases/latest`)
2. Зеркала из `update_mirrors` (проверяются по очереди)

**Зеркало по умолчанию** — сервер supervpn сам. Адрес зеркала выводится автоматически из
`server` в конфиге клиента: `http://server_host:9090/update`. Явно задавать не нужно.

Если порт status_listen на сервере не 9090:
```toml
update_mirrors = ["http://vpn.example.com:8080/update"]
```

**Сервер** при старте скачивает недостающие клиентские бинарники с GitHub в `dist/` и раздаёт
их через `GET /update/{asset}`. Директория настраивается через `update_dir`.

---

## Сборка

Требуется Go 1.22+.

```bash
make build          # все платформы → dist/
make server         # только Linux сервер
make client-windows # только Windows клиент
make client-darwin-arm64   # macOS Apple Silicon
make client-darwin-amd64   # macOS Intel
make test           # go test -race ./...
make zip            # собрать supervpn-dist.zip
make release        # build + zip + публикация вручную (обычно не нужно)
```

Версия (`b{N}`) задаётся автоматически по числу коммитов в git — не нужно проставлять вручную.

**Публикация релизов автоматическая:** каждый `git push origin main` запускает GitHub Actions,
который прогоняет тесты, собирает все платформы и публикует новый релиз в supervpn-releases.
`make release` нужен только для внепланового ручного деплоя.

### Вручную

```bash
# Сервер
GOOS=linux GOARCH=amd64 go build -o supervpn-server ./cmd/supervpn-server

# Клиент Windows
GOOS=windows GOARCH=amd64 go build -o supervpn-client.exe ./cmd/supervpn-client

# Клиент macOS
GOOS=darwin GOARCH=arm64 go build -o supervpn-client-arm64 ./cmd/supervpn-client
GOOS=darwin GOARCH=amd64 go build -o supervpn-client-amd64 ./cmd/supervpn-client
```

---

## Deploy (systemd)

```bash
install -o root -g root -m 755 supervpn-server /usr/local/bin/
install -d /etc/supervpn
install -m 640 server.toml /etc/supervpn/server.toml
cp supervpn-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now supervpn-server
```

Файл unit: `dist/linux/supervpn-server.service`.

---

## Безопасность

**Шифрование:** AES-128-GCM. Каждый пакет: `[peer_id:4][counter:8][nonce:12][ciphertext+tag]`.

**Nonce:** `counter(8) || salt(4)`. `salt` — случайные 4 байта на сессию. Гарантирует
уникальность nonce при коллизии session ID.

**Ключ:** HKDF-SHA256 из `SHA256(password) + hub_name + login`. Уникален для каждой пары
(пользователь, хаб).

**Wire auth:** на сервер передаётся `hex(SHA256(password))`, хранится `bcrypt(wire_hash)`.

**Replay protection:** sliding window 512 пакетов.

---

## Структура проекта

```
cmd/
  supervpn-server/     — точка входа сервера
  supervpn-client/     — точка входа клиента
internal/
  crypto/              — AES-128-GCM + ReplayWindow (не изменять)
  proto/               — wire format: типы фреймов, заголовки, seq-поля
  fec/                 — Forward Error Correction (Reed-Solomon / XOR)
  transport/           — UDP + TLS/TCP транспорт, knock-and-dial
  hub/                 — L2 коммутатор: MAC-таблица + IP-трекинг, forwarding
  bridge/              — детект 169.254, bridge loop
  auth/                — bcrypt/SHA-256 аутентификация
  config/              — TOML конфигурация
  update/              — авто-обновление: GitHub API + зеркала, FetchAsset
pkg/
  tun/                 — TAP (Linux/Windows tap0901), WinTun (Windows TUN), BPF (macOS bridge), utun (macOS direct)
dist/
  linux/               — сервер + конфиги + systemd unit
  windows/             — клиент + tap-driver + wintun.dll + конфиги
  macos/               — клиент (arm64 + amd64) + конфиги
```

---

## Лицензия

Proprietary. All rights reserved.
