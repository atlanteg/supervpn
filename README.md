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
[Клиент A]                          [Сервер Linux]
  bridge mode:                        UDP :5555
  169.254.x.x NIC ──► BPF/TAP        TLS :443 (fallback)
  L2 frames ──► FEC encode ──►            │
                                       Hub 1 (L2 switch)
                          ◄── FEC decode ─┤
                                          │
                                    [Клиент B]
                                      direct mode:
                                      TUN «supervpn»
                                      (назначить IP вручную)
```

**Bridge mode** — клиент находит интерфейс с адресом `169.254.0.0/16` (APIPA) и прозрачно
форвардит весь L2-трафик в хаб. Никаких ручных маршрутов. На macOS использует BPF (root),
на Windows — tap-windows6, на Linux — kernel TAP.

**Direct mode** — если 169.254-интерфейса нет, клиент открывает TUN-адаптер
(`supervpn` по умолчанию). После запуска назначить IP вручную.

**Hub** — изолированный L2-коммутатор: учит MAC-адреса, делает unicast/broadcast/flood.
Несколько хабов на одном сервере не смешиваются.

**FEC** — Reed-Solomon над GF(2⁸): на K пакетов добавляется R repair-символов, любые ≤R
потерь в блоке восстанавливаются без retransmit. По умолчанию K=20, R=6.
Streaming delivery: пакеты до пробела возвращаются немедленно, не ждут весь блок.

**Transport** — UDP primary; при недоступности — автоматический fallback на TLS 1.3/TCP
(configurable SNI). Каждые 5 минут TLS-клиент зондирует UDP и переключается обратно.

**Knock-and-dial** — перед каждой UDP auth-попыткой клиент отправляет N случайных пакетов
с того же сокета (тот же 5-tuple), праймируя NAT/firewall. Затем несколько knock→auth циклов.

---

## Особенности

| | |
|---|---|
| Прозрачный L2 мост | bridge mode не требует настройки IP или маршрутов |
| FEC без retransmit | восстанавливает до R потерь в блоке, стриминг без ожидания |
| UDP + TLS fallback | работает через ТСПУ, корпоративные firewall |
| Knock-and-dial | праймирование NAT перед auth одним сокетом |
| AES-128-GCM | per-session random salt, counter-based nonce, replay window 512 |
| Multi-hub | независимые L2-домены на одном сервере |
| Kick + blocklist | принудительный дисконнект через HTTP API с блокировкой на 5 минут |
| HTTP status API | JSON /status на сервере и клиенте |
| Версии b{N} | автоинкремент по числу коммитов, видно в логах и /status |

---

## Платформы

| Компонент | Платформа | Адаптер | Статус |
|---|---|---|---|
| `supervpn-server` | Linux amd64 | — | готово |
| `supervpn-client` | Windows amd64 | WinTun (direct) / tap-windows6 (bridge) | готово |
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
status_listen = "127.0.0.1:9090"

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
# supervpn-server b76 starting: UDP=0.0.0.0:5555 hubs=1
# listening TLS/TCP 0.0.0.0:443
```

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

При старте клиент пишет режим работы:

```
supervpn-client b76: server=vpn.example.com:5555 hub=1 login=alice
bridge mode: link-local interface en0 (00:11:22:33:44:55), adapter="en0" method=netbridge
# или
direct mode: no 169.254.x.x interface found, opening TUN "supervpn"
direct mode: assign an IP inside the hub subnet to "supervpn" after startup
```

---

## Конфигурация

### Сервер (`server.toml`)

| Ключ | Тип | Default | Описание |
|---|---|---|---|
| `listen` | string | — | UDP адрес, напр. `0.0.0.0:5555` |
| `listen_tcp` | string | — | TLS/TCP адрес, напр. `0.0.0.0:443` |
| `status_listen` | string | — | HTTP status API, напр. `127.0.0.1:9090` |
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
| `tun_name` | string | `supervpn` | Имя TUN в direct mode |
| `status_listen` | string | — | HTTP status API клиента |
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
  "version": "b76",
  "uptime": "2h15m30s",
  "udp_listen": "0.0.0.0:5555",
  "tcp_listen": "0.0.0.0:443",
  "tcp_listener_up": true,
  "hubs": [
    {
      "id": 1,
      "name": "office",
      "clients": [
        {
          "session_id": 3141592653,
          "login": "alice",
          "remote_addr": "1.2.3.4:51234",
          "mode": "udp",
          "connected_at": "2026-05-15T10:00:00Z",
          "last_seen": "2026-05-15T12:14:58Z",
          "duration": "2h14m58s",
          "frames_rx": 1024,
          "frames_tx": 980,
          "hub_send_calls": 1024
        }
      ]
    }
  ]
}
```

`tcp_listener_up` — `true` если TLS/TCP listener реально поднялся (а не только задан в конфиге).
`frames_rx` — Ethernet фреймов получено от клиента и отправлено в hub.
`frames_tx` — Ethernet фреймов отправлено клиенту из hub.
`hub_send_calls` — сколько раз hub вызвал Send для этого клиента (до FEC-кодирования).

### `GET http://127.0.0.1:9191/status` (клиент)

```json
{
  "version": "b76",
  "uptime": "45m10s",
  "state": "connected",
  "session": {
    "session_id": 3141592653,
    "server": "vpn.example.com:5555",
    "hub_id": 1,
    "login": "alice",
    "mode": "udp",
    "connected_at": "2026-05-15T11:30:00Z",
    "duration": "45m10s"
  }
}
```

`state`: `starting` | `connecting` | `connected` | `reconnecting`
`mode`: `udp` | `tls`

### `POST http://127.0.0.1:9090/api/hubs/{hub_id}/kick/{session_id}`

```bash
curl -X POST http://127.0.0.1:9090/api/hubs/1/kick/3141592653
# {"status":"ok","session_id":3141592653,"login":"alice"}
```

Логин блокируется на 5 минут после kick.

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
make release        # build + zip + публикация в GitHub Releases
```

Версия (`b{N}`) задаётся автоматически по числу коммитов в git — не нужно проставлять вручную.

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
  hub/                 — L2 коммутатор: MAC-таблица, forwarding
  bridge/              — детект 169.254, bridge loop
  auth/                — bcrypt/SHA-256 аутентификация
  config/              — TOML конфигурация
pkg/
  tun/                 — TAP (Linux), WinTun (Windows), BPF (macOS bridge), utun (macOS direct)
dist/
  linux/               — сервер + конфиги + systemd unit
  windows/             — клиент + tap-driver + wintun.dll + конфиги
  macos/               — клиент (arm64 + amd64) + конфиги
```

---

## Лицензия

Proprietary. All rights reserved.
