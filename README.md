# supervpn

Прозрачный L2 VPN с автоматическим восстановлением потерь пакетов (FEC) и fallback на TLS/TCP.

Два бинарника: **сервер** (Linux) и **клиент** (Windows, macOS).

---

## Как это работает

```
[Клиент A — bridge mode]              [Сервер Linux]
  169.254.x.x ──► WinTun/utun          UDP :5555
       L2 frames  ──► FEC encode ──►   TLS :443 (fallback)
                                            │
                                         Hub 1 (L2 switch)
                                            │
                        ◄── FEC decode ◄─── │ ──► [Клиент B — direct mode]
                                                    utun / WinTun (raw IP)
```

**Bridge mode** — клиент находит интерфейс с адресом `169.254.0.0/16` (APIPA) и прозрачно
форвардит с него весь L2-трафик в хаб. Никаких ручных маршрутов.

**Direct mode** — если `169.254`-интерфейса нет, клиент создаёт собственный TUN-адаптер
(`supervpn` по умолчанию) и подключается к хабу напрямую, получая полный L2-доступ к нему.

**Hub** — изолированный L2-коммутатор на сервере: учит MAC-адреса, unicast/broadcast,
трафик между хабами не смешивается.

**FEC** — Reed-Solomon над GF(2⁸): на каждые K пакетов добавляется R repair-символов,
любые R потерь в блоке восстанавливаются без retransmit. По умолчанию K=20, R=6.

**Transport** — UDP primary; при недоступности UDP — автоматический fallback на TLS 1.3/TCP
с configurable SNI (по умолчанию — имя хоста сервера). Каждые 5 минут TLS-клиент
зондирует UDP и переключается обратно при появлении пути.

**Knock-and-dial** — перед каждой UDP auth-попыткой клиент отправляет N случайных UDP-пакетов
с того же сокета (тот же 5-tuple), прайминг NAT/firewall-состояние. Затем несколько
knock→auth циклов, и только потом fallback на TLS.

---

## Особенности

| | |
|---|---|
| Прозрачный L2 мост | bridge mode не требует настройки IP или маршрутов |
| FEC без retransmit | восстанавливает до R потерь в блоке без задержки retransmit |
| UDP + TLS fallback | работает через ТСПУ, корпоративные firewall |
| Knock-and-dial | прайминг NAT перед auth одним сокетом |
| AES-128-GCM | per-session random salt, счётчик-based nonce, replay window 512 |
| Multi-hub | независимые L2-домены на одном сервере |
| Kick + blocklist | принудительный дисконнект через HTTP API с блокировкой на 5 минут |
| HTTP status API | JSON /status на сервере и клиенте |
| macOS utun | нативная поддержка без сторонних драйверов |

---

## Платформы

| Компонент | Платформа | Статус |
|---|---|---|
| `supervpn-server` | Linux amd64 | готово |
| `supervpn-client` | Windows amd64 | готово (WinTun) |
| `supervpn-client` | macOS amd64/arm64 | готово (utun) |

---

## Быстрый старт

### 1. Сервер

Генерируем hash пароля:

```bash
supervpn-server hashpw mypassword
# $2a$10$...
```

Создаём конфиг:

```toml
# /etc/supervpn/server.toml
listen        = "0.0.0.0:5555"
listen_tcp    = "0.0.0.0:443"
status_listen = "127.0.0.1:9090"

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
supervpn-server -config /etc/supervpn/server.toml
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
# tun_name    = "supervpn"   # имя TUN в direct mode (если нет 169.254-интерфейса)

[tls]
sni = "microsoft.com"   # SNI в TLS ClientHello — имитирует HTTPS

[udp]
knock_count = 3    # knock-пакетов перед каждой auth-попыткой
knock_size  = 16   # размер каждого knock-пакета
attempts    = 3    # попыток UDP перед fallback на TLS
```

```bash
# Windows
supervpn-client.exe -config client.toml

# macOS
sudo supervpn-client -config client.toml

# Без файла конфига
supervpn-client -server vpn.example.com:5555 -hub 1 -login alice -password mypassword
```

При старте клиент пишет в лог режим работы:

```
bridge mode: link-local interface Ethernet 2 (00:11:22:33:44:55)
# или
direct mode: no 169.254.x.x interface found, opening TUN "supervpn"
direct mode: assign an IP inside the hub subnet to "supervpn" after startup
```

---

## Конфигурация

### Сервер (`server.toml`)

| Ключ | Тип | Описание |
|---|---|---|
| `listen` | string | UDP адрес, напр. `0.0.0.0:5555` |
| `listen_tcp` | string | TLS/TCP адрес, напр. `0.0.0.0:443` |
| `status_listen` | string | HTTP status API, напр. `127.0.0.1:9090` |
| `[[hub]]` | — | Секция хаба (можно несколько) |
| `hub.id` | uint16 | Уникальный ID хаба |
| `hub.name` | string | Имя хаба (для логов/API) |
| `[[hub.user]]` | — | Пользователь в хабе |
| `hub.user.login` | string | Логин |
| `hub.user.password_hash` | string | bcrypt hash (`supervpn-server hashpw`) |
| `[fec]` | — | Forward Error Correction |
| `fec.k` | int | Data-пакетов в блоке (default 20) |
| `fec.r` | int | Repair-пакетов в блоке (default 6) |
| `[tls]` | — | TLS сертификат |
| `tls.cert_file` | string | PEM cert (если пусто — self-signed) |
| `tls.key_file` | string | PEM key |

### Клиент (`client.toml`)

| Ключ | Тип | Описание |
|---|---|---|
| `server` | string | UDP адрес сервера |
| `server_tcp` | string | TLS/TCP адрес сервера (fallback) |
| `status_listen` | string | HTTP status API клиента |
| `hub_id` | uint16 | ID хаба |
| `login` | string | Логин |
| `password` | string | Пароль |
| `tun_name` | string | Имя TUN в direct mode (default `supervpn`) |
| `[fec]` | — | FEC параметры (должны совпадать с сервером) |
| `[tls].sni` | string | SNI в ClientHello (default = хост сервера) |
| `[udp].knock_count` | int | Knock-пакетов перед auth (default 3) |
| `[udp].knock_size` | int | Размер knock-пакета в байтах (default 16) |
| `[udp].attempts` | int | Попыток UDP перед TLS fallback (default 3) |

---

## HTTP Status API

### Сервер: `GET http://127.0.0.1:9090/status`

```json
{
  "version": "v1.0.0",
  "uptime": "2h15m30s",
  "udp_listen": "0.0.0.0:5555",
  "tcp_listen": "0.0.0.0:443",
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
          "duration": "2h14m58s"
        }
      ]
    }
  ],
  "blocked": {
    "bob": "2026-05-15T12:20:00Z"
  }
}
```

Поле `blocked` появляется, если есть кикнутые логины (с таймстампом до которого заблокированы).

### Клиент: `GET http://127.0.0.1:9191/status`

```json
{
  "version": "v1.0.0",
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

### Kick: `POST http://127.0.0.1:9090/api/hubs/{hub_id}/kick/{session_id}`

```bash
curl -X POST http://127.0.0.1:9090/api/hubs/1/kick/3141592653
# {"status":"ok","session_id":3141592653,"login":"alice"}
```

После kick логин блокируется на 5 минут — клиент не сможет переподключиться.

---

## Сборка

```bash
# Требуется Go 1.22+
make build            # server (linux/amd64) + client (windows/amd64) → dist/
make server           # только сервер
make client-windows   # только Windows-клиент
make client-darwin    # только macOS-клиент
make test             # тесты (с -race)
make clean            # удалить dist/

# Версия
make build VERSION=v1.2.3
```

### Cross-compile вручную

```bash
# Сервер
GOOS=linux GOARCH=amd64 go build -o supervpn-server ./cmd/supervpn-server

# Клиент Windows
GOOS=windows GOARCH=amd64 go build -o supervpn-client.exe ./cmd/supervpn-client

# Клиент macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o supervpn-client-darwin ./cmd/supervpn-client

# Клиент macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o supervpn-client-darwin-arm64 ./cmd/supervpn-client
```

---

## Deploy

### systemd (Linux сервер)

```bash
# Создать пользователя
useradd -r -s /sbin/nologin supervpn

# Скопировать файлы
install -o supervpn -g supervpn /path/to/supervpn-server /usr/local/bin/supervpn-server
install -d -o supervpn /etc/supervpn
install -o supervpn /path/to/server.toml /etc/supervpn/server.toml

# Установить unit
cp deploy/supervpn-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now supervpn-server
```

### Docker

```bash
docker build -t supervpn-server .
docker run -d \
  -v /etc/supervpn:/etc/supervpn:ro \
  -p 5555:5555/udp \
  -p 443:443/tcp \
  --cap-drop=ALL \
  supervpn-server
```

### GitHub Releases

При пуше тега `v*` CI автоматически публикует 4 бинарника:
- `supervpn-server-linux-amd64`
- `supervpn-client-windows-amd64.exe`
- `supervpn-client-darwin-amd64`
- `supervpn-client-darwin-arm64`

---

## Безопасность

**Шифрование:** AES-128-GCM. Каждый пакет: `[peer_id:4][counter:8][nonce:12][ciphertext+tag]`.

**Nonce:** `counter(8) || salt(4)`. `salt` — случайные 4 байта, генерируются при создании
каждой сессии. Гарантирует уникальность nonce даже при коллизии session ID.

**Ключ сессии:** HKDF-SHA256 из `SHA256(password) || hub_name || login`. Уникален для каждой
пары (пользователь, хаб).

**Replay protection:** sliding window 512 пакетов. Повторные пакеты с уже виденным counter
отбрасываются.

**Аутентификация:** bcrypt hash хранится на сервере. По wire передаётся `SHA256(password)`
в hex (не сам пароль).

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
  tun/                 — TAP (Linux), WinTun (Windows), utun (macOS)
configs/               — примеры конфигурации
deploy/                — systemd unit
```

---

## Роадмап

См. [ROADMAP.md](ROADMAP.md).

---

## Лицензия

Proprietary. All rights reserved.
