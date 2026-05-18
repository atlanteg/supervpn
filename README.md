# supervpn

Прозрачный L2 VPN с автоматическим восстановлением потерь пакетов (FEC) и fallback на TLS/TCP.

Три бинарника: **сервер** (Linux), **консольный клиент** и **GUI-клиент** (Windows, macOS).

## Скачать

Текущая версия: [releases](https://github.com/atlanteg/supervpn-releases/releases/latest).

| Файл | Платформа | Описание |
|---|---|---|
| `supervpn-server` | Linux amd64 | Сервер |
| `supervpn-client-windows-amd64.exe` | Windows amd64 | Консольный клиент |
| `supervpn-client-darwin-arm64` | macOS Apple Silicon | Консольный клиент |
| `supervpn-client-darwin-amd64` | macOS Intel | Консольный клиент |
| `supervpn-client-gui-windows-amd64.exe` | Windows amd64 | GUI-клиент (оконный) |
| `supervpn-client-gui-darwin-arm64` | macOS Apple Silicon | GUI-клиент (оконный) |
| `supervpn-client-gui-darwin-amd64` | macOS Intel | GUI-клиент (оконный) |

---

## Как это работает

```
[Клиент A — bridge mode]              [Сервер Linux]
  169.254.x.x NIC                       UDP :5555  / :5556 (dual-path)
  Npcap/BPF/TAP ──► FEC encode ──►     TLS :443   / :444  (dual-path)
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

**Direct mode** — если 169.254-интерфейса нет, клиент открывает TAP/WinTun-адаптер `supervpn-tap`
(L2, полные Ethernet-кадры). Участвует в L2-домене хаба наравне с bridge-клиентами —
ARP, unicast и broadcast работают прозрачно. После запуска назначить IP вручную:
```
netsh interface ip set address "supervpn-tap" static 192.168.5.1 255.255.255.0
```

На Windows в direct mode клиент сначала пробует **WinTun** (L2-эмуляция через ring-buffer,
обходит NDIS LWF фильтры таких продуктов как FortiClient/OpenVPN), при неудаче — tap-windows6.

TAP-драйвер (`tap-driver/`) устанавливается **автоматически** при первом запуске если не установлен.
Требует запуска от Администратора.

**Hub** — изолированный L2-коммутатор: учит MAC-адреса из каждого входящего кадра,
извлекает IP из ARP и IPv4-заголовков, делает unicast/broadcast/flood. Таблица MAC→IP
видна в `/status` и полезна для диагностики форвардинга.

**FEC** — Reed-Solomon над GF(2⁸): на K пакетов добавляется R repair-символов, любые ≤R
потерь в блоке восстанавливаются без retransmit. По умолчанию K=20, R=6.
Streaming delivery: пакеты до пробела возвращаются немедленно, не ждут весь блок.
Параметры K и R **автоматически принимаются от сервера** при каждом подключении — сервер
передаёт их в `AuthOK` (2 байта), клиент подстраивает FEC-пайп до начала передачи данных.
Ручного выравнивания конфигов не требуется.

**Transport** — UDP primary; при недоступности — автоматический fallback на TLS 1.3/TCP
(configurable SNI). Каждые 5 минут TLS-клиент зондирует UDP и переключается обратно.

**Dual-path** — клиент открывает два параллельных соединения (порт N и N+1) по обоим
протоколам. Все данные и repair-символы дублируются на оба пути. FEC-декодер
дедуплицирует через флаг `done` — никаких дублей на прикладном уровне.

**Keepalive и детекция обрыва:**
- UDP: application-level keepalive, пинг каждые 5 секунд, таймаут 10 секунд (2 пропущенных понга).
- TCP/TLS: OS-level TCP keepalive (`SO_KEEPALIVE`, интервал 5 секунд), детекция ~10 секунд.
- Статистика FEC в логах — каждые 10 секунд.

**Knock-and-dial** — перед каждой UDP auth-попыткой клиент отправляет N случайных пакетов
с того же сокета (тот же 5-tuple), праймируя NAT/firewall. Затем несколько knock→auth циклов.

**Авто-обновление** — при старте клиент проверяет последний релиз (GitHub API). Зеркало
для скачивания берётся автоматически из адреса сервера (`http://server_host/update`, порт 80).
Сервер сам скачивает клиентские бинарники в `dist/` при старте и раздаёт их клиентам.

---

## Особенности

| | |
|---|---|
| Прозрачный L2 мост | bridge mode не требует настройки IP или маршрутов |
| Автонастройка Windows | TAP переименовывается и Network Bridge создаётся автоматически |
| FEC без retransmit | восстанавливает до R потерь в блоке, стриминг без ожидания |
| Dual-path транспорт | два параллельных соединения (порт N и N+1), данные дублируются |
| Быстрая детекция обрыва | ~10 с для UDP и TCP/TLS |
| FEC-статистика в логах | keepalive каждые 10s показывает data/repair/recovered/lost |
| UDP + TLS fallback | работает через ТСПУ, корпоративные firewall |
| Быстрый реконнект | фиксированная пауза 2s при дисконнекте, без экспоненциального backoff |
| Knock-and-dial | праймирование NAT перед auth одним сокетом |
| AES-128-GCM | per-session random salt, counter-based nonce, replay window 512 |
| Multi-hub | независимые L2-домены на одном сервере |
| Kick + blocklist | принудительный дисконнект через HTTP API с блокировкой на 5 минут |
| HTTP status API | JSON /status на сервере и клиенте; MAC/IP-таблица хаба |
| Авто-обновление | GitHub Releases + fallback-зеркало на сервере (порт 80); сервер авто-скачивает клиентов |
| Авторелиз CI | каждый push в main = новый релиз в GitHub Releases |
| Защита от зависших процессов | при старте клиент убивает предыдущий экземпляр через PID-файл |

---

## Платформы

| Компонент | Платформа | Адаптер | Статус |
|---|---|---|---|
| `supervpn-server` | Linux amd64 | — | готово |
| `supervpn-client` | Windows amd64 | WinTun L2 / tap-windows6 (direct), Npcap / NDISUIO (bridge) | готово |
| `supervpn-client` | macOS arm64/amd64 | utun (direct) / BPF (bridge, root) | готово |
| `supervpn-client-gui` | Windows amd64 | то же что и консольный | готово |
| `supervpn-client-gui` | macOS arm64/amd64 | то же что и консольный | готово |

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
status_listen = "127.0.0.1:9090"   # admin API — только loopback
update_listen = "0.0.0.0:80"       # зеркало обновлений для клиентов

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
# supervpn-server b122 starting: UDP=0.0.0.0:5555 hubs=1
# listening TLS/TCP 0.0.0.0:443
# update mirror on http://0.0.0.0:80/update
# update mirror: downloading  supervpn-client-windows-amd64.exe  (release b122) ...
# update mirror: ready  supervpn-client-windows-amd64.exe  (4521984 bytes)
```

При старте сервер автоматически скачивает клиентские бинарники в `dist/` (рядом с бинарником)
и начинает раздавать их клиентам как зеркало обновлений на порту 80.

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
# mode      = "auto"   # auto (default) | direct | bridge

[fec]
k = 20   # должно совпадать с сервером
r = 6    # должно совпадать с сервером

[tls]
sni = "microsoft.com"   # SNI в TLS ClientHello

[udp]
knock_count = 3
knock_size  = 16
attempts    = 3

# update_mirrors не нужен — автоматически: http://vpn.example.com/update
```

**GUI-клиент — macOS:**

1. Скачать `superVPN-macos.zip` со [страницы релизов](https://github.com/atlanteg/supervpn-releases/releases/latest)
2. Распаковать zip — появится `superVPN.app`
3. Снять карантин Gatekeeper (обязательно, иначе macOS заблокирует):
   ```bash
   xattr -d com.apple.quarantine superVPN.app
   ```
4. Перенести `superVPN.app` в `/Applications`

Приложение универсальное (arm64 + amd64), работает на Apple Silicon и Intel.

**Запуск с правами root (обязателен для VPN-адаптера на macOS):**

На macOS создание TUN/BPF интерфейсов требует root. Запускать через Terminal:

```bash
sudo /Applications/superVPN.app/Contents/MacOS/superVPN
```

Чтобы не вводить каждый раз, добавьте алиас в `~/.zshrc`:

```bash
alias supervpn='sudo /Applications/superVPN.app/Contents/MacOS/superVPN'
```

> Двойной клик на `.app` без sudo запустит приложение, но подключение завершится ошибкой
> `operation not permitted` — это ограничение macOS, обойти которое без подписи
> Apple Developer можно только через sudo.

**GUI-клиент — Windows:**

1. Скачать `supervpn-client-gui-windows-amd64.exe` со [страницы релизов](https://github.com/atlanteg/supervpn-releases/releases/latest)
2. Запустить двойным кликом — откроется окно superVPN (консоль не появляется)
3. Если Windows SmartScreen блокирует — нажать «Подробнее» → «Выполнить в любом случае»

Все параметры конфига доступны во вкладке Advanced. Конфиг `.toml` можно загрузить через Browse.

**Консольный клиент:**

```bash
# Windows
supervpn-client.exe -config client.toml

# macOS — снять карантин и дать права на запуск:
xattr -d com.apple.quarantine supervpn-client-darwin-arm64
chmod +x supervpn-client-darwin-arm64

# macOS (bridge mode требует root)
sudo ./supervpn-client-darwin-arm64 -config client.toml

# Без конфига — все параметры как аргументы
supervpn-client -server vpn.example.com:5555 -login alice -password mypassword

# Форсировать TLS (пропустить UDP пробы)
supervpn-client -config client.toml -transport tcp

# Принудительно direct mode (без bridge-детекции)
supervpn-client -config client.toml -mode direct
```

При старте клиент убивает предыдущий зависший экземпляр (через PID-файл), затем
автоматически проверяет обновления и перезапускается если найдена новая версия:

```
update: mirror auto-set to http://vpn.example.com/update
update: checking for updates (current: b122) ...
update: already up to date (b122)
supervpn-client b122: server=vpn.example.com:5555 hub=1 login=alice
```

Лог в работе (статистика каждые 10 секунд):

```
# Bridge mode (Windows) — Network Bridge создаётся автоматически:
bridge: creating Windows Network Bridge ("Ethernet" ↔ "supervpn-tap") ...
bridge mode: bridging local NIC "Ethernet" (addr=169.254.3.7 mac=84:a6:c8:d1:06:bf) → "supervpn-tap"
session 469949699 active via udp
session 469949699: secondary path udp vpn.example.com:5556 connected
keepalive: ping #2 sent, last pong 0s ago | FEC data=0 repair=0 recovered=0 lost=0 | ↑0.0 KB/s ↓0.0 KB/s
keepalive: pong received from server
keepalive: ping #4 sent, last pong 9s ago | FEC data=1247 repair=62 recovered=3 lost=0 | ↑12.4 KB/s ↓8.1 KB/s

# Direct mode (нет 169.254 интерфейса):
direct mode: opened "supervpn-tap" (L2 TAP — participates in hub L2 domain)
# Windows — назначить IP:
# netsh interface ip set address "supervpn-tap" static 192.168.5.1 255.255.255.0

# macOS — utun работает в режиме point-to-point, маршрут в подсеть надо добавить вручную:
# sudo ifconfig utun9 192.168.5.4 192.168.5.4 netmask 255.255.255.0
# sudo route add -net 192.168.5.0/24 -interface utun9
# (номер utun9 смотри в выводе: direct mode: opened "supervpn" → ifconfig | grep utun)
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
| `status_listen` | string | — | HTTP admin API, напр. `127.0.0.1:9090` |
| `update_listen` | string | — | Зеркало обновлений для клиентов, напр. `0.0.0.0:80`; если не задан — `/update` раздаётся через `status_listen` |
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
| `update_mirrors` | []string | авто из `server` | Зеркала для скачивания обновлений; если не задано — `http://server_host/update` (порт 80) |
| `fec.k` | int | 20 | Data-пакетов (должно совпадать с сервером) |
| `fec.r` | int | 6 | Repair-пакетов (должно совпадать с сервером) |
| `tls.sni` | string | хост сервера | SNI в ClientHello |
| `udp.knock_count` | int | 3 | Knock-пакетов перед auth |
| `udp.knock_size` | int | 16 | Размер knock-пакета (байт) |
| `udp.attempts` | int | 3 | Попыток UDP перед TLS fallback |

**Флаги командной строки** перекрывают конфиг — все параметры доступны как через `.toml`, так и через флаги:

```
-config            путь к .toml
-server            UDP адрес (host:port)
-server-tcp        TCP адрес (host:port)
-hub               ID хаба
-login             логин
-password          пароль
-transport         auto | udp | tcp
-mode              auto | direct | bridge
-tun-name          имя TUN (direct mode, macOS/Linux)
-status-listen     HTTP status API адрес
-timeout           таймаут сессии (напр. 30s)
-update-mirrors    зеркала обновлений (через запятую)
-fec-k             FEC data-пакетов в блоке
-fec-r             FEC repair-пакетов в блоке
-fec-delay         задержка repair-фреймов (мс)
-tls-sni           SNI в TLS ClientHello
-udp-knock-count   knock-пакетов перед auth
-udp-knock-size    размер knock-пакета (байт)
-udp-attempts      попыток UDP перед TLS fallback
-bridge-nic        физический NIC для bridge (Windows)
-bridge-tap        TAP-адаптер (Windows bridge/direct)
-bridge-method     netbridge | hyperv
```

---

## HTTP Status API

### `GET http://127.0.0.1:9090/status` (сервер)

```json
{
  "version": "b122",
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
          "connected_at": "2026-05-16T10:00:00Z",
          "last_seen": "2026-05-16T12:14:58Z",
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
        }
      ]
    }
  ],
  "update_mirror": {
    "url": "http://vpn.example.com/update",
    "assets": {
      "supervpn-client-windows-amd64.exe": "ok (4521984 bytes)",
      "supervpn-client-darwin-arm64": "ok (5234688 bytes)",
      "supervpn-client-darwin-amd64": "ok (5190144 bytes)",
      "supervpn-client-gui-windows-amd64.exe": "ok (18432000 bytes)",
      "supervpn-client-gui-darwin-arm64": "ok (19922944 bytes)",
      "supervpn-client-gui-darwin-amd64": "ok (20480000 bytes)"
    }
  }
}
```

`tcp_listener_up` / `tcp2_listener_up` — `true` если соответствующий TLS/TCP listener поднялся.  
`udp_listen_2` / `tcp_listen_2` — адреса вторичных слушателей (порт+1) для dual-path.  
`secondary_addr` — адрес клиента на вторичном пути; пусто если клиент подключён по одному каналу.  
`frames_rx` — Ethernet фреймов получено от клиента и отправлено в hub.  
`frames_tx` — Ethernet фреймов отправлено клиенту из hub.  
`mac_table` — текущая MAC-таблица хаба с TTL записей.  
`update_mirror.assets` — какие клиентские бинарники готовы к раздаче.

### `GET http://127.0.0.1:9191/status` (клиент)

```json
{
  "version": "b122",
  "uptime": "45m10s",
  "state": "connected",
  "session": {
    "session_id": 3141592653,
    "server": "vpn.example.com:5555",
    "hub_id": 1,
    "login": "alice",
    "mode": "udp",
    "secondary_addr": "vpn.example.com:5556",
    "connected_at": "2026-05-16T11:30:00Z",
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

**Зеркало по умолчанию** — сервер supervpn сам. Адрес выводится автоматически из
`server` в конфиге клиента: `http://server_host/update` (порт 80, без явного указания).
Явно задавать `update_mirrors` не нужно.

Если нужен нестандартный порт:
```toml
update_mirrors = ["http://vpn.example.com:8080/update"]
```

**Сервер** при старте скачивает недостающие клиентские бинарники с GitHub в `dist/` и раздаёт
их через `GET /update/{asset}` на порту `update_listen`. Директория настраивается через `update_dir`.

`GET /update/` (с trailing slash) возвращает HTML-страницу с листингом доступных файлов и ссылками
для скачивания — удобно для проверки из браузера.

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

**Публикация релизов автоматическая:** каждый `git push origin main` запускает GitHub Actions
(4 параллельных джоба), который прогоняет тесты, собирает все платформы и публикует новый релиз
в supervpn-releases.

**GUI-клиент требует CGo (Fyne)** — не собирается с `CGO_ENABLED=0`.
На macOS: `CGO_ENABLED=1` достаточно. На Windows: нужен MinGW-w64 gcc.

### Вручную

```bash
# Сервер
GOOS=linux GOARCH=amd64 go build -o supervpn-server ./cmd/supervpn-server

# Консольный клиент Windows
GOOS=windows GOARCH=amd64 go build -o supervpn-client.exe ./cmd/supervpn-client

# Консольный клиент macOS
GOOS=darwin GOARCH=arm64 go build -o supervpn-client-arm64 ./cmd/supervpn-client
GOOS=darwin GOARCH=amd64 go build -o supervpn-client-amd64 ./cmd/supervpn-client

# GUI-клиент macOS (требует CGo)
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o supervpn-client-gui-arm64 ./cmd/supervpn-client-gui
CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o supervpn-client-gui-amd64 ./cmd/supervpn-client-gui

# GUI-клиент Windows (требует MinGW-w64)
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui" -o supervpn-client-gui.exe ./cmd/supervpn-client-gui
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

Открыть порты в firewall:
```bash
ufw allow 5555/udp   # VPN UDP primary
ufw allow 5556/udp   # VPN UDP secondary (dual-path)
ufw allow 443/tcp    # VPN TLS primary
ufw allow 444/tcp    # VPN TLS secondary (dual-path)
ufw allow 80/tcp     # update mirror для клиентов
# 9090/tcp — admin API, только loopback (не открывать наружу)
```

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
  supervpn-client/     — точка входа консольного клиента
  supervpn-client-gui/ — точка входа GUI-клиента (Fyne, требует CGo)
internal/
  crypto/              — AES-128-GCM + ReplayWindow (не изменять)
  proto/               — wire format: типы фреймов, заголовки, seq-поля
  fec/                 — Forward Error Correction (Reed-Solomon / XOR)
  transport/           — UDP + TLS/TCP транспорт, knock-and-dial, TCP keepalive
  hub/                 — L2 коммутатор: MAC-таблица + IP-трекинг, forwarding
  bridge/              — детект 169.254, bridge loop
  auth/                — bcrypt/SHA-256 аутентификация
  config/              — TOML конфигурация
  update/              — авто-обновление: GitHub API + зеркала, FetchAsset
  vpnclient/           — общий VPN-движок (Client struct, reconnect loop, статистика)
  clientadapter/       — платформо-зависимое открытие адаптеров (bridge/direct/WinTun)
pkg/
  tun/                 — TAP (Linux/Windows tap0901), WinTun L2 эмуляция (Windows), BPF (macOS bridge), utun (macOS direct)
dist/
  linux/               — сервер + конфиги + systemd unit
  windows/             — клиент + tap-driver + wintun.dll + конфиги
  macos/               — клиент (arm64 + amd64) + конфиги
```

---

## Лицензия

Proprietary. All rights reserved.
