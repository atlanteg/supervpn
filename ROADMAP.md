# supervpn — Roadmap

Статусы: ✅ готово | 🔧 в работе | 📋 запланировано | 💡 идея

---

## Фаза 0 — Scaffold ✅

- ✅ Структура проекта (Go модуль, пакеты, build tags)
- ✅ Шифрование AES-128-GCM (перенесено из myvpn, не изменяется)
- ✅ Wire format (proto/packet.go): FrameType, Header
- ✅ FEC: XOR (R=1) + Reed-Solomon (R>1) с тестами — Encoder/Decoder API готов
- ✅ Hub скелет: MAC-таблица, unicast/broadcast forwarding
- ✅ Bridge скелет: детект 169.254.0.0/16, Framer interface
- ✅ Transport: UDP реализация
- ✅ Auth: bcrypt + SHA-256 wire hash
- ✅ Config: TOML структуры
- ✅ pkg/tun: WinTun (Windows) + TAP (Linux)
- ✅ GitHub Actions CI (4 джоба: ubuntu server+CLI, macOS GUI matrix, Windows GUI, release)
- ✅ CLAUDE.md с 7 агентами
- ✅ Приватное репо atlanteg/supervpn

---

## Фаза 1 — Рабочий сквозной туннель

Цель: клиент подключается к серверу, аутентифицируется, L2-трафик ходит в обе стороны.
Без FEC, без TCP fallback — только основной путь.

### 1.1 Handshake и аутентификация
- ✅ Протокол handshake: ClientHello → ServerChallenge → ClientAuth → SessionReady
- ✅ Обмен session_id при успешной аутентификации
- ✅ Деривация сессионного ключа из пароля (HKDF как в crypto.go)
- ✅ Таймаут и повтор при неудаче

### 1.2 Сервер — основной loop
- ✅ UDP listener: читает фреймы, парсит Header, роутит по hub_id + session_id
- ✅ Hub manager: создаёт хабы из конфига, хранит map[hubID]*Hub
- ✅ Сессионный менеджер: map[sessionID]*Session, добавление/удаление клиентов
- ✅ Forwarding: Hub.Forward() вызывается для каждого входящего L2-фрейма
- ✅ Ping/Pong keepalive (25s ping, 90s сессионный таймаут)
- ✅ Graceful shutdown (context cancellation)

### 1.3 Клиент — основной loop
- ✅ Dial UDP → handshake → получить session_id
- ✅ Запуск bridge.RunUpstream() в горутине
- ✅ Receive loop: получать фреймы с сервера → bridge.Inject()
- ✅ Keepalive ping
- ✅ Reconnect при потере соединения (exponential backoff)

### 1.4 Windows клиент — WinTun интеграция
- ✅ Создание WinTun адаптера при старте
- ✅ ReadFrame / WriteFrame через wintun.Session
- ✅ WinTun L2 эмуляция (windowsTUNL2): виртуальный MAC, ARP-кэш, inject-канал; обходит NDIS LWF (FortiClient, OpenVPN)
- ✅ Direct mode: WinTun L2 primary, tap-windows6 fallback
- ✅ Фикс ARP-инжекта: readIPOnce с 50ms timeout вместо бесконечного блока
- 📋 Установка IP-адреса на WinTun интерфейсе (необязательно — мы L2)
- 📋 Сборка как Windows Service (golang.org/x/sys/windows/svc)
- 📋 Инсталлятор (NSIS или WiX) с wintun.dll в комплекте

### 1.5 Конфигурация и утилиты
- ✅ Парсинг TOML конфига (сервер + клиент, BurntSushi/toml)
- ✅ `supervpn-server hashpw <password>` — генерация bcrypt хеша
- ✅ Все параметры конфига доступны как CLI-флаги (перекрывают .toml)
- 📋 `supervpn-server status` — список хабов и клиентов (HTTP API, Фаза 4)

---

## Фаза 2 — FEC ✅

Цель: случайные потери до 5% восстанавливаются на лету без retransmit.

### 2.1 Полная реализация Reed-Solomon
- ✅ Замена XOR parity на Reed-Solomon над GF(2^8) (github.com/klauspost/reedsolomon)
- ✅ Поддержка R > 1 (восстановление нескольких потерь в блоке)
- ✅ Тесты: потери от 1 до R пакетов, out-of-order, block expiry
- ✅ Бенчмарки: overhead vs скорость при разных K/R

### 2.2 FEC в транспорте
- ✅ FECPipe реализован: прозрачный encode/decode wrapper для сессий
- ✅ Repair-фреймы передаются через FrameRepair (PackRepairSeq/UnpackRepairSeq)
- ✅ FECPipe интегрирован в сервер
- ✅ FECPipe интегрирован в клиент
- ✅ Encoder встраивается в send-path (через FECPipe)
- ✅ Decoder встраивается в receive-path (через FECPipe)
- ✅ Repair-фреймы передаются в том же UDP потоке (FrameRepair тип)
- ✅ Block reordering tolerance: буфер на 8 блоков вперёд (maxOldBlocks)
- ✅ FEC mismatch detection: клиент сравнивает K/R из repair-заголовка с конфигом, при несоответствии — лог + disconnect

### 2.3 Адаптивный FEC
- 📋 Мониторинг реального процента потерь (скользящее окно)
- 📋 Автоматическая корректировка R при росте потерь
- 📋 Конфиг: min_r, max_r, target_loss_rate

---

## Фаза 3 — TCP fallback и ТСПУ-совместимость

Цель: работа в сетях с UDP-блокировкой (ТСПУ, корпоративные firewalls).

### 3.1 TCP транспорт
- ✅ TLS 1.3 обёртка поверх TCP (SNI mimicry, self-signed cert, InsecureSkipVerify)
- ✅ Framing поверх TCP: length-prefixed frames (2 байта длина + данные) — TCPTransport готов
- ✅ TLSTransport: DialTLS, ListenTLS, AcceptTLS, NewServerTLSConfig

### 3.2 Автопереключение UDP → TCP ✅
- ✅ Клиент пробует UDP первым (3 s timeout на auth)
- ✅ При неудаче — автоматически TLS/TCP (server_tcp)
- ✅ Периодическая проверка возврата на UDP (каждые 5 минут)
- ✅ Сервер принимает TLS/TCP соединения (ListenTLS, per-conn goroutine)
- ✅ Тот же wire format внутри TLS (length-prefixed frames, FrameData/Repair/Ping/Auth)

### 3.3 UDP Knock-and-dial ✅
- ✅ Перед каждой UDP auth-попыткой: N случайных пакетов на том же сокете (одинаковый 5-tuple)
- ✅ UDPConfig: knock_count, knock_size, attempts — настраивается через TOML
- ✅ Несколько последовательных knock→auth циклов перед фолбеком на TLS

### 3.4 Обфускация (опционально)
- 💡 Рандомизация размеров пакетов (padding до ближайшего 128/256)
- 💡 Имитация TLS Application Data record structure
- 💡 Configurable SNI для TCP режима

---

## Фаза 4 — Управление и мониторинг

### 4.1 Сервер API ✅ (частично)
- ✅ `GET /status` — все хабы и подключённые клиенты (login, IP, mode, duration) — JSON
- ✅ `POST /api/hubs/{id}/kick/{session}` — дисконнект клиента
- 📋 `GET /api/hubs` / `GET /api/hubs/{id}/clients` — отдельные REST endpoints (если нужны)
- 📋 `GET /api/metrics` — Prometheus metrics
- 📋 Prometheus метрики: bytes_in/out per hub, active_sessions, packet_loss_rate, fec_recovered

### 4.2 Клиент API ✅
- ✅ `GET /status` — текущий режим (udp/tls), состояние, server, hub, session_id, duration

### 4.3 CLI управление
- 📋 `supervpn-ctl` — CLI клиент к серверному API
- 📋 Горячая перезагрузка конфига (SIGHUP)

### 4.4 Логирование
- 📋 Структурированные логи (slog)
- 📋 Ротация логов
- 📋 Debug-режим: dump фреймов (без payload)

---

## Фаза 5 — Качество и production-ready

### 5.1 Тестирование
- ✅ Unit тесты: hub forwarding, crypto round-trip
- ✅ FEC (все комбинации потерь)
- ✅ proto marshal/parse tests
- ✅ auth tests
- ✅ transport TCP tests
- ✅ bridge routing tests
- ✅ Loss simulation: end-to-end 5% random + burst loss recovery tests
- 📋 Integration тесты: виртуальная сеть (veth pairs), клиент↔сервер без реального железа
- 📋 Loss simulation: `tc netem loss 5%` в CI для проверки FEC
- 📋 Нагрузочные тесты: N клиентов, X Mbit/s, проверка CPU/RAM

### 5.2 Безопасность
- ✅ Security review: nonce uniqueness при session restart — random 4-byte salt per session в `crypto.NewCipher`, гарантирует уникальность nonce даже при коллизии session ID
- ✅ Blocklist после kick — kicked login блокируется на 5 минут, `handleAuth` отклоняет reconnect
- 📋 Rate limiting: max подключений с одного IP

### 5.3 Деплой ✅ (частично)
- ✅ systemd unit файл для сервера (`deploy/supervpn-server.service`)
- ✅ Docker образ сервера (`Dockerfile`, multi-stage, scratch)
- ✅ GitHub Releases с автоматической публикацией бинарников (`.github/workflows/release.yml`, тег `v*`)
- 📋 Windows installer (.msi или NSIS) с wintun.dll + Windows Service

---

## Фаза 6 — macOS клиент ✅ (базовый)

- ✅ `pkg/tun/tun_darwin.go` — native utun через SYSPROTO_CONTROL / CTLIOCGINFO
- ✅ Dual-mode client: bridge mode (169.254 найден) + direct mode (standalone TUN)
- ✅ `tun.Namer` interface — auto-assigned kernel name (utun0, utun1…)
- 💡 macOS app bundle / launchd service
- 💡 Универсальный бинарник (amd64 + arm64)

---

## Фаза 7 — GUI-клиент ✅

- ✅ Фреймворк: Fyne (CGo, нативный рендеринг: Metal macOS, OpenGL/DX Windows)
- ✅ `cmd/supervpn-client-gui/` — оконный клиент (без трей-иконки)
- ✅ 3 вкладки: Connection (сервер, логин, пароль, хаб, режим, транспорт), Advanced (FEC, TLS, UDP, Bridge, TUN), Log
- ✅ Загрузка конфига из `.toml` через Browse
- ✅ Индикатор состояния (цветная точка + текст: Disconnected / Connecting / Connected / Reconnecting)
- ✅ Лог VPN-движка в реальном времени (кольцевой буфер 500 строк)
- ✅ Общий VPN-движок через `internal/vpnclient` и `internal/clientadapter` (код не дублируется)
- ✅ Авто-обновление (GUI-специфичные бинарники: `supervpn-client-gui-*`)
- ✅ Windows: подавление консоли через `-H windowsgui` + `FreeConsole()`
- ✅ CI: macOS matrix (macos-13 amd64, macos-latest arm64), Windows (MSYS2 MinGW)
- ✅ Сервер раздаёт GUI-бинарники через `/update` (добавлены в `clientAssets`)
- 📋 Список серверов в выпадающем меню (пока пустой, пользователь добавляет вручную)
- 💡 Трей-иконка (опционально)

---

## Технический долг и известные ограничения

| Ограничение | Когда исправить |
|---|---|
| ~~FEC: только XOR (R=1), нет полного RS~~ | ✅ Исправлено |
| ~~tun_windows.go: WaitForSingleObject без таймаута~~ | ✅ Исправлено |
| ~~hub.go: импорт net только для документации~~ | ✅ Исправлено |
| ~~config.go: TOML не парсится, только структуры~~ | ✅ Исправлено |
| ~~Нет reconnect логики на клиенте~~ | ✅ Исправлено |
| ~~Нет keepalive~~ | ✅ Исправлено |

---

## Зависимости

| Пакет | Назначение |
|---|---|
| `golang.org/x/crypto` | HKDF, bcrypt |
| `golang.org/x/sys` | Linux syscalls, Windows API |
| `golang.zx2c4.com/wintun` | Windows TUN driver |
| `github.com/BurntSushi/toml` | TOML конфиг |
| `github.com/klauspost/reedsolomon` | Reed-Solomon GF(2^8) |
