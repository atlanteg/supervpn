# supervpn — Roadmap

Статусы: ✅ готово | 🔧 в работе | 📋 запланировано | 💡 идея

---

## Фаза 0 — Scaffold ✅

- ✅ Структура проекта (Go модуль, пакеты, build tags)
- ✅ Шифрование AES-128-GCM (перенесено из myvpn, не изменяется)
- ✅ Wire format (proto/packet.go): FrameType, Header
- ✅ FEC скелет: Encoder/Decoder с XOR parity
- ✅ Hub скелет: MAC-таблица, unicast/broadcast forwarding
- ✅ Bridge скелет: детект 169.254.0.0/16, Framer interface
- ✅ Transport: UDP реализация
- ✅ Auth: bcrypt + SHA-256 wire hash
- ✅ Config: TOML структуры
- ✅ pkg/tun: WinTun (Windows) + TAP (Linux)
- ✅ GitHub Actions CI (linux + windows cross-compile, tests)
- ✅ CLAUDE.md с 7 агентами
- ✅ Приватное репо atlanteg/supervpn

---

## Фаза 1 — Рабочий сквозной туннель

Цель: клиент подключается к серверу, аутентифицируется, L2-трафик ходит в обе стороны.
Без FEC, без TCP fallback — только основной путь.

### 1.1 Handshake и аутентификация
- 📋 Протокол handshake: ClientHello → ServerChallenge → ClientAuth → SessionReady
- 📋 Обмен session_id при успешной аутентификации
- 📋 Деривация сессионного ключа из пароля (HKDF как в crypto.go)
- 📋 Таймаут и повтор при неудаче

### 1.2 Сервер — основной loop
- 📋 UDP listener: читает фреймы, парсит Header, роутит по hub_id + session_id
- 📋 Hub manager: создаёт хабы из конфига, хранит map[hubID]*Hub
- 📋 Сессионный менеджер: map[sessionID]*Session, добавление/удаление клиентов
- 📋 Forwarding: Hub.Forward() вызывается для каждого входящего L2-фрейма
- 📋 Ping/Pong keepalive (30s интервал, 90s таймаут)
- 📋 Graceful shutdown

### 1.3 Клиент — основной loop
- 📋 Dial UDP → handshake → получить session_id
- 📋 Запуск bridge.RunUpstream() в горутине
- 📋 Receive loop: получать фреймы с сервера → bridge.Inject()
- 📋 Keepalive ping
- 📋 Reconnect при потере соединения (exponential backoff)

### 1.4 Windows клиент — WinTun интеграция
- 📋 Создание WinTun адаптера при старте
- 📋 ReadFrame / WriteFrame через wintun.Session
- 📋 Установка IP-адреса на WinTun интерфейсе (необязательно — мы L2)
- 📋 Сборка как Windows Service (golang.org/x/sys/windows/svc)
- 📋 Инсталлятор (NSIS или WiX) с wintun.dll в комплекте

### 1.5 Конфигурация и утилиты
- 📋 Парсинг TOML конфига (сервер + клиент)
- 📋 `supervpn-server hashpw <password>` — генерация bcrypt хеша
- 📋 `supervpn-server status` — список хабов и клиентов

---

## Фаза 2 — FEC: устойчивость к потере пакетов

Цель: случайные потери до 5% восстанавливаются на лету без retransmit.

### 2.1 Полная реализация Reed-Solomon
- 📋 Замена XOR parity на Reed-Solomon над GF(2^8)
- 📋 Поддержка R > 1 (восстановление нескольких потерь в блоке)
- 📋 Тесты: инжект N% случайных потерь, проверка восстановления
- 📋 Бенчмарки: overhead vs скорость при разных K/R

### 2.2 FEC в транспорте
- 📋 Encoder встраивается в send-path на клиенте и сервере
- 📋 Decoder встраивается в receive-path
- 📋 Repair-фреймы передаются в том же UDP потоке (FrameRepair тип)
- 📋 Block reordering tolerance: буфер на M блоков вперёд

### 2.3 Адаптивный FEC
- 📋 Мониторинг реального процента потерь (скользящее окно)
- 📋 Автоматическая корректировка R при росте потерь
- 📋 Конфиг: min_r, max_r, target_loss_rate

---

## Фаза 3 — TCP fallback и ТСПУ-совместимость

Цель: работа в сетях с UDP-блокировкой (ТСПУ, корпоративные firewalls).

### 3.1 TCP транспорт
- 📋 TLS 1.3 обёртка поверх TCP (SNI mimicry — выглядит как HTTPS)
- 📋 Framing поверх TCP: length-prefixed frames (2 байта длина + данные)
- 📋 Тот же wire format внутри TLS

### 3.2 Автопереключение UDP → TCP
- 📋 Клиент пробует UDP первым (3 попытки × 1s)
- 📋 При неудаче — автоматически TCP
- 📋 Периодическая проверка возврата на UDP (каждые 5 минут)

### 3.3 Обфускация (опционально)
- 💡 Рандомизация размеров пакетов (padding до ближайшего 128/256)
- 💡 Имитация TLS Application Data record structure
- 💡 Configurable SNI для TCP режима

---

## Фаза 4 — Управление и мониторинг

### 4.1 Сервер API
- 📋 HTTP JSON API на localhost:
  - `GET /api/hubs` — список хабов
  - `GET /api/hubs/{id}/clients` — клиенты в хабе
  - `POST /api/hubs/{id}/kick/{session}` — дисконнект клиента
  - `GET /api/metrics` — Prometheus metrics
- 📋 Prometheus метрики: bytes_in/out per hub, active_sessions, packet_loss_rate, fec_recovered

### 4.2 CLI управление
- 📋 `supervpn-ctl` — CLI клиент к серверному API
- 📋 Горячая перезагрузка конфига (SIGHUP)

### 4.3 Логирование
- 📋 Структурированные логи (slog)
- 📋 Ротация логов
- 📋 Debug-режим: dump фреймов (без payload)

---

## Фаза 5 — Качество и production-ready

### 5.1 Тестирование
- 📋 Unit тесты: FEC (все комбинации потерь), Hub forwarding, crypto round-trip
- 📋 Integration тесты: виртуальная сеть (veth pairs), клиент↔сервер без реального железа
- 📋 Loss simulation: `tc netem loss 5%` в CI для проверки FEC
- 📋 Нагрузочные тесты: N клиентов, X Mbit/s, проверка CPU/RAM

### 5.2 Безопасность
- 📋 Security review: nonce uniqueness при session restart
- 📋 Rate limiting: max подключений с одного IP
- 📋 Blocklist сессий (kick + запрет переподключения)

### 5.3 Деплой
- 📋 systemd unit файл для сервера
- 📋 Docker образ сервера
- 📋 Windows installer (.msi или NSIS) с wintun.dll + Windows Service
- 📋 GitHub Releases с автоматической публикацией бинарников

---

## Фаза 6 — macOS клиент

- 💡 pkg/tun/tun_darwin.go — утилита через /dev/tap или utun
- 💡 macOS app bundle (launchd service)
- 💡 Универсальный бинарник (amd64 + arm64)

---

## Технический долг и известные ограничения

| Ограничение | Когда исправить |
|---|---|
| FEC: только XOR (R=1), нет полного RS | Фаза 2 |
| tun_windows.go: WaitForSingleObject без таймаута | Фаза 1.4 |
| hub.go: импорт net только для документации | Фаза 1.2 |
| config.go: TOML не парсится, только структуры | Фаза 1.5 |
| Нет reconnect логики на клиенте | Фаза 1.3 |
| Нет keepalive | Фаза 1.2 |

---

## Зависимости

| Пакет | Назначение |
|---|---|
| `golang.org/x/crypto` | HKDF, bcrypt |
| `golang.org/x/sys` | Linux syscalls, Windows API |
| `golang.zx2c4.com/wintun` | Windows TUN driver |
| TBD: `github.com/BurntSushi/toml` | TOML конфиг |
| TBD: `github.com/klauspost/reedsolomon` | Reed-Solomon GF(2^8) для Фазы 2 |
