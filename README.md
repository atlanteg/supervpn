# supervpn

Прозрачный L2 VPN с автоматическим восстановлением при потере пакетов.

Аналог SoftEther VPN Bridge + Server + Client, переработанный в два бинарника:
**сервер** (Linux) и **клиент** (Windows, macOS в планах).

---

## Как это работает

```
[Windows клиент]                          [Linux сервер]
  169.254.x.x ──► WinTun ──► Bridge ──► UDP/TCP ──► Hub 1 ──► Bridge ──► 169.254.x.x
  (любой APIPA-интерфейс)      FEC         FEC        Hub 2
                                                       Hub N
```

**Клиент** автоматически обнаруживает сетевые интерфейсы с адресацией `169.254.0.0/16`
(APIPA / link-local) и прозрачно бриджует весь L2-трафик с них на сервер.
Никаких ручных настроек маршрутизации — подключился и работает.

**Сервер** поддерживает несколько независимых Хабов. Каждый Хаб — изолированный
L2-коммутатор: учит MAC-адреса, делает unicast/broadcast, не смешивает трафик между хабами.

**FEC (Forward Error Correction)** — автоматическое восстановление при потере пакетов.
Использует матричный XOR/Reed-Solomon по принципу SMPTE 2022-1 (как в профессиональном
IP-телевидении): на каждые K пакетов добавляется R repair-символов, любые потери
восстанавливаются без retransmit. По умолчанию K=20, R=1 (≈5% overhead, recovers 1 loss).

---

## Особенности

- **Прозрачный L2 мост** — клиент не знает об IP-адресации, работает на уровне Ethernet-фреймов
- **Устойчивость к потере пакетов** — до 5% случайных потерь восстанавливаются на лету без retransmit
- **UDP + TCP fallback** — основной транспорт UDP, автоматически переключается на TCP при блокировке
- **Работает через ТСПУ** — TCP-режим неотличим от TLS-трафика
- **Несколько хабов** — независимые L2-домены на одном сервере
- **Шифрование** — AES-128-GCM с per-session nonce и защитой от replay-атак
- **Аутентификация** — логин + пароль на каждый хаб

---

## Платформы

| Компонент | Платформа | Статус |
|---|---|---|
| supervpn-server | Linux amd64 | в разработке |
| supervpn-client | Windows amd64 | в разработке |
| supervpn-client | macOS amd64/arm64 | планируется |

---

## Структура проекта

```
cmd/
  supervpn-server/     — точка входа сервера
  supervpn-client/     — точка входа клиента
internal/
  crypto/              — AES-128-GCM шифрование + ReplayWindow
  proto/               — wire format: типы фреймов, заголовки
  fec/                 — Forward Error Correction (XOR/Reed-Solomon)
  transport/           — UDP + TCP транспорт
  hub/                 — L2 коммутатор: MAC-таблица, forwarding
  bridge/              — детект 169.254, bridge loop
  auth/                — аутентификация логин/пароль
  config/              — TOML конфигурация
pkg/
  tun/                 — TAP (Linux), WinTun (Windows)
```

---

## Быстрый старт (когда будет готово)

### Сервер

```toml
# /etc/supervpn/server.toml
listen     = "0.0.0.0:5555"
listen_tcp = "0.0.0.0:443"

[[hub]]
id   = 1
name = "main"

  [[hub.user]]
  login         = "alice"
  password_hash = "$2a$10$..."   # supervpn-server hashpw alice

  [[hub.user]]
  login         = "bob"
  password_hash = "$2a$10$..."
```

```bash
supervpn-server -config /etc/supervpn/server.toml
```

### Клиент (Windows)

```
supervpn-client.exe -server vpn.example.com:5555 -hub 1 -login alice -password s3cr3t
```

Клиент сам найдёт интерфейсы с `169.254.x.x` и начнёт бриджевать трафик.

---

## Сборка

```bash
# Требуется Go 1.22+
make build          # server (linux) + client (windows)
make server         # только сервер
make client-windows # только Windows-клиент
make test           # тесты
```

---

## Протокол (кратко)

```
UDP payload:
[ frame_type: 1 ][ hub_id: 2 ][ session_id: 4 ][ seq: 8 ][ encrypted payload ]

Encrypted payload (AES-128-GCM):
[ peer_id: 4 ][ counter: 8 ][ nonce: 12 ][ ciphertext + tag ]

FEC block (K=20, R=1):
data[0..19] → каждые 20 пакетов + 1 repair (XOR всех data)
```

---

## Роадмап

См. [ROADMAP.md](ROADMAP.md).

---

## Лицензия

Proprietary. All rights reserved.
