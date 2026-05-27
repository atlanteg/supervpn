# bmwzgw

Автономный Go-пакет для обнаружения BMW ZGW (Central Gateway) по сети ENET.

Ноль внешних зависимостей — только стандартная библиотека Go.  
Работает на **Windows** и **macOS/Linux** без изменений.

---

## Что делает

Обнаруживает BMW автомобиль, подключённый кабелем ENET к сетевому интерфейсу компьютера:

1. **Этап интерфейса** — как только появляется NIC с адресом `169.254.x.x`, сразу вызывает `onChange` с IP (VIN пустой). Машина видна моментально, до любого UDP-обмена.
2. **Этап ZGW** — отправляет UDP-зонд на `255.255.255.255:6811` и `169.254.255.255:6811`, ждёт ответа с VIN. При получении вызывает `onChange` с заполненными VIN, Model, Chassis, Target.

Каждые 5 секунд повторяет зондирование. Если ZGW перестаёт отвечать — возвращается к интерфейсному режиму.

### Что возвращает

```
IP      "169.254.138.176"
MAC     "48:C5:8D:90:51:5C"
VIN     "WBA8X51000CF40263"
Model   "F34 320i xDrive"
Chassis "F34"
Target  "F020"          ← ISTA ECU target ID
```

**Target** вычисляется из поля `DIAGADR` в ответе ZGW: `DIAGADR "10"` → `0x10 × 2 = 0x20` → `"F020"`.

**Model** декодируется из VIN по таблице BMW Baumuster (VIN[3] = тип кузова, VIN[4] = привод, VIN[5] = двигатель).  
Поддерживаются E-series, F-series (2011–2019), G-series (2019–).

---

## Установка

```bash
go get github.com/atlanteg/bmwzgw
```

Или просто скопируйте папку в свой проект и поменяйте строку модуля в `go.mod`.

---

## Использование

### Непрерывный мониторинг (рекомендуется)

```go
package main

import (
    "context"
    "fmt"
    "os/signal"
    "syscall"

    "github.com/atlanteg/bmwzgw"
)

func main() {
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    bmwzgw.Run(ctx, "", func(info *bmwzgw.Info) {
        // вызывается в фоновой горутине при каждом изменении
        fmt.Println(bmwzgw.FormatBMW(info))
    })
}
```

Вывод:
```
BMW: 169.254.138.176 (no ZGW response)          ← кабель воткнут, ZGW ещё не ответил
BMW: 169.254.138.176  WBA8X51000CF40263  F34 320i xDrive  F020   ← ZGW ответил
BMW: not found                                   ← кабель вытащили
```

### Параметр skipIfaceName

Если ваше приложение создаёт виртуальный сетевой адаптер с адресом `169.254.x.x` (VPN, TAP и т.п.), передайте его имя чтобы он не принимался за BMW:

```go
bmwzgw.Run(ctx, "supervpn", func(info *bmwzgw.Info) { ... })
bmwzgw.Run(ctx, "tap0",     func(info *bmwzgw.Info) { ... })
```

### Одиночный запрос (без горутины)

```go
info := bmwzgw.Discover("169.254.138.100") // IP вашего NIC
if info != nil {
    fmt.Println(info.VIN, info.Model, info.Target)
}
```

Ждёт ответа 1.5 секунды, возвращает `nil` если ZGW не ответил.

### Использование полей Info напрямую

```go
bmwzgw.Run(ctx, "", func(info *bmwzgw.Info) {
    if info == nil || info.VIN == "" {
        return // нет машины или VIN ещё не известен
    }
    updateUI(info.IP, info.VIN, info.Model, info.Target, info.MAC)
})
```

---

## ZGW — протокол

**Зонд (6 байт):**
```
00 00 00 00 00 11
```
`0x0011 = 17` — длина VIN. ZGW игнорирует зонды короче 6 байт.

**Ответ ZGW (пример):**
```
00 00 00 32 00 11 DIAGADR10 BMWMAC48C58D90515C BMWVINWBA8X51000CF40263
```

| Поле | Пример | Описание |
|------|--------|----------|
| `DIAGADR` | `10` | hex, адрес ECU / 2 = ISTA target |
| `BMWMAC` | `48C58D90515C` | MAC-адрес ZGW |
| `BMWVIN` | `WBA8X51000CF40263` | VIN, 17 символов ISO 3779 |

**Порт:** `6811 UDP`  
**Источник зонда:** пакет отправляется как с порта `6811` (через постоянный rx-сокет), так и с эфемерных портов, привязанных к каждому `169.254.x.x` интерфейсу, — чтобы гарантировать прохождение через нужный NIC.

---

## Поддерживаемые модели (VIN[3])

| Ключ | Шасси | Серия |
|------|-------|-------|
| `1` | E87 | 1 Series |
| `9` | E90 | 3 Series |
| `2` | F20 | 1 Series |
| `3` | F30 | 3 Series |
| `4` | F32 | 4 Series |
| `5` | F10 | 5 Series |
| `6` | F12 | 6 Series |
| `7` | F01 | 7 Series |
| `8` | F34 | 3 GT |
| `A` | F15 | X5 |
| `B` | F16 | X6 |
| `C` | F25 | X3 |
| `D` | F26 | X4 |
| `E` | F45 | 2 Series AT |
| `F` | F48 | X1 |
| `G` | F39 | X2 |
| `H` | G20 | 3 Series |
| `J` | G30 | 5 Series |
| `K` | G11 | 7 Series |
| `L` | G01 | X3 |
| `M` | G02 | X4 |
| `N` | G05 | X5 |
| `P` | G06 | X6 |
| `R` | G07 | X7 |
| `S` | G29 | Z4 |
| `T` | G42 | 2 Series |
| `U` | G80 | M3 |
| `V` | G82 | M4 |
| `W` | G26 | 4 Series GC |
| `X` | G22 | 4 Series |
| `Y` | G15 | 8 Series |
| `Z` | G16 | 8 Series GC |

Если ваш автомобиль не в списке — откройте issue или PR с VIN (первые 6 символов достаточно).

---

## Требования

- Go 1.21+
- Windows, macOS или Linux
- На Windows: права на создание UDP-сокета на порту 6811 (обычно достаточно запуска от обычного пользователя; если порт занят Remote Enet — пакет работает совместно через SO_REUSEADDR)
