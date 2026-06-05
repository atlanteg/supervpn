# bmwzgw

Автономный Go-пакет для обнаружения BMW ZGW (Central Gateway) по сети ENET и декодирования VIN.

**Ноль внешних зависимостей** — только стандартная библиотека Go.  
Работает на **Windows**, **macOS** и **Linux** без изменений.

---

## Что делает

Обнаруживает BMW, подключённый кабелем ENET к сетевому интерфейсу компьютера, и возвращает полную информацию о машине:

1. **Этап интерфейса** — как только появляется NIC с адресом `169.254.x.x`, сразу вызывает `onChange` с IP (VIN пустой). Машина видна до любого UDP-обмена.
2. **Этап ZGW** — отправляет UDP-зонд на `255.255.255.255:6811` и `169.254.255.255:6811`, ждёт ответа ZGW с VIN. При получении вызывает `onChange` с заполненными полями `Info`.

Каждые 5 секунд повторяет зондирование. Если ZGW перестаёт отвечать — возвращается к этапу интерфейса.

### Пример вывода

```
IP       "169.254.138.176"
MAC      "48:C5:8D:90:51:5C"
VIN      "WBA5R7C0XLFH66853"
Model    "G20 330i xDrive"
Chassis  "G20"
Platform "S18A"
Engine   "B46B20"
PowerKW  185
Body     "Sedan"
```

---

## Установка

```bash
go get github.com/atlanteg/bmwzgw
```

Или скопируйте папку `bmwzgw/` в свой проект и поменяйте строку модуля в `go.mod`.  
Файл `bmw_types.csv` обязательно должен лежать рядом с `.go`-файлами.

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

    bmwzgw.Run(ctx, "supervpn", func(info *bmwzgw.Info) {
        if info == nil {
            fmt.Println("BMW: не найден")
            return
        }
        if info.VIN == "" {
            fmt.Printf("BMW: %s (кабель подключён, жду ZGW…)\n", info.IP)
            return
        }
        fmt.Printf("BMW: %s  %s  %s  %s  %s %dkW  %s\n",
            info.IP, info.VIN, info.Model, info.Platform,
            info.Engine, info.PowerKW, info.Body)
    })
}
```

Второй параметр `"supervpn"` — имя виртуального адаптера, который нужно **игнорировать**. Если VPN/TAP нет — передайте `""`.

### Одиночный запрос

```go
info := bmwzgw.Discover("169.254.138.100") // IP вашего NIC
if info != nil {
    fmt.Printf("Chassis=%s  Platform=%s  Engine=%s  %dkW\n",
        info.Chassis, info.Platform, info.Engine, info.PowerKW)
}
```

Ждёт ответа 1.5 секунды, возвращает `nil` если ZGW не ответил.

---

## Структура Info

```go
type Info struct {
    IP       string // ZGW IP, напр. "169.254.138.176"
    MAC      string // MAC ZGW, напр. "48:C5:8D:90:51:5C"
    VIN      string // 17-символьный VIN; "" пока ZGW не ответил
    Model    string // напр. "G20 330i xDrive"
    Chassis  string // код шасси, напр. "G20"
    Platform string // программная платформа ISTA, напр. "S18A"
    Target   string // ECU-адрес из DIAGADR×2 (для внутреннего использования)

    // Заполняются из bmw_types.csv; пустые/0 если модель не найдена в базе:
    Engine  string // код двигателя, напр. "B46B20"
    PowerKW int    // мощность в кВт, напр. 185
    Body    string // тип кузова: "Sedan", "Touring", "Coupe", …
}
```

**Platform** — идентификатор программной платформы ISTA. Нужен для выбора правильного ECU-дерева при диагностике:

| Platform | Автомобили |
|----------|-----------|
| `F001` | 7 Series F01/F02 (2008–2015) |
| `F010` | 5 Series F07/F10/F11, 6 Series F12/F13 (2010–2017) |
| `F020` | 1/2/3/4 Series F20–F36, M3 F80, M4 F82/F83 (2011–2019) |
| `F025` | X3 F25, X4 F26, X5 F15/F85, X6 F16/F86 (2011–2019) |
| `F056` | X1 F40/F48, X2 F39, 2AT F45/F46 (FWD, 2014–2022) |
| `S15A` | 5 Series G30/G31/G32, 7 Series G11/G12, X3 G01/F97, X4 G02/F98, M5 F90 |
| `S18A` | 3/4 Series G20–G26, X5 G05, X6 G06, X7 G07, 8 Series G14–G16, Z4 G29, M2–M4 |
| `S15C` | X3 G08 (Китай) |
| `G045` | iX G45/G46/G48 |
| `G070` | 5 Series G60, 7 Series G70, M5 G84/G90 |

---

## Как работает декодирование VIN

BMW использует **4-символьный внутренний тип-ключ** (Baumuster, VIN[3:7]).  
Декодер работает каскадом — от самого точного к фоллбэкам:

```
VIN = W B A 5 R 7 C 0 X L F H 6 6 8 5 3
      0 1 2 3 4 5 6 7 8 9 ...
          WMI ^   ^VIN[3:7] type key^   ^VIN[8]=check ^VIN[9]=год
```

**Шаг 1 — FA-обученная таблица (`faTypeKeys`, VIN[3:7]). Основной путь, ~99%.**  
Полный 4-символьный тип-ключ ищется в таблице, обученной на реальных BMW FA-бэкапах
(`fa_typekeys.go`, ~725 ключей). Даёт шасси + модель (напр. `330i`) + xDrive.  
Пример: `5R7C` → G20 330i xDrive. Платформа — из `faChassisPlatform` (реальный I-Step),
функция `platformForChassis`.

**Шаг 2 — двухсимвольный поиск (`bmwType2Keys`, VIN[3]+VIN[4]).**  
Если ключ не в FA-таблице. Покрывает 90+ подтверждённых комбинаций.

**Шаг 3 — поколенческое разрешение (`gseriesIntroMY` + `fseriesAltKeys`, VIN[3]+VIN[9]).**  
Для букв, переиспользованных между F- и G-поколениями: VIN[9] (ISO model-year;
VIN[8] — контрольная цифра) определяет эпоху.  
Пример: `K` + VIN[9]<`G` → F15 X5; `K` + VIN[9]≥`G` → G11/G12 7 Series.

**Шаг 4 — однобуквенный поиск (`bmwTypeKeys`, VIN[3]).**  
Финальный фоллбэк: самый распространённый вариант для каждой буквы.

> Файлы `fa_typekeys.go` / `fa_platform.go` — **генерируются** скриптом
> `tools/vin-retrain/retrain.py` из FA-данных, руками не править.

---

## Поддерживаемые модели

### Однобуквенные ключи VIN[3] (фоллбэк если VIN[4] не в таблице)

| Ключ | Шасси | Серия | Примечание |
|------|-------|-------|------------|
| `1` | F20/F21 | 1 Series F-gen | также G30, G08 на этом ключе |
| `2` | F45/F46 | 2 AT/GT FWD | также G02, G20, G07 |
| `3` | F30/F31 | 3 Series F-gen | по умолчанию F30 sedan |
| `4` | F36 | 4 Series Gran Coupé | по умолчанию F36 |
| `5` | F10/F11 | 5 Series F-gen | также G01, G20, G22 |
| `6` | F12 | 6 Series | |
| `7` | G11/G12 | 7 Series G-gen | |
| `8` | F30/F31 | 3 Series F-gen | F34 GT тоже на `8` |
| `9` | E90/E91 | 3 Series E-gen | |
| `A` | F15 | X5 | |
| `B` | F16 | X6 | |
| `C` | G05 | X5 G-gen | |
| `D` | F26 | X4 F-gen | немецкий завод |
| `E` | F45 | 2 Active Tourer FWD | |
| `F` | F48 | X1 FWD | BMW SA также кодирует F10 на `F` |
| `G` | F39 | X2 FWD | |
| `H` | G29 | Z4 | до MY2019: F48 X1 FWD |
| `J` | G30/G31 | 5 Series G-gen | |
| `K` | G11/G12 | 7 Series G-gen | до MY2016: F15 X5 |
| `L` | F13 | 6 Series Coupé | |
| `M` | G02 | X4 G-gen | не верифицировано FA XML |
| `N` | G05 | X5 G-gen | не верифицировано |
| `P` | G06 | X6 G-gen | не верифицировано |
| `R` | G07 | X7 | не верифицировано |
| `S` | G29 | Z4 | не верифицировано |
| `T` | G01 | X3 G-gen | TA→G05, TB→G07, TC→G06 |
| `U` | G01 | X3 G-gen | UJ→F98 X4M |
| `V` | G82/G83 | M4 | VJ→G02 X4 |
| `W` | G26 | 4 Series GC G-gen | до MY2022: F25 X3 |
| `X` | F26 | X4 (BMW SA) | XA/XG/XH→F10 BMW SA |
| `Y` | F39 | X2 FWD | YB/YC→F01, YM→F13, YP→F12 |
| `Z` | G16 | 8 Series GC | не верифицировано |

### Двухсимвольные ключи VIN[3]+VIN[4] (фоллбэк, 90+ записей)

Используется когда полный 4-символьный ключ не найден в FA-таблице `faTypeKeys`.
Полная таблица — в `zgw.go`, переменная `bmwType2Keys`. Ниже — важные группы:

| VIN[3]+[4] | Шасси | Что это | VINs |
|------------|-------|---------|------|
| `CW`, `CX` | G07 | X7 xDrive | 236 |
| `JD`, `JF`, `JE`, `JB` | G30 | 5 Series G sedan | 494 |
| `JP`, `JM`, `JL` | G31 | 5 Series G Touring | 42 |
| `JV`, `JW`, `JX` | G32 | 6 Series GT | 46 |
| `CY` | G06 | X6 G-gen | 68 |
| `GT` | G06 | X6 G-gen | 108 |
| `GV`, `GW` | G16 | 8 Series GC | 42 |
| `5U`, `5R`, `5V`, `5P`, `5F`, `5X`, `5W` | G20/G21 | 3 Series G sedan | 173 |
| `53` | G22/G23 | 4 Series G | — |
| `57` | G01 | X3 G BMW SA | — |
| `3A`–`3D` | F30 | 3 Series sedan | 210 |
| `3K`, `3L` | F31 | 3 Series Touring | 46 |
| `3X`, `3Y`, `3Z` | F34 | 3 Series GT | 64 |
| `3V` | F33 | 4 Series Convertible | — |
| `3R`, `3U` | F82/F83 | M4 | 12 |
| `8T`, `8X`, `8Y`, `8Z` | F34 | 3 Series GT | 92 |
| `8H`, `8J` | F31 | 3 Series Touring | 22 |
| `8M` | F80 | M3 | 8 |
| `7U`, `7T`, `7J`, `7H`, `7V` | G12 | 7 Series LWB | 58 |
| `7K`, `7L`, `7M`, `7N` | F40 | 1 Series G FWD | 42 |
| `71`, `73` | G30 | 5 Series G | 42 |
| `KV`, `KU` | F16 | X6 F-gen | 84 |
| `KT` | F85 | X5M | 24 |
| `KW` | F86 | X6M | 14 |
| `KB`, `KC`, `KM` | F01/F02 | 7 Series F-gen | 65 |
| `FW`, `FP`, `FU`, `FR`, `FV` | F10/F11 | 5 Series BMW SA | 90 |
| `HF` | G29 | Z4 | — |
| `HS`, `HY` | F48 | X1 FWD | — |
| `JG`, `JH`, `JJ` | F48 | X1 FWD | 52 |
| `JU` | G05 | X5 G-gen | 38 |
| `VJ` | G02 | X4 G-gen | 38 |
| `BC` | G15 | 8 Series Coupé | 52 |
| `TA`, `TC` | G05/G06 | X5/X6 G-gen | 22 |
| `TB` | G07 | X7 | 4 |
| `41`, `43` | G80 | M3 | 46 |
| `21`, `23` | G07 | X7 | 60 |
| `YB`, `YC` | F01 | 7 Series F-gen | 37 |
| `YM`, `YP` | F13/F12 | 6 Series | 18 |
| `SP`, `SN` | F07 | 5-series GT | 31 |
| `MX` | F11 | 5 Series Touring | 31 |
| `UJ` | F98 | X4M | 12 |
| `XA`, `XG`, `XH` | F10/F11 | 5 Series BMW SA | 55 |
| ... и ещё 30+ записей | | | |

---

## Дообучение по FA XML

Основная таблица `faTypeKeys` (полный 4-символьный VIN[3:7]) и
`faChassisPlatform` (шасси→платформа) **обучаются на реальных BMW FA-бэкапах** —
файлах «Fahrzeugauftrag» из VCM MASTER, где есть авторитетные `vinLong`,
`series` (шасси), `typeKey` (= VIN[3:7]), имя модели и I-Step платформа.

### Метрики точности (на обучающей выборке ~1945 VIN)

| Метод | Шасси | Платформа |
|-------|-------|-----------|
| только однобуквенная эвристика VIN[3] | ~43% | ~63% |
| **+ FA-таблица 4-симв. VIN[3:7]** | **~99.6%** | **~99.7%** |

4-символьный тип-ключ уникален по шасси на ~98%, поэтому FA-таблица — основной
путь, а 1/2-символьные таблицы остаются фоллбэком для незнакомых ключей.

### Как переобучить (одной командой)

```bash
# каталог с FA-файлами (*.xml и/или *.zip), напр. tests_FA_all
python3 tools/vin-retrain/retrain.py PATH_TO_FA_DIR
gofmt -w internal/zgw/fa_*.go standalone/bmwzgw/fa_*.go
go test ./internal/zgw -run FAAccuracy -v    # точность + топ ошибок
```

Скрипт перегенерирует `fa_typekeys.go` + `fa_platform.go` **в обоих** местах
(`internal/zgw` и `standalone/bmwzgw`). Сырые FA-архивы не коммитятся
(gitignore) — только сгенерированные таблицы. Полное описание:
[`docs/vin-decoder.md`](../../docs/vin-decoder.md).

### Нормализация FA series → chassis

FA использует формат с нулём: `G020`→`G20`, `F030`→`F30`, `G011`→`G11`
(убирается второй символ-ноль).

---

## ZGW — протокол

**Зонд (6 байт):**
```
00 00 00 00 00 11
```
`0x0011 = 17` — длина VIN. ZGW игнорирует зонды короче 6 байт.

**Ответ ZGW:**
```
00 00 00 32 00 11 DIAGADR10 BMWMAC48C58D90515C BMWVINWBA8X51000CF40263
```

| Поле | Пример | Описание |
|------|--------|----------|
| `DIAGADR` | `10` | hex; ECU-адрес = значение × 2; "10" → F020 |
| `BMWMAC` | `48C58D90515C` | MAC ZGW |
| `BMWVIN` | `WBA8X51000CF40263` | VIN 17 символов ISO 3779 |

**Порт:** `6811 UDP`

---

## Переиспользование VIN[3] между поколениями

BMW переиспользует буквы VIN[3] при смене поколений. Разрешение — по VIN[10] (производственный год):

| VIN[10] | Год | VIN[10] | Год |
|---------|-----|---------|-----|
| `A` | 2010 | `K` | 2019 |
| `B` | 2011 | `L` | 2020 |
| `C` | 2012 | `M` | 2021 |
| `D` | 2013 | `N` | 2022 |
| `E` | 2014 | `P` | 2023 |
| `F` | 2015 | `R` | 2024 |
| `G` | 2016 | `S` | 2025 |
| `H` | 2017 | | |
| `J` | 2018 | | |

> Заводы BMW SA (WMI `X4X`, `WBX`) и ряд других используют цифры в VIN[10]. Цифры (ASCII < букв) всегда попадают в «старое» поколение.

**Подтверждённые пороги `gseriesIntroMY`:**

| VIN[3] | Порог | Старый (F-series) | Новый (G-series) |
|--------|-------|-------------------|-----------------|
| `H` | `K` (2019) | F48 X1 FWD | G29 Z4 |
| `K` | `G` (2016) | F15 X5 / F16 X6 / F85 X5M | G11/G12 7 Series |
| `W` | `N` (2022) | F25 X3 | G26 4 Series GC |

---

## Требования

- Go 1.21+
- Windows, macOS или Linux

---

## Файлы

| Файл | Описание |
|------|----------|
| `zgw.go` | ZGW discovery, VIN decoder, Info struct |
| `fa_typekeys.go` | **генерируется** — VIN[3:7]→модель из FA-данных (~725 ключей) |
| `fa_platform.go` | **генерируется** — шасси→ISTA-платформа из FA I-Step |
| `vindb.go` | Поиск в базе типов BMW |
| `bmw_types.csv` | ~4600 вариантов BMW (встроено `//go:embed`) |
| `broadcast_windows.go` | SO_BROADCAST для Windows |
| `broadcast_other.go` | Заглушка macOS/Linux |

---

## История обучения таблиц

| Версия | Датасет | Точность | Что добавлено |
|--------|---------|---------|---------------|
| v1.5.6 | 73 FA XML | — | Начальная таблица |
| v1.5.7 | 73 FA XML | ~65% | Исправлено 12 bmwTypeKeys; bmwType2Keys: 5R/5V/53/57 |
| v1.5.9 | +1 VIN (bimmer.work) | — | 5R/5V → G20 (баг-репорт пользователя) |
| v1.6.0 | 7 546 FA XML | **~89%** | 90+ записей bmwType2Keys; chassisPlatform расширен |
| v1.7.0 | 1 945 уник. VIN | **~99.6%** | FA-таблица 4-симв. `faTypeKeys` (~725) + `faChassisPlatform`; авто-генерация `tools/vin-retrain/retrain.py` |
