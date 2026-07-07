# BMW ENET Protocol — документация

Собрано реверс-инжинирингом трёх утилит: ZGW_SEARCH_3.0.exe, Remote Enet_ssh.exe, RemoteTool.exe.

---

## Сетевая топология

BMW подключается к ПК через ENET-кабель (RJ45 ↔ OBD2).  
Адресация — link-local: **169.254.x.x / 16** (APIPA).  
Автомобиль отвечает с адреса вида **169.254.x.y** и участвует в L2-домене.

---

## Утилиты и их роли

| Утилита | Тип | Роль |
|---|---|---|
| ZGW_SEARCH_3.0.exe | VB6 | Discovery: найти машину в сети, показать IP + VIN |
| Remote Enet_ssh.exe | C++ Win32 | Полноценный ENET-клиент: диагностика, кодирование |
| RemoteTool.exe | .NET 4.6.1 (obfuscated) | Удалённый туннель: пробрасывает диагностический порт через интернет |

---

## Протокол ZGW Discovery (порт 6811 UDP)

### Запрос

- **Транспорт:** UDP broadcast  
- **Адрес назначения:** `169.254.255.255:6811`  
- **Payload запроса:** `\x00\x00\x00\x00` (4 нулевых байта)

```
+------+------+------+------+
| 0x00 | 0x00 | 0x00 | 0x00 |
+------+------+------+------+
```

### Ответ от ZGW

ZGW (Central Gateway Module) отвечает unicast на отправителя.  
Структура ответного пакета (из анализа Remote Enet, поля BMWVIN / BMWMAC / DIAGADR10):

```
Offset  Len  Поле
  0      1   Type / version (обычно 0x01 или 0xFF)
  1      3   Зарезервировано / padding
  4      4   IP-адрес ZGW (big-endian или как строка — зависит от прошивки)
 10      6   MAC-адрес (6 байт)
 16     17   VIN (ASCII, 17 символов, без null-терминатора)
 33      ?   DIAGADR (диагностический адрес, 10 байт в Remote Enet)
```

> **Примечание:** точные смещения могут отличаться на 1-2 байта в зависимости от версии ZGW.  
> Надёжнее искать VIN как первую последовательность из 17 ASCII-символов `[A-Z0-9]` в ответе.

### Пример ответа (типичный)

```
FF 00 00 00  A9 FE 01 C8  AA BB CC DD EE FF  57 42 41 31 32 33 34 35 36 37 38 39 30 41 42 43 44  ...
```
- IP: `169.254.1.200`
- MAC: `AA:BB:CC:DD:EE:FF`
- VIN: `WBA123456789 0ABCD` (17 chars)

---

## Порты используемые Remote Enet

| Порт | Протокол | Назначение |
|---|---|---|
| 6811 | UDP | ZGW Discovery (broadcast + ответ) |
| 6801 | TCP | ENET data (основной диагностический канал, HO-CAN) |
| 2000 | TCP | EDIABAS legacy |
| 4040 | TCP | Дополнительный |
| 13400 | TCP/UDP | DoIP (ISO 13400 — Diagnostics over IP) |
| 30491 | TCP | DoIP расширенный |
| 50160 | TCP | Диагностический порт (DIAGADR10, используется RemoteTool) |

---

## Как этот трафик несёт supervpn

supervpn заменяет RemoteTool: машина и удалённый ПК ставятся в один L2-хаб
(оба через адаптеры 169.254.x.x), и весь ENET-обмен идёт прозрачно на уровне L2,
без ручного проброса портов. Discovery-broadcast (6811 UDP), DoIP (13400),
диагностический TCP (6801/50160) — всё это обычные кадры внутри хаба.

**Порядок доставки — критично для прошивки.** UDS/ENET-прошивка блоков ЭБУ идёт
поверх внутреннего TCP: пришедший не по порядку сегмент трактуется как потеря →
dup-ACK → ложные ретрансмиты → обрыв сессии прошивки. Поэтому supervpn гарантирует
**строгий порядок кадров в пределах сессии** на пути «FEC-декод → форвард в хаб»:
декодер отдаёт кадры в порядке (blockID, pktIdx), а per-session `orderMu` не даёт
конкурентным обработчикам (пул UDP-воркеров сервера, два recvLoop клиента при
двухпутевом режиме, stale-flush) переставить их. Расшифровка AES-GCM при этом
остаётся параллельной. FEC (K/R) и дублирование по двум путям добавляют
устойчивость к потерям без ретрансмита — то есть на плохом канале прошивка не
рвётся, но и порядок не ломается. См. таблицу design-решений в `CLAUDE.md`
(строка «Delivery order»).

**MTU / фрагментация — вторая причина обрывов длинных потоков.** Полноразмерный
внутренний кадр (1514 Б) с оверхедом supervpn (`proto 15 + crypto 40 + IP/UDP 28`)
даёт на проводе ~1597 Б — больше MTU 1500, значит каждая крупная датаграмма
фрагментируется, а потеря одного фрагмента = потеря всей. DPI (ТСПУ) и NAT
фрагменты часто режут. Короткие транзакции (кодирование, Tool32) этого не
достигают и работают всегда; bulk-поток (ISTA-чтение, UDS-прошивка по DoIP/ENET)
упирается на каждом пакете. Лечится **TCP MSS clamping** (`[bridge] mss_clamp`,
дефолт 1300): в проходящих SYN снижается анонсируемый MSS, и внутренний TCP сам
перестаёт слать сегменты, которые бы фрагментировались. Клампинг идёт в обе
стороны на клиентском бридже (`internal/bridge/mssclamp.go`), IP-payload не
трогается — правится только TCP-заголовок с корректировкой контрольной суммы.

**Крупные не-TCP кадры по UDP.** MSS — механизм TCP; в UDP его нет, поэтому
большой внутренний UDP-кадр (или не-склампленный TCP) MSS не спасёт. Для них есть
**фрагментация на уровне VPN** (`internal/fragment`): кадр >1400 Б бьётся на
куски `FrameDataFrag`, каждый в своей датаграмме (не фрагментируется на IP →
пролезает через ТСПУ), и собирается обратно до форвардинга. Включается по
негоциации (флаг `FlagFragment` в AuthOK), только на UDP-сессиях — по TLS/Reality
не нужно, там сегментацию делает потоковый транспорт. Избыточность — дублирование
по двум путям; дедуп и сборка — в реассемблере. Нормальный FrameData/FEC-поток
(по нему идёт склампленная UDS/ISTA-нагрузка) при этом не меняется вообще.

---

## RemoteTool — туннель диагностики

RemoteTool (.NET, обфусцирован ZYXDNGuarder/HVMRuntm) решает задачу **удалённой диагностики**:

1. **ListenUDP** — слушает локальный UDP, принимает пакеты от диагностической программы
2. **BmwIdent / StartIdent** — выполняет идентификацию ZGW (получает VinData)
3. **TogglePortForward / forwardPort** — пробрасывает TCP-порт (по умолчанию `50160`) через туннель
4. **AdjustFW** — добавляет правило Windows Firewall через INetFwPolicy2
5. **ReqPort / resetPort** — управление портом диагностического запроса

UI-элементы:
- `portBox` — ввод диагностического порта (placeholder: `DIAG PORT ex. 50160`)
- `portHolder` — отображение текущего порта
- `listBox` — список найденных машин / статус соединений
- `REMOTE CONNECT` / `Awaiting vehicle connection...` — статусные строки

### Что делает RemoteTool по шагам

```
1. Определяет локальный интерфейс 169.254.x.x (GetAllNetworkInterfaces → UnicastAddresses)
2. Шлёт ZGW Discovery broadcast → получает IP + VIN → VinData
3. Устанавливает TCP-соединение с ZGW на порту 6801 или 50160
4. Настраивает port forwarding: внешний запрос → локальный BMW-порт
5. Сообщает пользователю "REMOTE CONNECT" — соединение готово
```

---

## Remote Enet_ssh — дополнительные данные

Из бинаря извлечены строковые поля ответа ZGW:
- `BMWVIN` → `Vin` — поле VIN
- `BMWMAC` → `Mac` — поле MAC-адреса
- `DIAGADR10` — диагностический адрес (10 байт)
- `169.254.255.255` — broadcast-адрес для discovery
- `169.254` — prefix для определения нужного интерфейса

Требует прав администратора (`requestedExecutionLevel: requireAdministrator`).  
Использует `GetAdaptersAddresses` + `GetIpAddrTable` для поиска 169.254 интерфейса.

---

## Реализация ZGW Discovery на Go

```go
// Минимальный ZGW discovery
func discoverZGW(localIP string) (*ZGWInfo, error) {
    conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(localIP), Port: 0})
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    broadcast := &net.UDPAddr{IP: net.IPv4(169, 254, 255, 255), Port: 6811}
    conn.SetDeadline(time.Now().Add(2 * time.Second))

    // ZGW Discovery request: 4 zero bytes
    _, err = conn.WriteToUDP([]byte{0x00, 0x00, 0x00, 0x00}, broadcast)
    if err != nil {
        return nil, err
    }

    buf := make([]byte, 256)
    n, remoteAddr, err := conn.ReadFromUDP(buf)
    if err != nil {
        return nil, err // timeout = машина не найдена
    }

    return parseZGWResponse(buf[:n], remoteAddr)
}

// parseZGWResponse извлекает VIN из ответа: ищет 17 ASCII-символов [A-Z0-9]
func parseZGWResponse(data []byte, addr *net.UDPAddr) (*ZGWInfo, error) {
    re := regexp.MustCompile(`[A-HJ-NPR-Z0-9]{17}`)
    vin := re.Find(data)
    if vin == nil {
        return nil, fmt.Errorf("VIN not found in response")
    }
    return &ZGWInfo{IP: addr.IP.String(), VIN: string(vin)}, nil
}
```

---

## Открытые вопросы

1. **Точный формат запроса**: `\x00\x00\x00\x00` или другой — нужно подтвердить Wireshark-захватом
2. **Точные смещения VIN/MAC в ответе** — варьируются по версии ZGW прошивки
3. **Аутентификация в RemoteTool** — обфусцированный код скрывает механизм туннелирования
