# bytewren

Анализатор сетевого трафика и отладчик протоколов на Rust. Пишется с нуля,
без готовых сетевых крейтов.

- GitHub: https://github.com/bytewren-rs/bytewren
- Лицензия: Apache-2.0
- Статус: 0.0.1, early development

## Жёсткие правила

- **НЕ использовать сетевые крейты**: `pnet`, `etherparse`, `socket2`, `pcap`,
  `tun-tap`, `pdu`. FFI объявляем сами. Это не догма ради догмы: цель проекта —
  контроль над разбором пакетов и zero-copy на всём пути от сокета до парсера.
- Разрешено: `tokio` и `axum` в веб-крейте, `nom` в парсерах, всё для тестов,
  бенчмарков и фаззинга.
- `libc` — осознанная и постоянная зависимость, не компромисс. Сопровождается
  `rust-lang`, кода не содержит — только объявления из системных заголовков,
  бинарник получается тот же. Правило про сетевые крейты он не нарушает: он не
  разбирает пакеты и не управляет захватом. Ручные `extern "C"` для
  `sockaddr_ll`, `ifreq` и структур `TPACKET_V3` дали бы молчаливые ошибки
  раскладки на других архитектурах (знаковость `c_char`, паддинг, кодировка
  номеров ioctl) и не приблизили бы к цели проекта.

## Стек и окружение

Rust 1.90, edition 2024, Linux. Пин в `rust-toolchain.toml`.
`rust-version` (MSRV) намеренно снят до первого публичного релиза.

## Структура

```
bytewren/
├── Cargo.toml              # [workspace], resolver 3, общие lints
├── rust-toolchain.toml     # 1.90
├── crates/
│   ├── bytewren-proto/     # парсеры L2-L4, zero-copy, БЕЗ зависимостей от сокетов
│   ├── bytewren-capture/   # AF_PACKET, raw_socket_linux.rs
│   └── bytewren-cli/       # bin: bytewren
├── pcaps/                  # тестовые дампы, коммитятся в git
└── docs/                   # конспекты по теории протоколов и захвата
```

Инвариант: `bytewren-proto` не знает про сокеты и тестируется без рута — иначе
CI не сможет гонять тесты, там нет `CAP_NET_RAW`. Всё, что требует привилегий,
живёт в `bytewren-capture`.

Активные lints воркспейса: `unsafe_op_in_unsafe_fn = deny`,
`undocumented_unsafe_blocks = deny`, `indexing_slicing = warn`,
`cast_possible_truncation = warn`, `missing_debug_implementations = warn`.

`undocumented_unsafe_blocks` подавлять через `#[allow]` нельзя — каждый
`unsafe`-блок несёт комментарий `SAFETY:` с предусловием, которое компилятор
проверить не может.

## Дорожная карта

1. Захват: `AF_PACKET` + `recvfrom` → потом `TPACKET_V3` через `mmap`
2. Парсеры Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
3. Таблица потоков по 5-tuple
4. DNS, TLS ClientHello (SNI)
5. Реассемблинг TCP
6. Веб-дашборд: axum + WebSocket, агрегация тиками по 100–200 мс
7. BPF-фильтрация в ядре через `SO_ATTACH_FILTER`
8. eBPF через `aya` — привязка соединения к PID (этого `AF_PACKET` не даёт)

Дальше отдельным крейтом — TCP/IP-стек в userspace поверх TUN.
