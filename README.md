<div align="center">

```
███████╗██████╗ ███████╗███████╗██████╗  ██████╗ ███╗   ███╗███╗   ██╗███████╗████████╗
██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗ ████║████╗  ██║██╔════╝╚══██╔══╝
█████╗  ██████╔╝█████╗  █████╗  ██║  ██║██║   ██║██╔████╔██║██╔██╗ ██║█████╗     ██║
██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ██║  ██║██║   ██║██║╚██╔╝██║██║╚██╗██║██╔══╝     ██║
██║     ██║  ██║███████╗███████╗██████╔╝╚██████╔╝██║ ╚═╝ ██║██║ ╚████║███████╗   ██║
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝
```

**Обход DPI · Без VPN-сервера · Без смены IP · Открытый исходный код**

[![Rust](https://img.shields.io/badge/Rust-async%20proxy-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![C++17](https://img.shields.io/badge/C%2B%2B17-native%20core-blue?style=for-the-badge&logo=cplusplus)](https://isocpp.org/)
[![D Language](https://img.shields.io/badge/D-vpn%20generator-red?style=for-the-badge&logo=d)](https://dlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## ⚡ Что это такое

**FreedomNet** — локальный прокси-сервер с обходом DPI (Deep Packet Inspection).  
Работает **без удалённого сервера** и **без смены IP-адреса**.  
Вместо этого он обманывает оборудование DPI на уровне пакетов.

| Работает против | Метод блокировки |
|:---|:---|
| 🇷🇺 Россия — ТСПУ / Echelon | SNI-инспекция, DNS-подмена |
| 🇮🇷 Иран — IRIAMAN | Глубокая инспекция пакетов |
| 🇨🇳 Китай — Great Firewall | Keyword filtering, DNS poison |
| 🇰🇿 Казахстан, 🇧🇾 Беларусь | DPI + DNS |

> ⚠️ **КНДР**: физическая изоляция на уровне BGP-маршрутизации. Ни один клиентский инструмент не поможет без физического доступа к сети.

---

## 🏗️ Архитектура

```
Браузер / Приложение
        │
        ▼
┌───────────────────────────────────────────────┐
│          SOCKS5 / HTTP CONNECT прокси         │
│               127.0.0.1:1080                  │
│                  (Rust + tokio)               │
└───────────────────┬───────────────────────────┘
                    │
          ┌─────────▼──────────┐
          │   DoH DNS Resolver  │  ← Cloudflare / Google / Quad9
          │       (Rust)        │    обход ISP DNS-блокировки
          └─────────┬──────────┘
                    │
          ┌─────────▼──────────┐
          │  C++ bypass_core   │  ← libbypass_core.a (C++17)
          │                    │
          │  ┌──────────────┐  │
          │  │ TLS splitter │  │  ClientHello → 2 TLS record
          │  └──────────────┘  │
          │  ┌──────────────┐  │
          │  │ HTTP mangler │  │  User-Agent → uSeR-AgEnT
          │  └──────────────┘  │
          └─────────┬──────────┘
                    │
          ┌─────────▼──────────┐
          │  Rust Anon Layer   │  ← strip X-Real-IP, Referer
          │                    │     normalise UA & Accept-Lang
          └─────────┬──────────┘
                    │
                    ▼
              Реальный сервер
          (прямое TCP соединение)
```

---

## 🔬 Техники обхода DPI

### 1. TLS Record Fragmentation *(основная)*

Большинство DPI-систем ищут SNI (имя сайта) в **первом TLS-record** ClientHello.  
FreedomNet разбивает один ClientHello на **два отдельных TLS-record**:

```
Оригинал:  [TLS Record: весь ClientHello + SNI "example.com"]
                                  ↓
Record-1:  [TLS Record: HandshakeType + несколько байт]   ← DPI видит это, но SNI нет
Record-2:  [TLS Record: остальные байты + SNI "example.com"]  ← DPI не смотрит
```

Сервер нормально собирает оба record (RFC 5246 §6.2.1). DPI — нет.

### 2. DNS over HTTPS

```
Обычный DNS:  браузер → ISP DNS → [ЗАБЛОКИРОВАНО / ПОДМЕНА]
FreedomNet:   браузер → HTTPS → cloudflare-dns.com/dns-query → реальный IP
```

Цепочка резолверов: **Cloudflare → Google → Quad9 → system fallback**

### 3. HTTP Header Mangling

```http
# До (DPI видит и блокирует):
GET / HTTP/1.1
Host: rutracker.org
User-Agent: Mozilla/5.0

# После (DPI не распознаёт):
GET / HTTP/1.1
Host: rutracker.org
uSeR-AgEnT: Mozilla/5.0
```

### 4. Anonymity Layer

Второй проход по HTTP-запросу убирает заголовки, раскрывающие реальный IP:

```
Удаляет:    X-Real-IP · X-Forwarded-For · CF-Connecting-IP
            True-Client-IP · Via · Forwarded · Referer
Заменяет:   User-Agent → Chrome/124 (Windows NT 10.0)
            Accept-Language → en-US,en;q=0.9
```

---

## 🚀 Установка и запуск

### Требования

```
Rust 1.70+      https://rustup.rs
C++17 compiler  (clang++ или g++) — обычно уже установлен
ldc2 (для D)    brew install ldc  /  https://dlang.org
```

### Сборка

```bash
git clone https://github.com/sirmir25/freedomnetwork.git
cd freedomnetwork

# Собрать Rust + C++ (автоматически через build.rs)
cargo build --release

# Собрать D VPN-генератор
cd vpngen && ldc2 -O2 -of=fn-vpn source/*.d && cd ..
```

### Запуск прокси

```bash
./target/release/fn
```

```
FreedomNet DPI Bypass Proxy  [native core 0.2.0]
──────────────────────────────────────────────────────
Listen   127.0.0.1:1080
Protocol SOCKS5 + HTTP CONNECT
Bypass   DoH DNS  ·  C++ TLS record split  ·  C++ HTTP mangle

Set browser proxy to  SOCKS5  127.0.0.1  port 1080
                 or  HTTP     127.0.0.1  port 1080
Press Ctrl+C to stop.
──────────────────────────────────────────────────────
```

### Настройка браузера

**Firefox:**  Настройки → Общие → Настройки сети → Ручная настройка прокси  
→ SOCKS v5: `127.0.0.1` порт `1080`  → ✅ *Использовать DNS через SOCKS*

**Chrome / Edge:**
```bash
open -a "Google Chrome" --args --proxy-server="socks5://127.0.0.1:1080"
```

**Автоматически (PAC-файл):**
```
Системные настройки → Сеть → Прокси → Автоматическая настройка
URL: http://127.0.0.1:8085/proxy.pac
```
*(PAC-сервер запускается вместе с прокси)*

---

## 🔧 Параметры командной строки

```bash
fn [OPTIONS] [COMMAND]

Options:
  --listen <ADDR>       Адрес прокси       [default: 127.0.0.1:1080]
  --pac-listen <ADDR>   Адрес PAC-сервера  [default: 127.0.0.1:8085]
  --no-pac              Отключить PAC-сервер
  -d, --debug           Подробное логирование
  -V, --version         Версия

Commands:
  proxy                 Запустить DPI-обход прокси (по умолчанию)
  vpn openvpn           Сгенерировать OpenVPN конфиг
  vpn wireguard         Сгенерировать WireGuard конфиг
  vpn shadowsocks       Сгенерировать Shadowsocks конфиг
```

---

## 🔐 VPN-конфиги (D-генератор)

Если у тебя есть **собственный сервер** за рубежом — генерируй клиентские конфиги:

### OpenVPN
```bash
fn vpn openvpn --server vpn.example.com --port 1194 --out client.ovpn
fn vpn openvpn --server vpn.example.com --port 443 --tcp --out client-tcp.ovpn
```

### WireGuard
```bash
fn vpn wireguard \
  --server 1.2.3.4:51820 \
  --pubkey "Ваш_публичный_ключ_сервера=" \
  --address 10.0.0.2/32 \
  --out wg0.conf
```

### Shadowsocks
```bash
fn vpn shadowsocks \
  --server 1.2.3.4 \
  --password "YourPassword" \
  --method chacha20-ietf-poly1305 \
  --out ss.json
```

---

## 📊 Состав кода

| Язык | Назначение | % |
|:-----|:-----------|:-:|
| **Rust** | Async SOCKS5/HTTP прокси, DoH DNS, PAC-сервер, anonymity layer | ~55% |
| **C++17** | TLS-парсер, record fragmenter, HTTP header mangler (нативная скорость) | ~33% |
| **D** | VPN config generator (OpenVPN / WireGuard / Shadowsocks) | ~12% |

---

## 📁 Структура проекта

```
freedomnetwork/
├── src/
│   ├── main.rs        — CLI, точка входа
│   ├── proxy.rs       — SOCKS5 + HTTP CONNECT сервер
│   ├── doh.rs         — DNS over HTTPS с кешированием
│   ├── ffi.rs         — безопасные FFI-обёртки над C++ библиотекой
│   ├── anon.rs        — слой анонимизации HTTP-запросов
│   └── pac.rs         — PAC-файл сервер
├── cpp/
│   ├── include/
│   │   └── bypass_core.h   — публичный C API
│   └── src/
│       ├── tls.cpp    — TLS ClientHello парсер + fragmenter
│       └── http.cpp   — HTTP header mangler
├── vpngen/            — D-проект (fn-vpn бинарь)
│   └── source/
│       ├── app.d          — CLI диспетчер
│       ├── openvpn.d      — OpenVPN генератор
│       ├── wireguard.d    — WireGuard генератор
│       └── shadowsocks.d  — Shadowsocks генератор
├── build.rs           — Rust build script (компилирует C++)
└── Cargo.toml
```

---

## 🛡️ Что это НЕ делает

| ❌ НЕ делает | ✅ Что вместо |
|:---|:---|
| Не меняет IP-адрес | VPN-режим с собственным сервером |
| Не анонимизирует трафик | Tor Browser для анонимности |
| Не работает в КНДР | Физическая изоляция на уровне BGP |
| Не требует root/admin | Всё работает от обычного пользователя |

---

## ⚖️ Лицензия

MIT © 2026 [sirmir25](https://github.com/sirmir25)

*Инструмент создан для законного доступа к информации в условиях цензуры.*  
*Используй ответственно.*

---

<div align="center">

**[⭐ Поставь звезду](https://github.com/sirmir25/freedomnetwork) если проект помог**

</div>
