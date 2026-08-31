Please donate project:

Paypal SLGPC.sec@gmail.com

Crypto Wallet SuperTrump: 0x25E99A4b58C83dC85c4668f43695eb00a4AB6a46
Trump Official: 2ZUw5ytdtRuTj9EhnJ6i7xErEo2cwHhbBTCAF9Wuwx9g
USDT Erc20: 0x25E99A4b58C83dC85c4668f43695eb00a4AB6a46
Bitcoin: bc1qnjypme6cxn9d2nhqyyc3mdun0lm8m6m6982mqu



A **Snort 3 logger plugin** that serializes IDS/IPS alert events to JSON and
bulk-inserts them into **HeavyDB** (formerly OmniSciDB) for GPU-accelerated
analytics queries.

---

## Architecture

```
Snort 3 (packet capture)
        │
        │  alert() / log()
        ▼
 snort3_heavydb_logger.so   ← Snort plugin (this repo)
        │
        │  json_binding::serialize()
        │  nlohmann::json → JSON string
        │
        ▼
 heavydb::Connector
        │
        │  Batch INSERT via HTTP REST
        │  POST /query  (port 6278)
        ▼
   HeavyDB server
        │
        ▼
   snort_alerts table  (GPU-resident columnar store)
```

---

## Dependencies

| Dependency | Min version | Notes |
|---|---|---|
| Snort 3 | 3.1.x | Headers only; link against Snort's installed `.so` is **not** required |
| libcurl | 7.68 | HTTP transport to HeavyDB |
| nlohmann/json | 3.10 | Header-only JSON library |
| C++ compiler | C++17 | GCC 9+ or Clang 10+ |
| CMake | 3.16 | Build system |

Install on Ubuntu/Debian:
```bash
sudo apt install libcurl4-openssl-dev nlohmann-json3-dev cmake g++
# Install Snort 3 from source or PPA, then note its include path
```

---

## Build

```bash
mkdir build && cd build

cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DSNORT3_INCLUDE_DIR=/usr/include/snort

make -j$(nproc)
sudo make install
# installs to /usr/local/lib/snort/plugins/logger/snort3_heavydb_logger.so
```

Override the install prefix:
```bash
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/snort
```

---

## HeavyDB table

The plugin calls `CREATE TABLE IF NOT EXISTS snort_alerts (...)` on first
connection, so no manual DDL is required. The full schema:

```sql
CREATE TABLE IF NOT EXISTS snort_alerts (
    alert_time        TIMESTAMP NOT NULL,
    src_ip            TEXT ENCODING DICT(32),
    dst_ip            TEXT ENCODING DICT(32),
    src_port          SMALLINT,
    dst_port          SMALLINT,
    protocol          SMALLINT,
    priority          TINYINT,
    generator_id      INTEGER,
    sig_id            INTEGER,
    sig_revision      INTEGER,
    classification    TEXT ENCODING DICT(32),
    action            TEXT ENCODING DICT(16),
    pkt_len           INTEGER,
    ttl               SMALLINT,
    iface             TEXT ENCODING DICT(16),
    rule_msg          TEXT,
    flow_id           BIGINT,
    raw_json          TEXT
) WITH (FRAGMENT_SIZE=2097152, STORAGE_TYPE='OMNISCI');
```

---

## Snort 3 configuration (`snort.lua`)

```lua
-- Load the plugin from its install path
plugins =
{
    { name = 'snort3_heavydb_logger', path = '/usr/local/lib/snort/plugins/logger' }
}

-- Configure the logger
heavydb_logger =
{
    host       = '127.0.0.1',   -- HeavyDB host
    port       = 6278,          -- HTTP port (default: 6278)
    user       = 'admin',
    password   = 'HyperInteractive',
    db_name    = 'heavyai',
    use_https  = false,
    timeout_ms = 5000,
    batch_size = 512,           -- rows buffered before bulk INSERT
}

-- Enable for alerts
alert_heavydb_logger = { }

-- Enable for logged packets (optional)
log_heavydb_logger = { }
```

---

## Tuning

| Parameter | Default | Guidance |
|---|---|---|
| `batch_size` | 512 | Increase (1024–4096) for high-throughput links; decrease for low-latency visibility |
| `timeout_ms` | 5000 | Raise if HeavyDB is on a slow WAN link |
| `use_https`  | false | Enable with a valid TLS certificate on HeavyDB |

On network termination (`close()`), the plugin flushes any buffered rows
automatically, so no events are silently dropped on clean shutdown.

---

## Querying alerts in HeavyDB

```sql
-- Top talkers (last 10 minutes)
SELECT src_ip, count(*) AS hits
FROM snort_alerts
WHERE alert_time >= NOW() - INTERVAL '10' MINUTE
GROUP BY src_ip ORDER BY hits DESC LIMIT 20;

-- Signature breakdown by priority
SELECT priority, sig_id, rule_msg, count(*) AS cnt
FROM snort_alerts
GROUP BY priority, sig_id, rule_msg
ORDER BY priority ASC, cnt DESC;

-- Port scan candidates (many unique dst_ports from one src)
SELECT src_ip, count(DISTINCT dst_port) AS ports_touched
FROM snort_alerts
WHERE protocol = 6          -- TCP
GROUP BY src_ip
HAVING ports_touched > 50
ORDER BY ports_touched DESC;
```

---

## File layout

```
snort3-heavydb/
├── CMakeLists.txt              # Build system
├── README.md                   # This file
├── heavydb_connector.h         # HeavyDB HTTP connector (interface)
├── heavydb_connector.cc        # HeavyDB HTTP connector (implementation)
├── json_binding.h              # Snort Packet/Event → nlohmann::json
├── snort3_heavydb_logger.h     # Snort 3 Logger plugin (interface)
└── snort3_heavydb_logger.cc    # Snort 3 Logger plugin (implementation)
``
