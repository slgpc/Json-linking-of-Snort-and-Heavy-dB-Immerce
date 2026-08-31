#include "heavydb_connector.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <utility>

// Fix #2: curl_global_init/cleanup are process-level operations.
// They must be called exactly once. Snort 3's pinit/pterm hooks are the
// right place; see snort3_heavydb_logger.cc.

namespace heavydb {

// ---------------------------------------------------------------------------
// Process-level helpers (fix #2)
// ---------------------------------------------------------------------------
void global_init()
{
    const CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("curl_global_init failed: ")
                                 + curl_easy_strerror(rc));
}

void global_cleanup()
{
    curl_global_cleanup();
}

// ---------------------------------------------------------------------------
// CURL write callback
// ---------------------------------------------------------------------------
static std::size_t curl_write_cb(char* ptr, std::size_t size,
                                  std::size_t nmemb, void* userdata)
{
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

// ---------------------------------------------------------------------------
// SQL string escaping (fix #1)
// Handles:
//   - single-quote  → ''   (standard SQL escaping)
//   - NUL / control characters (\x00-\x1f except tab/LF/CR) → stripped
//     because HeavyDB TEXT columns do not accept raw control bytes.
// ---------------------------------------------------------------------------
/*static*/
std::string Connector::escape_sql_string(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\'') {
            out += "''";
        } else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
            // strip NUL and other ASCII control chars that break SQL literals
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Ctor / dtor  (fix #2: no curl_global_init here)
// ---------------------------------------------------------------------------
Connector::Connector(const ConnectionConfig& cfg)
    : cfg_(cfg)
    , curl_(nullptr)
    // fix #8: guard batch_size — must be at least 1
    , safe_batch_size_(cfg.batch_size >= 1
                       ? static_cast<std::size_t>(cfg.batch_size)
                       : 1u)
{
    curl_ = curl_easy_init();
    if (!curl_)
        throw std::runtime_error("heavydb::Connector: curl_easy_init failed");
    connect();
}

Connector::~Connector()
{
    try {
        flush_impl();   // fix #9: explicit name, called as sole owner in dtor
        disconnect();
    } catch (...) { /* best-effort */ }

    if (curl_) {
        curl_easy_cleanup(static_cast<CURL*>(curl_));
        curl_ = nullptr;
    }
}

Connector::Connector(Connector&& o) noexcept
    : cfg_(std::move(o.cfg_))
    , curl_(std::exchange(o.curl_, nullptr))
    , session_(std::move(o.session_))
    , buffer_(std::move(o.buffer_))
    , safe_batch_size_(o.safe_batch_size_)
{}

Connector& Connector::operator=(Connector&& o) noexcept
{
    if (this != &o) {
        cfg_             = std::move(o.cfg_);
        curl_            = std::exchange(o.curl_, nullptr);
        session_         = std::move(o.session_);
        buffer_          = std::move(o.buffer_);
        safe_batch_size_ = o.safe_batch_size_;
    }
    return *this;
}

// ---------------------------------------------------------------------------
// Internal HTTP helper
// ---------------------------------------------------------------------------
std::string Connector::post(const std::string& path, const std::string& body)
{
    CURL* ch = static_cast<CURL*>(curl_);

    const std::string scheme = cfg_.use_https ? "https" : "http";
    const std::string url    = scheme + "://" + cfg_.host + ":"
                               + std::to_string(cfg_.port) + path;

    std::string response;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(ch, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,     headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS,     body.c_str());
    curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE,  static_cast<long>(body.size()));
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,      &response);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT_MS,     static_cast<long>(cfg_.timeout_ms));
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, cfg_.use_https ? 1L : 0L);

    CURLcode rc = curl_easy_perform(ch);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK)
        throw std::runtime_error(std::string("heavydb HTTP request failed: ")
                                 + curl_easy_strerror(rc));

    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code >= 400)
        throw std::runtime_error("heavydb HTTP " + std::to_string(http_code)
                                 + ": " + response);

    return response;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------
void Connector::connect()
{
    nlohmann::json req = {
        {"user",     cfg_.user},
        {"password", cfg_.password},
        {"dbname",   cfg_.db_name}
    };
    const std::string resp = post("/connect", req.dump());
    const auto j = nlohmann::json::parse(resp);

    if (!j.contains("session"))
        throw std::runtime_error("heavydb connect: no 'session' in response: " + resp);

    session_ = j["session"].get<std::string>();
}

void Connector::disconnect()
{
    if (session_.empty()) return;
    try {
        nlohmann::json req = {{"session", session_}};
        post("/disconnect", req.dump());
    } catch (...) {}
    session_.clear();
}

// Fix #5: reconnect logic — called automatically when execute() catches a
// session/auth error. Tries up to cfg_.max_reconnect_attempts times.
void Connector::try_reconnect()
{
    const int attempts = std::max(1, cfg_.max_reconnect_attempts);
    for (int i = 0; i < attempts; ++i) {
        try {
            disconnect(); // clear stale session token
            connect();
            return;       // success
        } catch (const std::exception& ex) {
            if (i + 1 == attempts)
                throw std::runtime_error(
                    std::string("heavydb: reconnect failed after ")
                    + std::to_string(attempts) + " attempts: " + ex.what());
        }
    }
}

// ---------------------------------------------------------------------------
// DDL helper  (fix #11: STORAGE_TYPE='OMNISCI' replaced with 'HEAVYDB')
// ---------------------------------------------------------------------------
void Connector::ensure_table()
{
    const std::string ddl = R"SQL(
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
        ) WITH (FRAGMENT_SIZE=2097152, STORAGE_TYPE='HEAVYDB')
    )SQL";
    execute(ddl);
}

// ---------------------------------------------------------------------------
// DML  (fix #5: retry on session failure)
// ---------------------------------------------------------------------------
void Connector::execute(const std::string& sql)
{
    auto do_execute = [&]() {
        nlohmann::json req = {
            {"session",       session_},
            {"query",         sql},
            {"column_format", false}
        };
        const std::string resp = post("/query", req.dump());
        const auto j = nlohmann::json::parse(resp);

        if (j.contains("error"))
            throw std::runtime_error("heavydb query error: "
                                     + j["error"].get<std::string>()
                                     + "\nSQL: " + sql);
    };

    try {
        do_execute();
    } catch (const std::runtime_error& ex) {
        // Session may have expired — attempt reconnect once then retry.
        try_reconnect();
        do_execute(); // throws on second failure, propagates to caller
    }
}

// ---------------------------------------------------------------------------
// Buffering
// ---------------------------------------------------------------------------
void Connector::enqueue(const std::string& json_row)
{
    buffer_.push_back(json_row);
    // fix #8: comparison is now std::size_t vs std::size_t — no sign mismatch
    if (buffer_.size() >= safe_batch_size_)
        flush_impl();
}

void Connector::flush()
{
    flush_impl(); // public wrapper; caller is responsible for thread-safety
}

// ---------------------------------------------------------------------------
// flush_impl  (fix #9: renamed from flush_locked; contract documented)
//
// Contract: caller ensures single-threaded access — either by holding an
// external mutex or by being the sole owner of this Connector instance
// (e.g. in dtor or single-thread open/close).
//
// Fix #1: all string values are SQL-escaped via escape_sql_string() before
// being embedded in the INSERT literal.
// ---------------------------------------------------------------------------
void Connector::flush_impl()
{
    if (buffer_.empty()) return;

    std::ostringstream sql;
    sql << "INSERT INTO snort_alerts ("
           "alert_time, src_ip, dst_ip, src_port, dst_port, protocol, "
           "priority, generator_id, sig_id, sig_revision, classification, "
           "action, pkt_len, ttl, iface, rule_msg, flow_id, raw_json"
           ") VALUES ";

    bool first_row = true;
    for (const auto& raw : buffer_) {
        nlohmann::json row;
        try {
            row = nlohmann::json::parse(raw);
        } catch (...) {
            // Malformed JSON — skip this row rather than poisoning the batch.
            continue;
        }

        if (!first_row) sql << ',';
        first_row = false;

        auto str_col = [&](const char* key) -> std::string {
            if (row.contains(key) && row[key].is_string())
                return "'" + escape_sql_string(row[key].get<std::string>()) + "'";
            return "NULL";
        };
        auto int_col = [&](const char* key) -> std::string {
            if (row.contains(key) && row[key].is_number())
                return std::to_string(row[key].get<long long>());
            return "0";
        };

        sql << '('
            << str_col("alert_time")     << ','
            << str_col("src_ip")         << ','
            << str_col("dst_ip")         << ','
            << int_col("src_port")       << ','
            << int_col("dst_port")       << ','
            << int_col("protocol")       << ','
            << int_col("priority")       << ','
            << int_col("generator_id")   << ','
            << int_col("sig_id")         << ','
            << int_col("sig_revision")   << ','
            << str_col("classification") << ','
            << str_col("action")         << ','
            << int_col("pkt_len")        << ','
            << int_col("ttl")            << ','
            << str_col("iface")          << ','
            << str_col("rule_msg")       << ','
            << int_col("flow_id")        << ','
            << str_col("raw_json")
            << ')';
    }

    buffer_.clear();

    if (first_row) return; // all rows were malformed

    execute(sql.str());
}

} // namespace heavydb
