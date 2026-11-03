// heavydb_replay.cpp
//
// Догрузка сегмента текстового лога алертов (JSON Lines формата json_binding.h)
// в таблицу snort_alerts HeavyDB. Идемпотентна: уже загруженные строки
// пропускаются, поэтому безопасно запускать повторно.
//
// Сборка:  g++ -std=c++17 -O2 heavydb_replay.cpp -lcurl -o heavydb_replay
// Запуск:  HEAVYDB_PASSWORD=... ./heavydb_replay --file alerts-2026110310.jsonl \
//              --from "2026-11-03 10:00:00" --to "2026-11-03 11:00:00"
//
// Протокол (/connect, /query) тот же, что в heavydb_connector.cc.
// Если у вас там другой транспорт - меняйте только класс Client.

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;

// Сеть/сервер недоступны: останавливаемся (повторный запуск безопасен).
struct TransportError : std::runtime_error { using std::runtime_error::runtime_error; };
// HeavyDB отверг конкретный запрос (плохие данные): делим пачку и ищем строку.
struct QueryError : std::runtime_error { using std::runtime_error::runtime_error; };

struct Opts {
    std::string file, from, to;
    std::string host = "localhost", user = "admin", password, db = "heavyai";
    int    port       = 6278;
    int    timeout_ms = 30000;
    size_t batch      = 1000;
    bool   dedup      = true;
    bool   dry_run    = false;
};

// ---------------------------------------------------------------------------
// HTTP-клиент HeavyDB
// ---------------------------------------------------------------------------
static size_t write_cb(char* p, size_t s, size_t n, void* ud)
{
    static_cast<std::string*>(ud)->append(p, s * n);
    return s * n;
}

class Client {
public:
    explicit Client(const Opts& o) : o_(o), curl_(curl_easy_init())
    {
        if (!curl_) throw TransportError("curl_easy_init failed");
        json req;
        req["user"]     = o_.user;
        req["password"] = o_.password;
        req["dbname"]   = o_.db;
        json r = json::parse(post("/connect", req.dump()), nullptr, false);
        if (r.is_discarded() || !r.contains("session"))
            throw QueryError("connect: no 'session' in response");
        session_ = r["session"].get<std::string>();
    }

    ~Client()
    {
        if (!curl_) return;
        if (!session_.empty()) {
            try {
                json req;
                req["session"] = session_;
                post("/disconnect", req.dump());
            } catch (...) {}
        }
        curl_easy_cleanup(curl_);
    }

    Client(const Client&)            = delete;
    Client& operator=(const Client&) = delete;

    json query(const std::string& sql)
    {
        json req;
        req["session"]       = session_;
        req["query"]         = sql;
        req["column_format"] = false;
        const std::string resp = post("/query", req.dump());
        json j = json::parse(resp, nullptr, false);
        if (j.is_discarded())
            throw TransportError("non-JSON response: " + resp.substr(0, 200));
        if (j.contains("error")) throw QueryError(j["error"].dump());
        return j;
    }

private:
    std::string post(const std::string& path, const std::string& body)
    {
        const std::string url = "http://" + o_.host + ":" + std::to_string(o_.port) + path;
        std::string response;

        curl_slist* h = nullptr;
        h = curl_slist_append(h, "Content-Type: application/json");
        h = curl_slist_append(h, "Accept: application/json");

        curl_easy_setopt(curl_, CURLOPT_URL,           url.c_str());
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER,    h);
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS,    body.c_str());
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA,     &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT_MS,    static_cast<long>(o_.timeout_ms));

        const CURLcode rc = curl_easy_perform(curl_);
        curl_slist_free_all(h);
        if (rc != CURLE_OK)
            throw TransportError(std::string("HTTP request failed: ") + curl_easy_strerror(rc));

        long code = 0;
        curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &code);
        if (code >= 500) throw TransportError("HTTP " + std::to_string(code) + ": " + response);
        if (code >= 400) throw QueryError("HTTP " + std::to_string(code) + ": " + response);
        return response;
    }

    Opts        o_;
    CURL*       curl_;
    std::string session_;
};

// ---------------------------------------------------------------------------
// Вспомогательные функции
// ---------------------------------------------------------------------------
static std::string esc(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\'')                                   out += "''";
        else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') { /* strip */ }
        else                                             out += static_cast<char>(c);
    }
    return out;
}

static long long ll(const json& r, const char* k)
{
    auto it = r.find(k);
    return (it != r.end() && it->is_number()) ? it->get<long long>() : 0;
}

static long long num(const json& c) { return c.is_number() ? c.get<long long>() : 0; }

// "YYYY-MM-DD HH:MM:SS" (секундная точность, чтобы не зависеть от микросекунд)
static std::string ts19(const json& c)
{
    if (c.is_string()) return c.get<std::string>().substr(0, 19);
    if (c.is_number_integer()) {
        std::time_t t = static_cast<std::time_t>(c.get<long long>());
        std::tm g{};
        gmtime_r(&t, &g);
        char b[32];
        std::strftime(b, sizeof b, "%Y-%m-%d %H:%M:%S", &g);
        return b;
    }
    return "";
}

static std::string make_key(const std::string& ts, long long flow, long long sig,
                            long long sp, long long dp)
{
    return ts + '|' + std::to_string(flow) + '|' + std::to_string(sig) + '|' +
           std::to_string(sp) + '|' + std::to_string(dp);
}

struct Row {
    json        j;
    std::string raw;   // исходная строка (для rejects)
    std::string key;
};

struct Stats {
    size_t read = 0, malformed = 0, out_of_range = 0, duplicates = 0,
           inserted = 0, rejected = 0;
};

static std::string build_insert(const std::vector<Row>& rows, size_t lo, size_t hi)
{
    std::string sql =
        "INSERT INTO snort_alerts (alert_time, src_ip, dst_ip, src_port, dst_port, "
        "protocol, priority, generator_id, sig_id, sig_revision, classification, "
        "action, pkt_len, ttl, iface, rule_msg, flow_id, raw_json) VALUES ";

    for (size_t i = lo; i < hi; ++i) {
        const json& r = rows[i].j;
        auto S = [&](const char* k) -> std::string {
            auto it = r.find(k);
            return (it != r.end() && it->is_string())
                       ? "'" + esc(it->get<std::string>()) + "'" : "NULL";
        };
        auto N = [&](const char* k) { return std::to_string(ll(r, k)); };

        if (i > lo) sql += ',';
        sql += '(' + S("alert_time") + ',' + S("src_ip") + ',' + S("dst_ip") + ',' +
               N("src_port") + ',' + N("dst_port") + ',' + N("protocol") + ',' +
               N("priority") + ',' + N("generator_id") + ',' + N("sig_id") + ',' +
               N("sig_revision") + ',' + S("classification") + ',' + S("action") + ',' +
               N("pkt_len") + ',' + N("ttl") + ',' + S("iface") + ',' + S("rule_msg") + ',' +
               N("flow_id") + ",'" + esc(rows[i].raw) + "')";
    }
    return sql;
}

// Вставка пачки; при отказе сервера делим пополам, пока не найдём плохую строку.
static void insert_range(Client& c, const std::vector<Row>& rows, size_t lo, size_t hi,
                         Stats& st, std::ofstream& rej)
{
    try {
        c.query(build_insert(rows, lo, hi));
        st.inserted += hi - lo;
    } catch (const QueryError& e) {
        if (hi - lo == 1) {
            ++st.rejected;
            rej << rows[lo].raw << '\n';
            std::cerr << "rejected row: " << e.what() << '\n';
            return;
        }
        const size_t mid = lo + (hi - lo) / 2;
        insert_range(c, rows, lo, mid, st, rej);
        insert_range(c, rows, mid, hi, st, rej);
    }
}

static std::unordered_set<std::string> load_existing(Client& c, const std::string& lo,
                                                     const std::string& hi)
{
    json j = c.query("SELECT alert_time, flow_id, sig_id, src_port, dst_port "
                     "FROM snort_alerts WHERE alert_time >= '" + esc(lo) +
                     "' AND alert_time <= '" + esc(hi) + "'");

    const json* rows = nullptr;
    for (const char* k : {"row_set", "rows", "result"}) {
        auto it = j.find(k);
        if (it != j.end() && it->is_array()) { rows = &*it; break; }
    }
    if (!rows)
        throw std::runtime_error("unexpected SELECT result format: adapt load_existing() "
                                 "to your endpoint or run with --no-dedup");

    std::unordered_set<std::string> keys;
    for (const auto& r : *rows)
        if (r.is_array() && r.size() >= 5)
            keys.insert(make_key(ts19(r[0]), num(r[1]), num(r[2]), num(r[3]), num(r[4])));
    return keys;
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv)
{
    Opts o;
    if (const char* p = std::getenv("HEAVYDB_PASSWORD")) o.password = p;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) { std::cerr << "missing value for " << a << '\n'; std::exit(64); }
            return argv[++i];
        };
        if      (a == "--file")     o.file       = val();
        else if (a == "--from")     o.from       = val();
        else if (a == "--to")       o.to         = val();
        else if (a == "--host")     o.host       = val();
        else if (a == "--port")     o.port       = std::stoi(val());
        else if (a == "--user")     o.user       = val();
        else if (a == "--password") o.password   = val();
        else if (a == "--db")       o.db         = val();
        else if (a == "--batch")    o.batch      = std::max<size_t>(1, std::stoul(val()));
        else if (a == "--timeout")  o.timeout_ms = std::stoi(val());
        else if (a == "--no-dedup") o.dedup      = false;
        else if (a == "--dry-run")  o.dry_run    = true;
        else { std::cerr << "unknown option: " << a << '\n'; return 64; }
    }
    if (o.file.empty()) {
        std::cerr << "usage: heavydb_replay --file F.jsonl [--from 'YYYY-MM-DD HH:MM:SS'] "
                     "[--to '...' (exclusive)] [--host H --port P --user U --db D] "
                     "[--batch N] [--no-dedup] [--dry-run]\n"
                     "password: env HEAVYDB_PASSWORD or --password\n";
        return 64;
    }

    std::ifstream in(o.file);
    if (!in) { std::cerr << "cannot open " << o.file << '\n'; return 66; }
    std::ofstream rej(o.file + ".rejects", std::ios::app);

    Stats st;
    std::vector<Row> rows;
    std::string min_ts, max_ts, line;

    // --- 1. Чтение и фильтрация сегмента ---
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        ++st.read;

        json j = json::parse(line, nullptr, false);
        if (j.is_discarded() || !j.is_object() || !j.contains("alert_time") ||
            !j["alert_time"].is_string() || j["alert_time"].get<std::string>().size() < 19) {
            ++st.malformed;                 // например, оборванная при сбое последняя строка
            rej << line << '\n';
            continue;
        }

        const std::string ts = j["alert_time"].get<std::string>();
        if ((!o.from.empty() && ts < o.from) || (!o.to.empty() && ts >= o.to)) {
            ++st.out_of_range;
            continue;
        }

        Row r;
        r.key = make_key(ts.substr(0, 19), ll(j, "flow_id"), ll(j, "sig_id"),
                         ll(j, "src_port"), ll(j, "dst_port"));
        r.j   = std::move(j);
        r.raw = line;
        if (min_ts.empty() || ts < min_ts) min_ts = ts;
        if (max_ts.empty() || ts > max_ts) max_ts = ts;
        rows.push_back(std::move(r));
    }

    std::cout << "read=" << st.read << " in_segment=" << rows.size()
              << " malformed=" << st.malformed << " out_of_range=" << st.out_of_range << '\n';

    if (o.dry_run || rows.empty()) return 0;

    // --- 2. Загрузка ---
    curl_global_init(CURL_GLOBAL_DEFAULT);
    int exit_code = 0;
    try {
        Client c(o);

        if (o.dedup) {
            const auto existing = load_existing(c, min_ts, max_ts);
            std::vector<Row> fresh;
            fresh.reserve(rows.size());
            for (auto& r : rows) {
                if (existing.count(r.key)) ++st.duplicates;
                else                       fresh.push_back(std::move(r));
            }
            rows.swap(fresh);
            std::cout << "already in HeavyDB=" << st.duplicates
                      << " to_insert=" << rows.size() << '\n';
        }

        for (size_t i = 0; i < rows.size(); i += o.batch)
            insert_range(c, rows, i, std::min(rows.size(), i + o.batch), st, rej);

    } catch (const std::exception& e) {
        std::cerr << "ABORTED: " << e.what() << "\ninserted so far: " << st.inserted
                  << " (повторный запуск безопасен при включённой дедупликации)\n";
        exit_code = 2;
    }
    curl_global_cleanup();

    std::cout << "inserted=" << st.inserted << " rejected=" << st.rejected << '\n';
    if (exit_code == 0 && (st.rejected || st.malformed)) exit_code = 1;
    return exit_code;
}
