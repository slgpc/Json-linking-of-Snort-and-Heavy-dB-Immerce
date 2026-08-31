#pragma once

// heavydb_connector.h
//
// Fixes applied:
//  #2  curl_global_init moved out of constructor — call global_init()/global_cleanup()
//      exactly once at process level via Connector::global_init() / global_cleanup().
//  #5  Added reconnect logic: try_reconnect() called automatically on execute() failure.
//  #8  batch_size validated > 0; stored as std::size_t to avoid signed/unsigned mismatch.
//  #9  flush_impl() (was flush_locked()) is private and clearly documented as
//      "must be called with mtx_ held OR from single-owner context".

#include <string>
#include <vector>
#include <cstddef>
#include <stdexcept>

namespace heavydb {

struct ConnectionConfig {
    std::string host       = "localhost";
    int         port       = 6278;          // HeavyDB HTTP port
    std::string user       = "admin";
    std::string password   = "HyperInteractive";
    std::string db_name    = "heavyai";
    bool        use_https  = false;
    int         timeout_ms = 5000;          // per-request timeout (ms)
    int         batch_size = 512;           // rows buffered before auto-flush (must be >= 1)
    int         max_reconnect_attempts = 3; // how many times to retry on session failure
};

// ---------------------------------------------------------------------------
// Process-level libcurl lifecycle (fix #2).
// Call global_init() once in pinit, global_cleanup() once in pterm.
// ---------------------------------------------------------------------------
void global_init();    // wraps curl_global_init(CURL_GLOBAL_DEFAULT)
void global_cleanup(); // wraps curl_global_cleanup()

// ---------------------------------------------------------------------------
// Lightweight HTTP connector to HeavyDB's REST SQL endpoint.
//
// Thread-safety: each instance owns its own CURL handle.
//   Do NOT share a single Connector across threads.
//   In Snort 3 each packet-thread calls open() which creates its own instance.
//
// Naming convention:
//   flush_impl() — internal flush; caller is responsible for ensuring
//                  single-threaded access (either holds mutex or is sole owner).
// ---------------------------------------------------------------------------
class Connector {
public:
    explicit Connector(const ConnectionConfig& cfg);
    ~Connector();

    // Non-copyable, movable
    Connector(const Connector&)            = delete;
    Connector& operator=(const Connector&) = delete;
    Connector(Connector&&)                 noexcept;
    Connector& operator=(Connector&&)      noexcept;

    // Execute a single SQL statement (DDL / DML).
    // On session failure attempts reconnect up to cfg.max_reconnect_attempts times.
    // Throws std::runtime_error on permanent failure.
    void execute(const std::string& sql);

    // Ensure the target table exists with the expected schema.
    void ensure_table();

    // Enqueue one JSON-encoded row.
    // Auto-flushes when buffer reaches batch_size.
    void enqueue(const std::string& json_row);

    // Force-flush any buffered rows to HeavyDB.
    void flush();

    // Number of rows currently buffered.
    std::size_t buffered_count() const { return buffer_.size(); }

private:
    ConnectionConfig         cfg_;
    void*                    curl_ = nullptr;   // CURL* opaque handle
    std::string              session_;           // HeavyDB session token
    std::vector<std::string> buffer_;            // pending JSON rows
    std::size_t              safe_batch_size_;   // validated copy of cfg_.batch_size

    void        connect();
    void        disconnect();
    // Attempt to re-establish session; throws if all attempts fail.
    void        try_reconnect();

    std::string post(const std::string& path, const std::string& body);

    // Internal flush — caller must ensure exclusive access.
    // Named flush_impl (not flush_locked) to make contract explicit.
    void        flush_impl();

    // Escape a string value for embedding in SQL literals.
    // Handles: single-quote doubling + NUL / control-character stripping.
    static std::string escape_sql_string(const std::string& s);
};

} // namespace heavydb
