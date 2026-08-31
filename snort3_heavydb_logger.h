#pragma once

// snort3_heavydb_logger.h
//
// Snort 3 output (logger) plugin that forwards alert events to HeavyDB.
// Drop the compiled .so into Snort's plugin path and configure via snort.lua.
//
// Plugin name: "heavydb_logger"
//
// Fixes applied:
//  #3  Removed duplicated (one was commented-out) alert() declaration.
//  #14 Mutex removed from HeavyDbLogger: in Snort 3 each packet-thread gets
//      its own Logger instance (open() per thread). The Connector is therefore
//      accessed only from one thread at a time — a mutex adds overhead with
//      no benefit. The comment previously was self-contradictory
//      ("per-instance connector, one per thread" yet guarded by a mutex).

#include <framework/logger.h>
#include <framework/module.h>
#include <main/snort_types.h>
#include <events/event.h>

#include "heavydb_connector.h"

#include <memory>
#include <string>

namespace heavydb_plugin {

// ---------------------------------------------------------------------------
// Module: exposes Lua configuration parameters to Snort
// ---------------------------------------------------------------------------
class HeavyDbModule final : public snort::Module
{
public:
    HeavyDbModule();
    ~HeavyDbModule() override = default;

    bool set(const char*, snort::Value&, snort::SnortConfig*) override;
    bool begin(const char*, int, snort::SnortConfig*)         override;

    Module::Usage get_usage() const override
    { return CONTEXT; }

    const heavydb::ConnectionConfig& config() const { return cfg_; }

private:
    heavydb::ConnectionConfig  cfg_;
    static const snort::Parameter params_[];
};

// ---------------------------------------------------------------------------
// Logger plugin
//
// Thread-safety model (fix #14):
//   Snort 3 creates one Logger instance per packet thread via logger_ctor().
//   open() / close() / alert() / log() are always called from the same thread
//   that owns this instance — no inter-thread sharing occurs.
//   Therefore no mutex is needed here.
// ---------------------------------------------------------------------------
class HeavyDbLogger final : public snort::Logger
{
public:
    explicit HeavyDbLogger(HeavyDbModule*);
    ~HeavyDbLogger() override;

    // Snort 3 calls open()/close() once per packet thread.
    void open()  override;
    void close() override;

    // Called for every IPS/IDS alert event.
    void alert(snort::Packet*, const char* msg, const Event&) override;

    // Called for logged (non-alert) packets that carry an Event.
    // Fix #12: rate-limited — only written when priority == 1.
    void log(snort::Packet*, const char* msg, Event*) override;

private:
    heavydb::ConnectionConfig           cfg_;
    std::unique_ptr<heavydb::Connector> conn_;  // owned by this thread
};

// ---------------------------------------------------------------------------
// Plugin API registration
// ---------------------------------------------------------------------------
extern const snort::LogApi heavydb_logger_api;

} // namespace heavydb_plugin
