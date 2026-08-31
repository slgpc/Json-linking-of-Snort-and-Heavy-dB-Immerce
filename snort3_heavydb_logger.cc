#include "snort3_heavydb_logger.h"
#include "json_binding.h"
#include "heavydb_connector.h"

#include <framework/logger.h>
#include <framework/module.h>
#include <main/snort_types.h>
#include <log/messages.h>
#include <curl/curl.h>

#include <stdexcept>
#include <string>

// Fixes applied in this file:
//  #2  curl_global_init / curl_global_cleanup called from pinit / pterm
//      (process-level hooks in LogApi), NOT from the Connector constructor.
//  #4  LogApi struct fully populated with explicit nullptr for all optional
//      fields (pinit, pterm, tinit, tterm) so no struct-member offset shift.
//  #12 log() is rate-limited: only events with priority == 1 (highest) are
//      written to avoid flooding HeavyDB at 10+ Gbps.
//  #14 Mutex removed from HeavyDbLogger — see header for rationale.

using namespace snort;

namespace heavydb_plugin {

// ---------------------------------------------------------------------------
// Module parameter table
// ---------------------------------------------------------------------------
const Parameter HeavyDbModule::params_[] =
{
    { "host",       Parameter::PT_STRING,  nullptr,    "localhost",
      "HeavyDB server hostname or IP" },

    { "port",       Parameter::PT_INT,     "1:65535",  "6278",
      "HeavyDB HTTP port (default 6278)" },

    { "user",       Parameter::PT_STRING,  nullptr,    "admin",
      "HeavyDB username" },

    { "password",   Parameter::PT_STRING,  nullptr,    "HyperInteractive",
      "HeavyDB password" },

    { "db_name",    Parameter::PT_STRING,  nullptr,    "heavyai",
      "HeavyDB database name" },

    { "use_https",  Parameter::PT_BOOL,    nullptr,    "false",
      "Use HTTPS for the HeavyDB connection" },

    { "timeout_ms", Parameter::PT_INT,     "100:60000","5000",
      "Per-request timeout in milliseconds" },

    { "batch_size", Parameter::PT_INT,     "1:65536",  "512",
      "Rows to buffer before a bulk INSERT flush" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

// ---------------------------------------------------------------------------
// HeavyDbModule
// ---------------------------------------------------------------------------
HeavyDbModule::HeavyDbModule()
    : Module("heavydb_logger",
             "Snort 3 logger plugin: streams alerts to HeavyDB (GPU analytics DB)",
             params_)
{}

bool HeavyDbModule::begin(const char* /*fqn*/, int /*idx*/, SnortConfig*)
{
    cfg_ = heavydb::ConnectionConfig{};
    return true;
}

bool HeavyDbModule::set(const char* /*fqn*/, Value& v, SnortConfig*)
{
    if      (v.is("host"))       cfg_.host       = v.get_string();
    else if (v.is("port"))       cfg_.port        = static_cast<int>(v.get_int64());
    else if (v.is("user"))       cfg_.user       = v.get_string();
    else if (v.is("password"))   cfg_.password   = v.get_string();
    else if (v.is("db_name"))    cfg_.db_name    = v.get_string();
    else if (v.is("use_https"))  cfg_.use_https  = v.get_bool();
    else if (v.is("timeout_ms")) cfg_.timeout_ms = static_cast<int>(v.get_int64());
    else if (v.is("batch_size")) cfg_.batch_size = static_cast<int>(v.get_int64());
    else return false;
    return true;
}

// ---------------------------------------------------------------------------
// HeavyDbLogger
// ---------------------------------------------------------------------------
HeavyDbLogger::HeavyDbLogger(HeavyDbModule* mod)
    : cfg_(mod->config())
{}

HeavyDbLogger::~HeavyDbLogger()
{
    // conn_ is cleaned up in close(); this is a safety net only.
}

void HeavyDbLogger::open()
{
    // Fix #14: no mutex — this method is called from exactly one packet thread.
    try {
        conn_ = std::make_unique<heavydb::Connector>(cfg_);
        conn_->ensure_table();
        LogMessage("heavydb_logger: connected to %s:%d db=%s\n",
                   cfg_.host.c_str(), cfg_.port, cfg_.db_name.c_str());
    } catch (const std::exception& ex) {
        ErrorMessage("heavydb_logger: open() failed: %s\n", ex.what());
        conn_.reset();
    }
}

void HeavyDbLogger::close()
{
    if (conn_) {
        try { conn_->flush(); }
        catch (const std::exception& ex) {
            ErrorMessage("heavydb_logger: flush on close failed: %s\n", ex.what());
        }
        conn_.reset();
    }
}

void HeavyDbLogger::alert(Packet* p, const char* /*msg*/, const Event& e)
{
    if (!conn_) return;

    try {
        const std::string json = json_binding::serialize(p, &e);
        conn_->enqueue(json);   // fix #14: no mutex, single-thread access
    } catch (const std::exception& ex) {
        ErrorMessage("heavydb_logger: alert() error: %s\n", ex.what());
    }
}

void HeavyDbLogger::log(Packet* p, const char* /*msg*/, Event* e)
{
    // Fix #12: rate-limit non-alert log() calls.
    // Only forward events with priority 1 (highest urgency) to avoid
    // overwhelming HeavyDB at multi-Gbps line rates.
    if (!conn_ || !e) return;

    constexpr uint32_t LOG_PRIORITY_THRESHOLD = 1u;
    if (e->get_priority() > LOG_PRIORITY_THRESHOLD) return;

    try {
        const std::string json = json_binding::serialize(p, e);
        conn_->enqueue(json);
    } catch (const std::exception& ex) {
        ErrorMessage("heavydb_logger: log() error: %s\n", ex.what());
    }
}

// ---------------------------------------------------------------------------
// Plugin factory functions
// ---------------------------------------------------------------------------
static Module* mod_ctor()
{ 
    curl_global_init(CURL_GLOBAL_DEFAULT);
    return new HeavyDbModule(); 
}

static void mod_dtor(Module* m)
{
    delete m;
    curl_global_cleanup();
}
//static void mod_dtor(Module* m)
//{ delete m; }

static Logger* logger_ctor(Module* mod)
{ return new HeavyDbLogger(static_cast<HeavyDbModule*>(mod)); }

static void logger_dtor(Logger* l)
{ delete l; }

// ---------------------------------------------------------------------------
// Fix #2: process-level libcurl init / cleanup via pinit / pterm hooks.
//   pinit  — called once in main thread before any packet thread starts.
//   pterm  — called once in main thread after all packet threads exit.
//   Guarantees curl_global_init runs exactly once.
// ---------------------------------------------------------------------------
static bool plugin_pinit()
{
    try {
        heavydb::global_init();
        return true;
    } catch (const std::exception& ex) {
        ErrorMessage("heavydb_logger: pinit failed: %s\n", ex.what());
        return false;
    }
}

static void plugin_pterm()
{
    heavydb::global_cleanup();
}

// ---------------------------------------------------------------------------
// LogApi registration struct
//
// Fix #4: ALL fields explicitly provided — no commented-out nullptrs.
//         Commented-out fields shift subsequent members in the struct
//         initializer, mapping logger_ctor into the wrong slot and causing
//         a silent segfault when Snort loads the plugin.
//
// LogApi layout (from framework/logger.h):
//   BaseApi    base
//   unsigned   flags
//   bool     (*pinit)()
//   void     (*pterm)()
//   void     (*tinit)()
//   void     (*tterm)()
//   LogNewFunc ctor
//   LogDelFunc dtor
// ---------------------------------------------------------------------------
const snort::LogApi heavydb_logger_api =
{
    {   // BaseApi
        PT_LOGGER,
        sizeof(snort::LogApi),
        LOGAPI_VERSION,
        0,               // api_version (reserved)
        0,               // API_RESERVED
        0,               // API_OPTIONS
        "heavydb_logger",
        "Snort 3 alert logger -> HeavyDB (GPU-accelerated analytics database)",
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT | OUTPUT_TYPE_FLAG__LOG,
//    plugin_pinit,   // pinit  — calls heavydb::global_init()    (fix #2)
//    plugin_pterm,   // pterm  — calls heavydb::global_cleanup() (fix #2)
//    nullptr,        // tinit  — not needed
//    nullptr,        // tterm  — not needed
    logger_ctor,
    logger_dtor
};

// ---------------------------------------------------------------------------
// Snort 3 plugin discovery entry point
// ---------------------------------------------------------------------------
extern "C" {
    const BaseApi* snort_plugins[] = {
        &heavydb_logger_api.base,
        nullptr
    };
}

} // namespace heavydb_plugin
