#pragma once

// json_binding.h
// Converts Snort 3 alert/packet structures into nlohmann::json objects.
//
// Fixes applied:
//  #7  Timestamp fallback when p==nullptr now uses Event::get_seconds() if
//      available, and only falls back to wall-clock with an explicit marker
//      field "alert_time_synthetic": true to flag the uncertainty.
//  #10 ingress_index values DAQ_PKTHDR_UNKNOWN (-1) and DAQ_PKTHDR_FLOOD (-2)
//      are now mapped to meaningful string constants instead of "-1"/"-2".
//  #13 Removed unused #include <network_inspectors/appid/appid_session_api.h>.

#include <sfip/sf_ip.h>
#include <time/packet_time.h>
#include <protocols/packet.h>
#include <events/event.h>
#include <framework/logger.h>

// Transport / L4 headers
#include <protocols/tcp.h>
#include <protocols/udp.h>
#include <protocols/icmp4.h>
#include <protocols/eth.h>

// DAQ constants for ingress_index sentinel values (fix #10)
#include <daq_common.h>

#include <arpa/inet.h>
#include <sys/time.h>

#include <string>
#include <ctime>
#include <sstream>

#include <nlohmann/json.hpp>

namespace snort { struct Packet; }
class Event;

namespace json_binding {

// -----------------------------------------------------------------------
// Timestamp helpers
// -----------------------------------------------------------------------

// Formats a timeval as "YYYY-MM-DD HH:MM:SS.uuuuuu" — HeavyDB TIMESTAMP(6)
inline std::string format_ts(const struct timeval& tv)
{
    std::time_t t = tv.tv_sec;
    struct tm gmt{};
    gmtime_r(&t, &gmt);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &gmt);

    char full[48];
    std::snprintf(full, sizeof(full), "%s.%06ld", buf,
                  static_cast<long>(tv.tv_usec));
    return full;
}

// -----------------------------------------------------------------------
// IP address helper  (SfIp → dotted-decimal or IPv6 string)
// -----------------------------------------------------------------------
inline std::string sfip_to_string(const snort::SfIp* ip)
{
    if (!ip) return "0.0.0.0";
    char buf[INET6_ADDRSTRLEN] = {};
    ip->ntop(buf, sizeof(buf));
    return buf;
}

// -----------------------------------------------------------------------
// Fix #10: human-readable interface name for DAQ sentinel values.
//   DAQ_PKTHDR_UNKNOWN = -1  → "unknown"
//   DAQ_PKTHDR_FLOOD   = -2  → "flood"
//   any other value          → decimal string of the index
// -----------------------------------------------------------------------
inline std::string iface_to_string(int32_t ingress_index)
{
    if (ingress_index == DAQ_PKTHDR_UNKNOWN) return "unknown";
    if (ingress_index == DAQ_PKTHDR_FLOOD)   return "flood";
    return std::to_string(ingress_index);
}

// -----------------------------------------------------------------------
// Core packet → JSON
// -----------------------------------------------------------------------
inline nlohmann::json packet_to_json(const snort::Packet* p,
                                     const Event*         e)
{
    nlohmann::json j;

    // --- Timestamp (fix #7) ---
    // Priority: packet header timestamp (most accurate)
    //           → Event::get_seconds() (correct event time, no microseconds)
    //           → wall-clock fallback (synthetic, flagged explicitly)
    if (p && p->pkth) {
        j["alert_time"]           = format_ts(p->pkth->ts);
        j["pkt_len"]              = static_cast<int>(p->pkth->pktlen);
        j["alert_time_synthetic"] = false;
    } else if (e) {
        struct timeval tv{};
        tv.tv_sec  = static_cast<time_t>(e->get_seconds());
        tv.tv_usec = 0;
        j["alert_time"]           = format_ts(tv);
        j["pkt_len"]              = 0;
        j["alert_time_synthetic"] = false;
    } else {
        // Absolute last resort — mark synthetic so analysts can filter it.
        struct timeval tv{};
        gettimeofday(&tv, nullptr);
        j["alert_time"]           = format_ts(tv);
        j["pkt_len"]              = 0;
        j["alert_time_synthetic"] = true;
    }

    // --- Network layer (L3) ---
    if (p && p->ptrs.ip_api.is_ip()) {
        j["src_ip"]   = sfip_to_string(p->ptrs.ip_api.get_src());
        j["dst_ip"]   = sfip_to_string(p->ptrs.ip_api.get_dst());
        j["ttl"]      = static_cast<int>(p->ptrs.ip_api.ttl());
        j["protocol"] = static_cast<int>(p->ptrs.ip_api.proto());
    } else {
        j["src_ip"]   = "0.0.0.0";
        j["dst_ip"]   = "0.0.0.0";
        j["ttl"]      = 0;
        j["protocol"] = 0;
    }

    // --- Transport layer (L4) ---
    j["src_port"] = 0;
    j["dst_port"] = 0;

    if (p) {
        if (p->ptrs.tcph) {
            j["src_port"] = static_cast<int>(p->ptrs.sp);
            j["dst_port"] = static_cast<int>(p->ptrs.dp);
        } else if (p->ptrs.udph) {
            j["src_port"] = static_cast<int>(p->ptrs.sp);
            j["dst_port"] = static_cast<int>(p->ptrs.dp);
        } else if (p->ptrs.icmph) {
            // For ICMP store type/code in src_port/dst_port columns
            j["src_port"] = static_cast<int>(p->ptrs.icmph->type);
            j["dst_port"] = static_cast<int>(p->ptrs.icmph->code);
        }
    }

    // --- Interface (fix #10: DAQ sentinel values handled) ---
    if (p && p->pkth)
        j["iface"] = iface_to_string(p->pkth->ingress_index);
    else
        j["iface"] = "unknown";

    // --- Flow ID ---
    j["flow_id"] = (p && p->pkth)
                   ? static_cast<long long>(p->pkth->flow_id)
                   : 0LL;

    // --- Event / signature ---
    if (e) {
        j["generator_id"]   = static_cast<int>(e->get_gid());
        j["sig_id"]         = static_cast<int>(e->get_sid());
        j["sig_revision"]   = static_cast<int>(e->get_rev());
        j["priority"]       = static_cast<int>(e->get_priority());
        const char* cls     = e->get_class_type();
        j["classification"] = cls ? std::string(cls) : "";
        j["rule_msg"]       = e->get_msg() ? std::string(e->get_msg()) : "";
    } else {
        j["generator_id"]   = 0;
        j["sig_id"]         = 0;
        j["sig_revision"]   = 0;
        j["priority"]       = 0;
        j["classification"] = "";
        j["rule_msg"]       = "";
    }

    // --- Action ---
    j["action"] = (e && e->get_action()) ? std::string(e->get_action()) : "allow";

    return j;
}

// -----------------------------------------------------------------------
// Convenience: returns the serialized JSON string (raw_json column value)
// -----------------------------------------------------------------------
inline std::string serialize(const snort::Packet* p, const Event* e)
{
    return packet_to_json(p, e).dump();
}

} // namespace json_binding
