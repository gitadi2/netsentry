// ─────────────────────────────────────────────────────────────────────────────
//  NetSentry — Main entry point
//  Modes:
//    ./netsentry --sim              → simulation mode (no root required)
//    ./netsentry --iface eth0       → live capture via libpcap (requires root)
//
//  Output: newline-delimited JSON to stdout (consumed by Node.js API)
// ─────────────────────────────────────────────────────────────────────────────
#include "netsentry.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <thread>

#ifdef HAVE_PCAP
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

// ─── JSON helpers ─────────────────────────────────────────────────────────
static std::string esc(const std::string& s) {
  std::string r; r.reserve(s.size());
  for (char c : s) {
    if (c == '"') r += "\\\"";
    else if (c == '\\') r += "\\\\";
    else r += c;
  }
  return r;
}

static std::string action_str(Action a) {
  switch (a) {
    case Action::BLOCK: return "BLOCKED";
    case Action::ALERT: return "ALERTED";
    case Action::LOG:   return "LOGGED";
    default:            return "PASSED";
  }
}

// ─── Geo database (simulator) ─────────────────────────────────────────────
struct GeoEntry { float lat, lon; const char* country; const char* city; };
static const GeoEntry GEO_DB[] = {
  {55.75f, 37.62f,   "Russia",      "Moscow"},
  {39.93f, 116.39f,  "China",       "Beijing"},
  {51.51f, -0.13f,   "UK",          "London"},
  {48.86f,  2.35f,   "France",      "Paris"},
  {52.52f, 13.40f,   "Germany",     "Berlin"},
  {35.69f, 139.69f,  "Japan",       "Tokyo"},
  {28.61f, 77.21f,   "India",       "New Delhi"},
  {-23.55f,-46.64f,  "Brazil",      "Sao Paulo"},
  {44.44f, 26.10f,   "Romania",     "Bucharest"},
  {50.45f, 30.52f,   "Ukraine",     "Kyiv"},
  {41.01f, 28.95f,   "Turkey",      "Istanbul"},
  {40.71f,-74.01f,   "USA",         "New York"},
  {34.05f,-118.24f,  "USA",         "Los Angeles"},
  {1.35f,  103.82f,  "Singapore",   "Singapore"},
  {25.20f, 55.27f,   "UAE",         "Dubai"},
  {19.43f,-99.13f,   "Mexico",      "Mexico City"},
  {-33.87f,151.21f,  "Australia",   "Sydney"},
  {59.33f, 18.07f,   "Sweden",      "Stockholm"},
  {37.57f, 126.98f,  "South Korea", "Seoul"},
  {55.68f, 12.57f,   "Denmark",     "Copenhagen"},
  {24.47f, 54.37f,   "UAE",         "Abu Dhabi"},
  {13.75f, 100.52f,  "Thailand",    "Bangkok"},
};
static const size_t GEO_COUNT = sizeof(GEO_DB) / sizeof(GEO_DB[0]);

// ─── Threat scenarios ─────────────────────────────────────────────────────
struct ThreatScenario {
  const char* type; const char* severity; const char* protocol;
  int dst_port; const char* payload_sample;
};
static const ThreatScenario SCENARIOS[] = {
  {"SQL_INJECTION",   "CRITICAL", "HTTP",  80,   "' UNION SELECT * FROM users--"},
  {"DDoS_SYN_FLOOD",  "CRITICAL", "TCP",   443,  "[SYN flood - 120k pps]"},
  {"C2_BEACON",       "HIGH",     "HTTPS", 443,  "GET /gate.php?id=infected_host"},
  {"BRUTE_FORCE_SSH", "HIGH",     "TCP",   22,   "Failed password for root"},
  {"XSS_ATTACK",      "HIGH",     "HTTP",  80,   "<script>document.location='evil.com'"},
  {"DATA_EXFILTRATION","CRITICAL","DNS",   53,   "base64.gzip.tunnel.domain.example"},
  {"RANSOMWARE_C2",   "CRITICAL", "TCP",   4444, "POST /encrypt HTTP/1.1"},
  {"PORT_SCAN",       "MEDIUM",   "TCP",   0,    "[SYN probe - masscan]"},
  {"CRYPTO_MINER",    "MEDIUM",   "TCP",   3333, "mining.pool.connect stratum+tcp"},
  {"TOR_EXIT_NODE",   "MEDIUM",   "TCP",   9001, "[Tor circuit handshake]"},
  {"BOT_TRAFFIC",     "LOW",      "HTTP",  8080, "User-Agent: python-requests"},
  {"SMTP_RELAY_ABUSE","LOW",      "SMTP",  25,   "RCPT TO: victim@domain.com"},
};
static const size_t SCENARIO_COUNT = sizeof(SCENARIOS) / sizeof(SCENARIOS[0]);

// ─── Global counters ──────────────────────────────────────────────────────
static std::atomic<uint64_t> g_packets{0}, g_alerts{0}, g_blocked{0};
static std::atomic<uint64_t> g_flows{0};

// ─── Print JSON alert to stdout ───────────────────────────────────────────
static void emit_alert(
    const std::string& src_ip, int src_port,
    const std::string& dst_ip, int dst_port,
    const std::string& protocol,
    const ThreatScenario& sc,
    const GeoEntry& geo,
    float ent)
{
  const char* action = (std::strcmp(sc.severity, "CRITICAL") == 0 ||
                        std::strcmp(sc.severity, "HIGH")     == 0) ? "BLOCKED" : "ALERTED";

  // ISO timestamp
  auto now = std::chrono::system_clock::now();
  auto t   = std::chrono::system_clock::to_time_t(now);

  char ts[32];
  std::strftime(ts, sizeof(ts), "%FT%TZ", std::gmtime(&t));

  std::cout
    << "{\"type\":\"alert\","
    << "\"id\":\"" << std::hex << std::hash<std::string>{}(src_ip + std::to_string(t)) << std::dec << "\","
    << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() << ","
    << "\"iso\":\"" << ts << "\","
    << "\"severity\":\"" << sc.severity << "\","
    << "\"threat_type\":\"" << sc.type << "\","
    << "\"src_ip\":\"" << esc(src_ip) << "\","
    << "\"dst_ip\":\"" << esc(dst_ip) << "\","
    << "\"src_port\":" << src_port << ","
    << "\"dst_port\":" << dst_port << ","
    << "\"protocol\":\"" << sc.protocol << "\","
    << "\"payload_snippet\":\"" << esc(sc.payload_sample) << "\","
    << "\"entropy_score\":" << std::fixed << std::setprecision(2) << ent << ","
    << "\"action\":\"" << action << "\","
    << "\"geo\":{"
      << "\"lat\":" << geo.lat << ","
      << "\"lon\":" << geo.lon << ","
      << "\"country\":\"" << esc(geo.country) << "\","
      << "\"city\":\"" << esc(geo.city) << "\""
    << "}}"
    << std::endl;

  g_alerts++;
  if (std::strcmp(action, "BLOCKED") == 0) g_blocked++;
}

static void emit_stats() {
  static uint64_t last_pkt = 0;
  uint64_t cur = g_packets.load();
  uint64_t pps = cur - last_pkt;
  last_pkt = cur;

  std::cout
    << "{\"type\":\"stats\","
    << "\"packets_per_sec\":" << pps << ","
    << "\"alerts_total\":" << g_alerts.load() << ","
    << "\"blocked_total\":" << g_blocked.load() << ","
    << "\"flows_active\":" << g_flows.load() << "}"
    << std::endl;
}

// ─── Simulation mode ──────────────────────────────────────────────────────
static void run_simulator() {
  std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<int> geo_d(0, (int)GEO_COUNT - 1);
  std::uniform_int_distribution<int> sc_d(0, (int)SCENARIO_COUNT - 1);
  std::uniform_int_distribution<int> port_d(1024, 65535);
  std::uniform_int_distribution<int> ip_d(1, 254);
  std::uniform_int_distribution<int> delay_d(300, 2000); // ms between alerts
  std::uniform_real_distribution<float> ent_d(3.5f, 7.9f);

  auto pkt_ticker = std::thread([&]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      // Simulate 10k–150k packets/s processed
      g_packets += (uint64_t)(std::uniform_int_distribution<int>(10000, 150000)(rng));
      g_flows = (uint64_t)(std::uniform_int_distribution<int>(500, 4000)(rng));
      emit_stats();
    }
  });
  pkt_ticker.detach();

  while (true) {
    int delay = delay_d(rng);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    const GeoEntry& geo = GEO_DB[geo_d(rng)];
    const ThreatScenario& sc = SCENARIOS[sc_d(rng)];

    // Randomize source IP based on geo region
    std::string src_ip =
      std::to_string(ip_d(rng)) + "." +
      std::to_string(ip_d(rng)) + "." +
      std::to_string(ip_d(rng)) + "." +
      std::to_string(ip_d(rng));

    int dst_port = sc.dst_port > 0 ? sc.dst_port : port_d(rng);
    float ent = ent_d(rng);

    emit_alert(src_ip, port_d(rng), "10.0.0.1", dst_port,
               sc.protocol, sc, geo, ent);
  }
}

// ─── libpcap capture mode ─────────────────────────────────────────────────
#ifdef HAVE_PCAP
static AhoCorasick  g_ac;
static BloomFilter  g_bf;
static FlowTable    g_ft;

static void load_rules(AhoCorasick& ac) {
  ac.add("' OR 1=1",        0);  // SQL injection
  ac.add("UNION SELECT",    0);
  ac.add("<script>",        1);  // XSS
  ac.add("javascript:",     1);
  ac.add("/bin/sh",         2);  // CMD injection
  ac.add("cmd.exe",         2);
  ac.add("GET /gate.php",   3);  // C2 beacon
  ac.add("POST /check-in",  3);
  ac.add("base64.gzip",     4);  // Data exfil
  ac.build();
}

static void packet_handler(u_char* /*user*/, const struct pcap_pkthdr* hdr,
                            const u_char* pkt)
{
  g_packets++;
  if (hdr->caplen < 34) return; // Ethernet + IP minimum

  const uint8_t* ip_hdr = pkt + 14;
  if ((ip_hdr[0] & 0xF0) != 0x40) return; // IPv4 only
  int ihl = (ip_hdr[0] & 0x0F) * 4;

  uint32_t src = *(uint32_t*)(ip_hdr + 12);
  uint32_t dst = *(uint32_t*)(ip_hdr + 16);
  uint8_t  proto = ip_hdr[9];

  uint16_t sport = 0, dport = 0;
  const uint8_t* payload = ip_hdr + ihl;
  size_t   plen = hdr->caplen - 14 - ihl;

  if (proto == IPPROTO_TCP && plen >= 20) {
    sport = ntohs(*(uint16_t*)(payload));
    dport = ntohs(*(uint16_t*)(payload + 2));
    int thl = ((payload[12] >> 4) & 0xF) * 4;
    payload += thl; plen -= thl;
  } else if (proto == IPPROTO_UDP && plen >= 8) {
    sport = ntohs(*(uint16_t*)(payload));
    dport = ntohs(*(uint16_t*)(payload + 2));
    payload += 8; plen -= 8;
  }

  char sip[16], dip[16];
  snprintf(sip, 16, "%u.%u.%u.%u",
    (src)&0xFF,(src>>8)&0xFF,(src>>16)&0xFF,(src>>24)&0xFF);
  snprintf(dip, 16, "%u.%u.%u.%u",
    (dst)&0xFF,(dst>>8)&0xFF,(dst>>16)&0xFF,(dst>>24)&0xFF);

  auto res = classify(payload, plen, g_ac, g_bf, sip);
  if (res.action == Action::PASS) return;

  GeoEntry geo{0,0,"Unknown","Unknown"};
  ThreatScenario sc{
    res.threat_type.c_str(), res.severity.c_str(),
    proto == IPPROTO_TCP ? "TCP" : "UDP",
    (int)dport, "[live capture]"
  };
  emit_alert(sip, sport, dip, dport, sc.protocol, sc, geo, res.entropy_val);
}

static void run_capture(const char* iface) {
  load_rules(g_ac);
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(iface, 65535, 1, 100, errbuf);
  if (!handle) { std::cerr << "pcap_open_live: " << errbuf << "\n"; return; }

  struct bpf_program fp;
  pcap_compile(handle, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(handle, &fp);
  pcap_loop(handle, -1, packet_handler, nullptr);
  pcap_close(handle);
}
#endif

// ─── main ─────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
  std::ios::sync_with_stdio(false);
  std::cout.setf(std::ios::unitbuf); // flush after each output

  if (argc >= 2 && std::strcmp(argv[1], "--iface") == 0) {
#ifdef HAVE_PCAP
    if (argc < 3) { std::cerr << "Usage: netsentry --iface <interface>\n"; return 1; }
    std::cerr << "[NetSentry] Live capture on " << argv[2] << "\n";
    run_capture(argv[2]);
#else
    std::cerr << "[NetSentry] libpcap not compiled in. Rebuild with -DHAVE_PCAP.\n";
    return 1;
#endif
  } else {
    // Default: simulation mode
    std::cerr << "[NetSentry] Simulation mode — generating synthetic attack traffic\n";
    run_simulator();
  }
  return 0;
}
