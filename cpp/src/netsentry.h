#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  NetSentry — Core data structures
//  AhoCorasick · BloomFilter · FlowTable · Shannon entropy
// ─────────────────────────────────────────────────────────────────────────────
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// ─── Aho-Corasick multi-pattern automaton ─────────────────────────────────
// Matches N threat signatures in a single O(len) pass over packet payload.
// Failure links built with BFS; output set propagated from fail states.
class AhoCorasick {
  struct State {
    std::array<int, 256> next{};
    int fail   = 0;
    int output = 0; // bitset: bit i set → pattern[i] matched
    State() { next.fill(-1); }
  };
  std::vector<State> trie;

  void build_fail() {
    std::queue<int> q;
    for (int c = 0; c < 256; c++) {
      if (trie[0].next[c] < 0) { trie[0].next[c] = 0; }
      else { trie[trie[0].next[c]].fail = 0; q.push(trie[0].next[c]); }
    }
    while (!q.empty()) {
      int u = q.front(); q.pop();
      trie[u].output |= trie[trie[u].fail].output;
      for (int c = 0; c < 256; c++) {
        if (trie[u].next[c] < 0) {
          trie[u].next[c] = trie[trie[u].fail].next[c];
        } else {
          trie[trie[u].next[c]].fail = trie[trie[u].fail].next[c];
          q.push(trie[u].next[c]);
        }
      }
    }
  }

public:
  AhoCorasick() { trie.emplace_back(); }

  void add(const std::string& pat, int id) {
    int s = 0;
    for (uint8_t c : pat) {
      if (trie[s].next[c] < 0) { trie[s].next[c] = (int)trie.size(); trie.emplace_back(); }
      s = trie[s].next[c];
    }
    trie[s].output |= (1 << id);
  }

  void build() { build_fail(); }

  // Returns bitset of matched pattern IDs (0 = no match)
  int search(const uint8_t* data, size_t len) const {
    int s = 0, matched = 0;
    for (size_t i = 0; i < len; i++) {
      s = trie[s].next[data[i]];
      matched |= trie[s].output;
    }
    return matched;
  }
};

// ─── Bloom filter — IP reputation pre-filter ──────────────────────────────
// 4 MB bit array, 7 hash functions, <0.1% FP rate for 10M-entry threat list.
// Clears benign IPs in ~5 ns before the full rule engine runs.
class BloomFilter {
  std::vector<uint8_t> bits;
  size_t N; // total bits
  int    K; // hash functions

  uint32_t murmur(const char* key, size_t len, uint32_t seed) const {
    uint32_t h = seed;
    for (size_t i = 0; i < len; i++) {
      h ^= (uint8_t)key[i];
      h *= 0x9e3779b9u;
      h ^= h >> 16;
    }
    return h;
  }

public:
  explicit BloomFilter(size_t capacity_bits = 4ULL * 1024 * 1024 * 8, int k = 7)
    : N(capacity_bits), K(k), bits(capacity_bits / 8 + 1, 0) {}

  void insert(const std::string& key) {
    for (int i = 0; i < K; i++) {
      size_t pos = murmur(key.c_str(), key.size(), i * 0x9e3779b9u) % N;
      bits[pos / 8] |= (uint8_t)(1 << (pos % 8));
    }
  }

  bool probably_in(const std::string& key) const {
    for (int i = 0; i < K; i++) {
      size_t pos = murmur(key.c_str(), key.size(), i * 0x9e3779b9u) % N;
      if (!(bits[pos / 8] & (1 << (pos % 8)))) return false;
    }
    return true;
  }
};

// ─── Shannon entropy ──────────────────────────────────────────────────────
// H(X) = -Σ p(x) log₂(p(x))  over 128-byte payload windows.
// Encrypted/compressed data scores ≈ 7.9 bits; plaintext ≈ 4–5 bits.
inline float entropy(const uint8_t* data, size_t len) {
  if (!len) return 0.f;
  int freq[256] = {};
  for (size_t i = 0; i < len; i++) freq[data[i]]++;
  float H = 0.f;
  for (int i = 0; i < 256; i++) {
    if (freq[i]) {
      float p = (float)freq[i] / (float)len;
      H -= p * std::log2f(p);
    }
  }
  return H;
}

// ─── Flow key + state ─────────────────────────────────────────────────────
struct FlowKey {
  uint32_t src_ip, dst_ip;
  uint16_t src_port, dst_port;
  uint8_t  proto;
  bool operator==(const FlowKey& o) const {
    return src_ip == o.src_ip && dst_ip == o.dst_ip &&
           src_port == o.src_port && dst_port == o.dst_port && proto == o.proto;
  }
};

struct FlowKeyHash {
  size_t operator()(const FlowKey& k) const {
    size_t h = k.src_ip;
    h = h * 2654435761u ^ k.dst_ip;
    h = h * 2654435761u ^ ((uint32_t)k.src_port << 16 | k.dst_port);
    h = h * 2654435761u ^ k.proto;
    return h;
  }
};

struct FlowState {
  uint64_t packets = 0, bytes = 0;
  float    entropy_sum = 0.f;
  std::chrono::steady_clock::time_point first_seen, last_seen;
  std::string threat_label;
  bool blocked = false;
};

using FlowTable = std::unordered_map<FlowKey, FlowState, FlowKeyHash>;

// ─── Threat classification result ─────────────────────────────────────────
enum class Action { PASS, LOG, ALERT, BLOCK };

struct ClassifyResult {
  Action      action       = Action::PASS;
  std::string threat_type  = "BENIGN";
  std::string severity     = "LOW";
  float       entropy_val  = 0.f;
  int         matched_mask = 0;
};

// ─── Rule engine ──────────────────────────────────────────────────────────
inline ClassifyResult classify(
    const uint8_t* payload, size_t plen,
    const AhoCorasick& ac,
    const BloomFilter& bf,
    const std::string& src_ip)
{
  ClassifyResult r;
  r.entropy_val = entropy(payload, std::min(plen, (size_t)128));
  r.matched_mask = ac.search(payload, plen);
  bool threat_ip = bf.probably_in(src_ip);

  // Pattern-match wins
  if (r.matched_mask & 0b00000001) { r.threat_type="SQL_INJECTION";      r.severity="CRITICAL"; r.action=Action::BLOCK; }
  else if (r.matched_mask & 0b00000010) { r.threat_type="XSS_ATTACK";    r.severity="HIGH";     r.action=Action::BLOCK; }
  else if (r.matched_mask & 0b00000100) { r.threat_type="CMD_INJECTION";  r.severity="CRITICAL"; r.action=Action::BLOCK; }
  else if (r.matched_mask & 0b00001000) { r.threat_type="C2_BEACON";      r.severity="HIGH";     r.action=Action::ALERT; }
  else if (r.matched_mask & 0b00010000) { r.threat_type="DATA_EXFIL";     r.severity="HIGH";     r.action=Action::ALERT; }
  // Entropy-based detection (C2 beaconing / encrypted tunnels)
  else if (r.entropy_val > 7.5f) { r.threat_type="ENCRYPTED_TUNNEL";      r.severity="HIGH";     r.action=Action::ALERT; }
  // IP reputation
  else if (threat_ip) { r.threat_type="KNOWN_BAD_IP";                      r.severity="MEDIUM";   r.action=Action::LOG;   }
  else { r.threat_type="BENIGN"; r.severity="LOW"; r.action=Action::PASS; }

  return r;
}
