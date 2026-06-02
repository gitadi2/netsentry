// ─────────────────────────────────────────────────────────────────────────────
//  NetSentry — Unit tests (GoogleTest)
//  Covers: AhoCorasick · BloomFilter · entropy() · classify()
//
//  Build:   cmake -B build -DBUILD_TESTS=ON && cmake --build build
//  Run:     ./build/netsentry_tests
//  Or:      cd build && ctest --output-on-failure
// ─────────────────────────────────────────────────────────────────────────────
#include "netsentry.h"
#include <gtest/gtest.h>
#include <cstring>
#include <random>
#include <string>

// Helper: search over a std::string payload
static int ac_search(const AhoCorasick& ac, const std::string& s) {
  return ac.search(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
static float entropy_of(const std::string& s) {
  return entropy(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// ═══════════════════════════════════════════════════════════════════════════
//  AhoCorasick
// ═══════════════════════════════════════════════════════════════════════════
class AhoCorasickTest : public ::testing::Test {
protected:
  AhoCorasick ac;
};

TEST_F(AhoCorasickTest, EmptyAutomatonMatchesNothing) {
  ac.build();
  EXPECT_EQ(ac_search(ac, "any random text here"), 0);
}

TEST_F(AhoCorasickTest, SinglePatternExactMatch) {
  ac.add("attack", 0);
  ac.build();
  EXPECT_NE(ac_search(ac, "this is an attack payload"), 0);
}

TEST_F(AhoCorasickTest, SinglePatternNoMatch) {
  ac.add("attack", 0);
  ac.build();
  EXPECT_EQ(ac_search(ac, "completely benign traffic"), 0);
}

TEST_F(AhoCorasickTest, MatchReturnsCorrectIdBit) {
  ac.add("sql", 0);   // bit 0 → mask 0b0001
  ac.add("xss", 1);   // bit 1 → mask 0b0010
  ac.build();
  int mask = ac_search(ac, "payload with xss inside");
  EXPECT_TRUE(mask & (1 << 1));   // xss bit set
  EXPECT_FALSE(mask & (1 << 0));  // sql bit not set
}

TEST_F(AhoCorasickTest, MultiplePatternsMatchSimultaneously) {
  ac.add("sql", 0);
  ac.add("xss", 1);
  ac.build();
  int mask = ac_search(ac, "both sql and xss present");
  EXPECT_TRUE(mask & (1 << 0));
  EXPECT_TRUE(mask & (1 << 1));
}

TEST_F(AhoCorasickTest, OverlappingPatterns) {
  ac.add("he", 0);
  ac.add("she", 1);
  ac.add("his", 2);
  ac.add("hers", 3);
  ac.build();
  // "hers" contains both "he" (id0) and "hers" (id3)
  int mask = ac_search(ac, "hers");
  EXPECT_TRUE(mask & (1 << 0));  // "he"
  EXPECT_TRUE(mask & (1 << 3));  // "hers"
}

TEST_F(AhoCorasickTest, MatchAtStartMiddleEnd) {
  ac.add("x", 0);
  ac.build();
  EXPECT_NE(ac_search(ac, "x at start"), 0);
  EXPECT_NE(ac_search(ac, "middle x here"), 0);
  EXPECT_NE(ac_search(ac, "ends with x"), 0);
}

TEST_F(AhoCorasickTest, RealAttackSignatures) {
  ac.add("' OR 1=1",      0);
  ac.add("UNION SELECT",  1);
  ac.add("<script>",      2);
  ac.add("/bin/sh",       3);
  ac.build();
  EXPECT_TRUE(ac_search(ac, "admin' OR 1=1--")        & (1 << 0));
  EXPECT_TRUE(ac_search(ac, "x UNION SELECT pw")      & (1 << 1));
  EXPECT_TRUE(ac_search(ac, "<script>alert(1)</script>") & (1 << 2));
  EXPECT_TRUE(ac_search(ac, "exec /bin/sh -i")        & (1 << 3));
  EXPECT_EQ(ac_search(ac, "SELECT name FROM products"), 0); // benign SQL
}

TEST_F(AhoCorasickTest, BinarySafeMatching) {
  // Patterns and payloads may contain non-printable bytes
  std::string pat = "\x00\x01\x02";  // 3 bytes incl. NUL
  ac.add(std::string("\x00\x01\x02", 3), 0);
  ac.build();
  std::string payload("prefix\x00\x01\x02 suffix", 16);
  EXPECT_NE(ac.search(reinterpret_cast<const uint8_t*>(payload.data()), payload.size()), 0);
}

TEST_F(AhoCorasickTest, EmptyPayloadMatchesNothing) {
  ac.add("test", 0);
  ac.build();
  EXPECT_EQ(ac_search(ac, ""), 0);
}

// ═══════════════════════════════════════════════════════════════════════════
//  BloomFilter
// ═══════════════════════════════════════════════════════════════════════════
TEST(BloomFilterTest, InsertedKeyIsFound) {
  BloomFilter bf;
  bf.insert("192.168.1.100");
  EXPECT_TRUE(bf.probably_in("192.168.1.100"));
}

TEST(BloomFilterTest, MultipleKeysAllFound) {
  BloomFilter bf;
  const char* ips[] = {"10.0.0.1", "172.16.5.4", "203.0.113.7", "8.8.8.8"};
  for (auto ip : ips) bf.insert(ip);
  for (auto ip : ips) EXPECT_TRUE(bf.probably_in(ip)) << "missing: " << ip;
}

TEST(BloomFilterTest, NoFalseNegatives) {
  // A Bloom filter must NEVER report a false negative.
  BloomFilter bf;
  std::mt19937 rng(42);
  std::vector<std::string> inserted;
  for (int i = 0; i < 1000; i++) {
    std::string key = "ip-" + std::to_string(rng());
    bf.insert(key);
    inserted.push_back(key);
  }
  for (const auto& k : inserted)
    EXPECT_TRUE(bf.probably_in(k)) << "false negative on: " << k;
}

TEST(BloomFilterTest, UnlikelyKeyUsuallyAbsent) {
  BloomFilter bf;
  bf.insert("the.only.key");
  // A never-inserted key should very probably be reported absent.
  EXPECT_FALSE(bf.probably_in("definitely.not.inserted.xyz.123"));
}

TEST(BloomFilterTest, FalsePositiveRateWithinBound) {
  // Insert 10k keys into a default 4MB / 7-hash filter, then probe 10k
  // never-inserted keys. Empirical FPR should be well under 1%.
  BloomFilter bf;  // 4 MB, k=7
  const int N = 10000;
  std::mt19937 rng(123);

  for (int i = 0; i < N; i++)
    bf.insert("inserted-" + std::to_string(i));

  int false_positives = 0;
  for (int i = 0; i < N; i++) {
    std::string probe = "absent-key-" + std::to_string(i);
    if (bf.probably_in(probe)) false_positives++;
  }
  double fpr = (double)false_positives / N;
  // Theoretical FPR for m=32Mbit, n=10k, k=7 is astronomically small;
  // allow generous 1% ceiling to stay robust across hash behavior.
  EXPECT_LT(fpr, 0.01) << "FPR too high: " << fpr;
}

TEST(BloomFilterTest, SmallFilterHasHigherFprButNoFalseNegatives) {
  // A deliberately tiny filter to exercise saturation behavior.
  BloomFilter bf(1024, 3);  // 1024 bits, 3 hashes
  std::vector<std::string> keys;
  for (int i = 0; i < 200; i++) {
    std::string k = "k" + std::to_string(i);
    bf.insert(k);
    keys.push_back(k);
  }
  // Still no false negatives even when saturated.
  for (const auto& k : keys) EXPECT_TRUE(bf.probably_in(k));
}

TEST(BloomFilterTest, EmptyFilterFindsNothing) {
  BloomFilter bf;
  EXPECT_FALSE(bf.probably_in("anything"));
  EXPECT_FALSE(bf.probably_in(""));
}

// ═══════════════════════════════════════════════════════════════════════════
//  entropy()
// ═══════════════════════════════════════════════════════════════════════════
TEST(EntropyTest, EmptyInputIsZero) {
  EXPECT_FLOAT_EQ(entropy(nullptr, 0), 0.0f);
}

TEST(EntropyTest, SingleRepeatedByteIsZero) {
  std::string s(256, 'A');  // all identical bytes → zero entropy
  EXPECT_NEAR(entropy_of(s), 0.0f, 1e-5);
}

TEST(EntropyTest, UniformAllBytesIsEight) {
  // Every byte value 0..255 exactly once → maximal entropy = 8 bits.
  std::vector<uint8_t> buf(256);
  for (int i = 0; i < 256; i++) buf[i] = (uint8_t)i;
  EXPECT_NEAR(entropy(buf.data(), buf.size()), 8.0f, 1e-4);
}

TEST(EntropyTest, TwoEqualSymbolsIsOneBit) {
  // 50/50 split of two values → 1 bit of entropy.
  std::string s;
  for (int i = 0; i < 128; i++) { s += 'A'; s += 'B'; }
  EXPECT_NEAR(entropy_of(s), 1.0f, 1e-5);
}

TEST(EntropyTest, PlaintextLowerThanRandom) {
  std::string text = "the quick brown fox jumps over the lazy dog "
                     "the quick brown fox jumps over the lazy dog";
  std::vector<uint8_t> rnd(512);
  std::mt19937 rng(7);
  for (auto& b : rnd) b = (uint8_t)(rng() & 0xFF);

  float h_text = entropy_of(text);
  float h_rand = entropy(rnd.data(), rnd.size());
  EXPECT_LT(h_text, h_rand);
  EXPECT_GT(h_rand, 7.0f);   // random data scores high
  EXPECT_LT(h_text, 6.0f);   // english text scores lower
}

TEST(EntropyTest, MonotonicWithDiversity) {
  std::string low  = "aaaaaaaaaabbbbbbbbbb";       // 2 symbols
  std::string high = "abcdefghijklmnopqrst";       // 20 symbols
  EXPECT_LT(entropy_of(low), entropy_of(high));
}

// ═══════════════════════════════════════════════════════════════════════════
//  classify()  — end-to-end rule engine
// ═══════════════════════════════════════════════════════════════════════════
class ClassifyTest : public ::testing::Test {
protected:
  AhoCorasick ac;
  BloomFilter bf;
  void SetUp() override {
    ac.add("' OR 1=1",     0);  // SQL injection  → bit 0
    ac.add("UNION SELECT", 0);
    ac.add("<script>",     1);  // XSS            → bit 1
    ac.add("/bin/sh",      2);  // CMD injection  → bit 2
    ac.add("GET /gate.php",3);  // C2 beacon      → bit 3
    ac.add("base64.gzip",  4);  // Data exfil     → bit 4
    ac.build();
    bf.insert("66.66.66.66");   // known-bad IP
  }
  ClassifyResult run(const std::string& payload, const std::string& ip = "1.2.3.4") {
    return classify(reinterpret_cast<const uint8_t*>(payload.data()),
                    payload.size(), ac, bf, ip);
  }
};

TEST_F(ClassifyTest, BenignTrafficPasses) {
  auto r = run("GET /index.html HTTP/1.1");
  EXPECT_EQ(r.action, Action::PASS);
  EXPECT_EQ(r.threat_type, "BENIGN");
}

TEST_F(ClassifyTest, SqlInjectionBlocked) {
  auto r = run("admin' OR 1=1--");
  EXPECT_EQ(r.action, Action::BLOCK);
  EXPECT_EQ(r.threat_type, "SQL_INJECTION");
  EXPECT_EQ(r.severity, "CRITICAL");
}

TEST_F(ClassifyTest, XssBlocked) {
  auto r = run("<script>alert(document.cookie)</script>");
  EXPECT_EQ(r.action, Action::BLOCK);
  EXPECT_EQ(r.threat_type, "XSS_ATTACK");
}

TEST_F(ClassifyTest, CommandInjectionBlocked) {
  auto r = run("; /bin/sh -i");
  EXPECT_EQ(r.action, Action::BLOCK);
  EXPECT_EQ(r.threat_type, "CMD_INJECTION");
}

TEST_F(ClassifyTest, C2BeaconAlerts) {
  auto r = run("GET /gate.php?id=host");
  EXPECT_EQ(r.action, Action::ALERT);
  EXPECT_EQ(r.threat_type, "C2_BEACON");
}

TEST_F(ClassifyTest, KnownBadIpLogged) {
  // Benign payload but flagged source IP → LOG
  auto r = run("GET /normal HTTP/1.1", "66.66.66.66");
  EXPECT_EQ(r.action, Action::LOG);
  EXPECT_EQ(r.threat_type, "KNOWN_BAD_IP");
}

TEST_F(ClassifyTest, EntropyValueIsPopulated) {
  auto r = run("some payload data here");
  EXPECT_GT(r.entropy_val, 0.0f);
}

TEST_F(ClassifyTest, PatternMatchBeatsEntropy) {
  // Even if entropy were high, an explicit signature wins and sets the type.
  auto r = run("UNION SELECT secret");
  EXPECT_EQ(r.threat_type, "SQL_INJECTION");
}

// ═══════════════════════════════════════════════════════════════════════════
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}