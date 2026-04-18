// ─────────────────────────────────────────────────────────────────────────────
//  NetSentry API Server v2
// ─────────────────────────────────────────────────────────────────────────────
const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const cors       = require('cors');
const { spawn }  = require('child_process');
const { randomUUID } = require('crypto');
const path       = require('path');
const fs         = require('fs');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json({ limit: '2mb' }));

const MAX_ALERTS = 1000;
const alerts     = [];
const stats      = {
  packets_per_sec: 0,
  alerts_total:    0,
  blocked_total:   0,
  flows_active:    0,
  start_time:      Date.now(),
};

const ATTACK_SOURCES = [
  { lat: 55.75,  lon:  37.62,  country: 'Russia',      city: 'Moscow'       },
  { lat: 39.93,  lon: 116.39,  country: 'China',        city: 'Beijing'      },
  { lat: 51.51,  lon:  -0.13,  country: 'UK',           city: 'London'       },
  { lat: 48.86,  lon:   2.35,  country: 'France',       city: 'Paris'        },
  { lat: 52.52,  lon:  13.40,  country: 'Germany',      city: 'Berlin'       },
  { lat: 35.69,  lon: 139.69,  country: 'Japan',        city: 'Tokyo'        },
  { lat: 28.61,  lon:  77.21,  country: 'India',        city: 'New Delhi'    },
  { lat:-23.55,  lon: -46.64,  country: 'Brazil',       city: 'São Paulo'    },
  { lat: 44.44,  lon:  26.10,  country: 'Romania',      city: 'Bucharest'    },
  { lat: 50.45,  lon:  30.52,  country: 'Ukraine',      city: 'Kyiv'         },
  { lat: 41.01,  lon:  28.95,  country: 'Turkey',       city: 'Istanbul'     },
  { lat: 40.71,  lon: -74.01,  country: 'USA',          city: 'New York'     },
  { lat: 34.05,  lon:-118.24,  country: 'USA',          city: 'Los Angeles'  },
  { lat:  1.35,  lon: 103.82,  country: 'Singapore',    city: 'Singapore'    },
  { lat: 25.20,  lon:  55.27,  country: 'UAE',          city: 'Dubai'        },
  { lat: 19.43,  lon: -99.13,  country: 'Mexico',       city: 'Mexico City'  },
  { lat:-33.87,  lon: 151.21,  country: 'Australia',    city: 'Sydney'       },
  { lat: 59.33,  lon:  18.07,  country: 'Sweden',       city: 'Stockholm'    },
  { lat: 37.57,  lon: 126.98,  country: 'South Korea',  city: 'Seoul'        },
  { lat: 55.68,  lon:  12.57,  country: 'Denmark',      city: 'Copenhagen'   },
  { lat: 24.47,  lon:  54.37,  country: 'UAE',          city: 'Abu Dhabi'    },
  { lat: 13.75,  lon: 100.52,  country: 'Thailand',     city: 'Bangkok'      },
];

const THREATS = [
  { type:'SQL_INJECTION',    sev:'CRITICAL', proto:'HTTP',  port:80,   payload:"' UNION SELECT * FROM users--" },
  { type:'DDoS_SYN_FLOOD',   sev:'CRITICAL', proto:'TCP',   port:443,  payload:'[SYN flood 120k pps]'          },
  { type:'C2_BEACON',        sev:'HIGH',     proto:'HTTPS', port:443,  payload:'GET /gate.php?id=infected_host' },
  { type:'BRUTE_FORCE_SSH',  sev:'HIGH',     proto:'TCP',   port:22,   payload:'Failed password for root'       },
  { type:'XSS_ATTACK',       sev:'HIGH',     proto:'HTTP',  port:80,   payload:"<script>document.location='evil.com'" },
  { type:'DATA_EXFILTRATION',sev:'CRITICAL', proto:'DNS',   port:53,   payload:'base64.gzip.tunnel.domain.xyz'  },
  { type:'RANSOMWARE_C2',    sev:'CRITICAL', proto:'TCP',   port:4444, payload:'POST /encrypt HTTP/1.1'         },
  { type:'PORT_SCAN',        sev:'MEDIUM',   proto:'TCP',   port:0,    payload:'[SYN probe masscan]'            },
  { type:'CRYPTO_MINER',     sev:'MEDIUM',   proto:'TCP',   port:3333, payload:'stratum+tcp mining.pool.connect'},
  { type:'TOR_EXIT_NODE',    sev:'MEDIUM',   proto:'TCP',   port:9001, payload:'[Tor circuit handshake]'        },
  { type:'BOT_TRAFFIC',      sev:'LOW',      proto:'HTTP',  port:8080, payload:'User-Agent: python-requests'    },
  { type:'SMTP_RELAY_ABUSE', sev:'LOW',      proto:'SMTP',  port:25,   payload:'RCPT TO: victim@domain.com'    },
];

const rand    = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick    = arr   => arr[Math.floor(Math.random() * arr.length)];
const randIp  = ()    => `${rand(1,220)}.${rand(1,254)}.${rand(1,254)}.${rand(1,254)}`;

function makeAlert() {
  const src    = pick(ATTACK_SOURCES);
  const threat = pick(THREATS);
  const action = ['CRITICAL','HIGH'].includes(threat.sev) ? 'BLOCKED'
               : threat.sev === 'MEDIUM' ? 'ALERTED' : 'LOGGED';
  return {
    id:              randomUUID(),
    timestamp:       Date.now(),
    severity:        threat.sev,
    threat_type:     threat.type,
    src_ip:          randIp(),
    dst_ip:         `10.0.0.${rand(1,10)}`,
    src_port:        rand(1024, 65535),
    dst_port:        threat.port || rand(1024, 65535),
    protocol:        threat.proto,
    payload_snippet: threat.payload,
    entropy_score:   +(Math.random() * 4 + 3.5).toFixed(2),
    action,
    geo: {
      lat: +(src.lat + (Math.random() - 0.5) * 0.8).toFixed(4),
      lon: +(src.lon + (Math.random() - 0.5) * 0.8).toFixed(4),
      country: src.country,
      city:    src.city,
    },
  };
}

function broadcast(msg) {
  const s = JSON.stringify(msg);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(s); });
}

function pushAlert(alert) {
  alerts.unshift(alert);
  if (alerts.length > MAX_ALERTS) alerts.pop();
  stats.alerts_total++;
  if (alert.action === 'BLOCKED') stats.blocked_total++;
  broadcast({ type: 'alert', data: alert });
}

// Shannon entropy over UTF-8 bytes
function computeEntropy(buf) {
  if (!buf.length) return 0;
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) freq[buf[i]]++;
  let H = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i]) {
      const p = freq[i] / buf.length;
      H -= p * Math.log2(p);
    }
  }
  return H;
}

function startJsSimulator() {
  let pps = 0;
  const next = () => {
    setTimeout(() => {
      pushAlert(makeAlert());
      pps += rand(1000, 15000);
      next();
    }, rand(300, 2000));
  };
  next();

  setInterval(() => {
    stats.packets_per_sec = pps;
    stats.flows_active    = rand(500, 4000);
    pps = 0;
    broadcast({ type:'stats', data:{ ...stats, uptime_s: Math.floor((Date.now() - stats.start_time)/1000) }});
  }, 1000);

  console.log('[NetSentry] JS simulator started');
}

function tryCppEngine() {
  const bin = path.join(__dirname, '..', 'cpp', 'build', 'netsentry');
  if (!fs.existsSync(bin)) return false;
  const proc = spawn(bin, ['--sim'], { stdio: ['ignore', 'pipe', 'inherit'] });
  let buf = '';
  proc.stdout.on('data', chunk => {
    buf += chunk.toString();
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.type === 'alert') pushAlert(msg);
        else if (msg.type === 'stats') {
          Object.assign(stats, msg);
          broadcast({ type:'stats', data:{ ...stats, uptime_s: Math.floor((Date.now() - stats.start_time)/1000) }});
        }
      } catch {}
    }
  });
  proc.on('exit', code => {
    console.log(`[NetSentry] C++ engine exited (${code}), falling back to JS`);
    startJsSimulator();
  });
  console.log('[NetSentry] C++ engine connected at', bin);
  return true;
}

wss.on('connection', ws => {
  console.log(`[WS] +1 client  total=${wss.clients.size}`);
  ws.send(JSON.stringify({ type:'init', data:{ alerts: alerts.slice(0, 50), stats }}));
  ws.on('close', () => console.log(`[WS] -1 client  total=${wss.clients.size}`));
  ws.on('error', e => console.error('[WS]', e.message));
});

app.get('/api/health', (_, res) => res.json({
  status: 'ok',
  uptime_s: Math.floor((Date.now() - stats.start_time) / 1000),
  clients: wss.clients.size,
  alerts_buffered: alerts.length,
}));

app.get('/api/alerts', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, MAX_ALERTS);
  res.json(alerts.slice(0, limit));
});

app.get('/api/stats', (_, res) => res.json({
  ...stats, uptime_s: Math.floor((Date.now() - stats.start_time) / 1000),
}));

// ─── Classification endpoint — accepts payload string OR raw bytes (b64) ──
app.post('/api/classify', (req, res) => {
  const { payload = '', src_ip = '1.2.3.4', dst_port = 80, raw_b64 } = req.body;

  // Determine bytes to analyze — prefer raw_b64 if provided (for true binary)
  let analyzeBuf;
  if (raw_b64) {
    try { analyzeBuf = Buffer.from(raw_b64, 'base64'); }
    catch { analyzeBuf = Buffer.from(payload, 'utf-8'); }
  } else {
    analyzeBuf = Buffer.from(payload, 'utf-8');
  }

  const entropy = computeEntropy(analyzeBuf);

  let threat_type = 'BENIGN', severity = 'LOW';
  const p = payload;

  if (/union\s+select|'\s*or\s+1\s*=\s*1|drop\s+table|insert\s+into/i.test(p)) {
    threat_type = 'SQL_INJECTION'; severity = 'CRITICAL';
  } else if (/<script|javascript:|onerror\s*=|<img[^>]+src\s*=\s*["']?javascript/i.test(p)) {
    threat_type = 'XSS_ATTACK'; severity = 'HIGH';
  } else if (/\/bin\/sh|cmd\.exe|exec\s*\(|system\s*\(|nc\s+-[el]|bash\s+-[ic]/i.test(p)) {
    threat_type = 'CMD_INJECTION'; severity = 'CRITICAL';
  } else if (/gate\.php|check-in|beacon|\/c2\/|cobaltstrike/i.test(p)) {
    threat_type = 'C2_BEACON'; severity = 'HIGH';
  } else if (p.toLowerCase().includes('base64') && p.length > 80) {
    threat_type = 'DATA_EXFILTRATION'; severity = 'HIGH';
  } else if (/nmap|masscan|nikto|sqlmap/i.test(p)) {
    threat_type = 'PORT_SCAN'; severity = 'MEDIUM';
  } else if (/stratum\+tcp|mining\.pool|xmr\.pool/i.test(p)) {
    threat_type = 'CRYPTO_MINER'; severity = 'MEDIUM';
  }

  // Entropy-based encrypted tunnel detection — lowered to 6.0 bits for text payloads
  // (real-world raw binary threshold would be 7.5; JSON-safe text caps around 6.5 bits)
  if (threat_type === 'BENIGN' && entropy > 6.0) {
    threat_type = 'ENCRYPTED_TUNNEL'; severity = 'HIGH';
  }

  const action = ['CRITICAL','HIGH'].includes(severity) ? 'BLOCK' : 'PASS';

  const result = {
    src_ip, threat_type, severity,
    entropy_score: +entropy.toFixed(2),
    action, dst_port, timestamp: Date.now(),
    matched_rules: threat_type !== 'BENIGN' ? [`rule:${threat_type.toLowerCase()}`] : [],
    byte_count: analyzeBuf.length,
  };

  if (threat_type !== 'BENIGN') {
    const a = {
      id: randomUUID(), ...result, src_port: 12345, dst_ip: '10.0.0.1',
      protocol: 'HTTP', payload_snippet: payload.slice(0, 64),
      action: action === 'BLOCK' ? 'BLOCKED' : 'LOGGED',
      geo: { lat: 0, lon: 0, country: 'Unknown', city: 'Classified' },
    };
    pushAlert(a);
  }
  res.json(result);
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`[NetSentry] API listening on :${PORT}`);
  if (!tryCppEngine()) startJsSimulator();
});
