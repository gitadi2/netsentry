import { useEffect, useRef, useState, useMemo } from 'react';
import { MapContainer, TileLayer, useMap } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

const SERVER_LOC = [37.7749, -122.4194];

const SEV_COLOR = {
  CRITICAL: '#ff1a44',
  HIGH:     '#ff6500',
  MEDIUM:   '#ffc800',
  LOW:      '#00c897',
};

// ─── Icons ───────────────────────────────────────────────────────────────
function pulseIcon(severity) {
  const c = SEV_COLOR[severity] || '#ff6500';
  return L.divIcon({
    className: '',
    html: `<div class="pulse-dot" style="--c:${c}"></div>`,
    iconSize:   [20, 20],
    iconAnchor: [10, 10],
    popupAnchor: [0, -10],
  });
}

const radarIcon = L.divIcon({
  className: '',
  html: `
    <div class="radar-pulse">
      <div class="radar-sweep"></div>
      <div class="radar-ring"></div>
      <div class="radar-ring" style="animation-delay:1s"></div>
      <div class="radar-ring" style="animation-delay:2s"></div>
      <div class="server-core"></div>
      <div class="server-label">⬡ PROTECTED NODE</div>
    </div>
  `,
  iconSize:    [180, 180],
  iconAnchor:  [90, 90],
  popupAnchor: [0, -20],
});

// ─── Attack layer — manages markers + arcs ─────────────────────────────
function AttackLayer({ alerts }) {
  const map    = useMap();
  const layers = useRef({});
  const prev   = useRef([]);

  useEffect(() => {
    if (!alerts?.length) return;
    const prevIds   = new Set(prev.current.map(a => a.id));
    const newAlerts = alerts.filter(a => !prevIds.has(a.id));
    prev.current    = alerts;

    newAlerts.forEach(alert => {
      if (layers.current[alert.id]) return;
      const geo = alert.geo;
      if (!geo?.lat || !geo?.lon) return;

      const srcLL = [geo.lat, geo.lon];
      const color = SEV_COLOR[alert.severity] || '#ff6500';

      const marker = L.marker(srcLL, { icon: pulseIcon(alert.severity) })
        .addTo(map)
        .bindPopup(`
          <div style="font-family:monospace;font-size:12px;min-width:200px;line-height:1.7">
            <div style="color:${color};font-weight:600;font-size:13px;margin-bottom:4px;letter-spacing:.05em">
              ${alert.threat_type}
            </div>
            <div style="color:#4a5a78;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin:6px 0 4px">Origin</div>
            <div style="color:#e8edf5">${geo.city}, ${geo.country}</div>
            <div style="color:#4a5a78;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin:6px 0 4px">Flow</div>
            <div style="color:#8a9ab8">${alert.src_ip}:${alert.src_port}</div>
            <div style="color:#8a9ab8">→ ${alert.dst_ip}:${alert.dst_port} <span style="color:#00d4ff">${alert.protocol}</span></div>
            <div style="color:#4a5a78;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin:6px 0 4px">Entropy</div>
            <div style="color:#00d4ff">${alert.entropy_score} bits</div>
            <div style="margin-top:8px;padding-top:8px;border-top:1px solid #1f2a42;font-weight:600;color:${alert.action==='BLOCKED'?'#ff1a44':'#ffc800'}">
              ▸ ${alert.action}
            </div>
          </div>
        `, { maxWidth: 260 });

      const arc = L.polyline([srcLL, SERVER_LOC], {
        color,
        weight:    1.6,
        opacity:   0.85,
        dashArray: '8 5',
        className: `arc-${alert.severity.toLowerCase()}`,
      }).addTo(map);

      layers.current[alert.id] = { marker, arc };
      setTimeout(() => {
        try { map.removeLayer(marker); } catch {}
        try { map.removeLayer(arc);    } catch {}
        delete layers.current[alert.id];
      }, 9000);
    });
  }, [alerts, map]);

  return null;
}

function ServerMarker() {
  const map = useMap();
  useEffect(() => {
    const m = L.marker(SERVER_LOC, { icon: radarIcon, zIndexOffset: 1000 }).addTo(map);
    return () => { try { map.removeLayer(m); } catch {} };
  }, [map]);
  return null;
}

// ─── Severity filter ──────────────────────────────────────────────────
function SeverityFilter({ filter, setFilter }) {
  return (
    <div className="sev-filter">
      {Object.entries(SEV_COLOR).map(([sev, color]) => (
        <button
          key={sev}
          className={`sev-chip ${filter[sev] ? 'active' : ''}`}
          style={{ '--sev-color': color }}
          onClick={() => setFilter(f => ({ ...f, [sev]: !f[sev] }))}
        >
          <span className="sev-chip-dot" />
          {sev.charAt(0) + sev.slice(1).toLowerCase()}
        </button>
      ))}
    </div>
  );
}

function fmtNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

// ─── Main export ─────────────────────────────────────────────────────
export default function ThreatMap({ alerts, stats, attackRate }) {
  const [filter, setFilter] = useState({
    CRITICAL: true, HIGH: true, MEDIUM: true, LOW: true,
  });

  const filteredAlerts = useMemo(
    () => alerts.filter(a => filter[a.severity]),
    [alerts, filter]
  );

  // Critical attacks in last 60s
  const criticalRecent = useMemo(() => {
    const cutoff = Date.now() - 60000;
    return alerts.filter(a => a.timestamp > cutoff && a.severity === 'CRITICAL').length;
  }, [alerts]);

  return (
    <div className="card map-card">
      <div className="card-header">
        <span className="card-title">Live Threat Map</span>
        <SeverityFilter filter={filter} setFilter={setFilter} />
      </div>

      <div className="map-wrap">
        <MapContainer
          center={[25, 0]}
          zoom={2}
          minZoom={2}
          maxZoom={7}
          maxBounds={[[-85, -180], [85, 180]]}
          maxBoundsViscosity={1.0}
          worldCopyJump={false}
          zoomControl={true}
          style={{ width: '100%', height: '100%' }}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png"
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>'
            subdomains="abcd"
            maxZoom={19}
            noWrap={true}
          />
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_only_labels/{z}/{x}/{y}{r}.png"
            subdomains="abcd"
            maxZoom={19}
            noWrap={true}
            pane="overlayPane"
          />
          <ServerMarker />
          <AttackLayer alerts={filteredAlerts} />
        </MapContainer>

        {/* Top-left: Total blocked counter */}
        <div className="map-overlay map-overlay-tl">
          <div className="overlay-label">Threats Blocked</div>
          <div className="overlay-value red">{fmtNum(stats.blocked_total || 0)}</div>
          <div className="overlay-sub">
            {criticalRecent} critical · last 60s
          </div>
        </div>

        {/* Top-right: Attack rate */}
        <div className="map-overlay map-overlay-tr">
          <div className="overlay-label">⚡ Attack Rate</div>
          <div className="overlay-value">{attackRate}<span style={{fontSize:13,color:'var(--text-3)'}}>/s</span></div>
          <div className="overlay-sub">
            {stats.flows_active || 0} flows tracked
          </div>
        </div>

        {/* Bottom-left: System status */}
        <div className="map-overlay map-overlay-bl">
          <div className="overlay-label">DPI Engine</div>
          <div className="overlay-value green" style={{fontSize:14}}>● ONLINE</div>
          <div className="overlay-sub">
            {fmtNum(stats.packets_per_sec || 0)} pkt/s
          </div>
        </div>
      </div>
    </div>
  );
}
