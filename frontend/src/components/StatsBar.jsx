import { useState, useEffect } from 'react';

function fmt(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

export default function StatsBar({ stats, wsStatus }) {
  const [tick, setTick] = useState(0);

  // Blink on new data
  useEffect(() => { setTick(t => t + 1); }, [stats]);

  const statusLabel = wsStatus === 'connected'    ? 'LIVE'
                    : wsStatus === 'reconnecting'  ? 'RECONNECTING'
                    : 'OFFLINE';

  const statusClass = wsStatus === 'connected'   ? ''
                    : wsStatus === 'reconnecting' ? 'connecting'
                    : 'offline';

  return (
    <header className="header">
      <div className="logo">
        <span className="logo-hex">⬡</span>
        NETSENTRY
      </div>

      <div style={{ display:'flex', alignItems:'center', gap:6, marginLeft:8 }}>
        <div className={`status-dot ${statusClass}`} />
        <span className="status-label">{statusLabel}</span>
      </div>

      <div className="stats-row">
        <div className="stat-item">
          <span className="stat-label">Packets / s</span>
          <span className="stat-value">{fmt(stats.packets_per_sec || 0)}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Total Alerts</span>
          <span className="stat-value orange">{fmt(stats.alerts_total || 0)}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Blocked</span>
          <span className="stat-value red">{fmt(stats.blocked_total || 0)}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Active Flows</span>
          <span className="stat-value green">{fmt(stats.flows_active || 0)}</span>
        </div>
      </div>

      <div style={{ marginLeft:'auto', fontSize:11, color:'var(--text-3)', fontFamily:'var(--font-mono)' }}>
        uptime {stats.uptime_s ? `${Math.floor(stats.uptime_s/60)}m ${stats.uptime_s%60}s` : '—'}
      </div>
    </header>
  );
}
