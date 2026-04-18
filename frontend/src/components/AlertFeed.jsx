import { useMemo } from 'react';

function timeAgo(ts) {
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 5)  return 'just now';
  if (d < 60) return `${d}s ago`;
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  return `${Math.floor(d/3600)}h ago`;
}

function AlertItem({ alert }) {
  const time = timeAgo(alert.timestamp);
  return (
    <div className="alert-item">
      <div className="alert-top">
        <span className={`sev-badge sev-${alert.severity}`}>{alert.severity}</span>
        <span className="threat-name">{alert.threat_type.replace(/_/g,' ')}</span>
        <span className="alert-time">{time}</span>
      </div>

      <div className="alert-ips">
        {alert.src_ip}:{alert.src_port}
        <span style={{color:'var(--text-3)',margin:'0 4px'}}>→</span>
        {alert.dst_ip}:{alert.dst_port}
        <span style={{color:'var(--cyan-dim)',marginLeft:6,fontSize:10}}>{alert.protocol}</span>
      </div>

      <div className="alert-meta">
        <span className="alert-geo">
          {alert.geo?.country ? `${alert.geo.city}, ${alert.geo.country}` : '—'}
        </span>
        {alert.entropy_score && (
          <span style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-3)', marginLeft:6 }}>
            H={alert.entropy_score}
          </span>
        )}
        <span className={`action-badge action-${alert.action}`}>{alert.action}</span>
      </div>

      {alert.payload_snippet && (
        <div style={{
          marginTop:4, fontFamily:'var(--font-mono)', fontSize:10,
          color:'var(--text-3)', overflow:'hidden', textOverflow:'ellipsis',
          whiteSpace:'nowrap', maxWidth:'100%',
        }}>
          {alert.payload_snippet.slice(0,60)}
        </div>
      )}
    </div>
  );
}

export default function AlertFeed({ alerts }) {
  // Country attack count for mini-leaderboard
  const topCountries = useMemo(() => {
    const counts = {};
    alerts.slice(0, 200).forEach(a => {
      if (a.geo?.country) counts[a.geo.country] = (counts[a.geo.country] || 0) + 1;
    });
    return Object.entries(counts).sort(([,a],[,b]) => b-a).slice(0, 5);
  }, [alerts]);

  const max = topCountries[0]?.[1] || 1;

  return (
    <div className="card" style={{ flex:1, display:'flex', flexDirection:'column', minHeight:0 }}>
      <div className="card-header">
        <span className="card-title">Live Alerts</span>
        <span style={{ fontSize:11, color:'var(--text-3)', fontFamily:'var(--font-mono)' }}>
          {alerts.length} events
        </span>
      </div>

      {/* Top attackers mini-bar */}
      <div style={{ padding:'8px 14px', borderBottom:'1px solid var(--border)', background:'var(--bg-1)' }}>
        <div style={{ fontSize:10, color:'var(--text-3)', marginBottom:5, textTransform:'uppercase', letterSpacing:'0.05em' }}>
          Top Attack Origins
        </div>
        {topCountries.map(([country, count]) => (
          <div key={country} style={{ display:'flex', alignItems:'center', gap:6, marginBottom:3 }}>
            <span style={{ fontSize:11, color:'var(--text-2)', width:100, flexShrink:0, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
              {country}
            </span>
            <div style={{ flex:1, height:4, background:'var(--border)', borderRadius:2, overflow:'hidden' }}>
              <div style={{
                height:'100%', borderRadius:2,
                width: `${(count/max)*100}%`,
                background:'linear-gradient(90deg,var(--cyan-dim),var(--cyan))',
                transition:'width 0.5s ease',
              }} />
            </div>
            <span style={{ fontSize:10, fontFamily:'var(--font-mono)', color:'var(--text-3)', width:24, textAlign:'right' }}>
              {count}
            </span>
          </div>
        ))}
      </div>

      <div className="alert-list">
        {alerts.length === 0 && (
          <div style={{ padding:'24px', textAlign:'center', color:'var(--text-3)', fontSize:12 }}>
            Waiting for alerts…
          </div>
        )}
        {alerts.map(a => <AlertItem key={a.id} alert={a} />)}
      </div>
    </div>
  );
}
