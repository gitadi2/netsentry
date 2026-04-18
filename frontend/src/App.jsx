import { useState, useEffect, useRef, useCallback } from 'react';
import ThreatMap from './components/ThreatMap';
import AlertFeed from './components/AlertFeed';
import StatsBar  from './components/StatsBar';
import Charts    from './components/Charts';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:3001';

export default function App() {
  const [alerts,       setAlerts]       = useState([]);
  const [mapAlerts,    setMapAlerts]    = useState([]);
  const [stats,        setStats]        = useState({ packets_per_sec:0, alerts_total:0, blocked_total:0, flows_active:0 });
  const [wsStatus,     setWsStatus]     = useState('connecting');
  const [attackRate,   setAttackRate]   = useState(0);
  const [timelineData, setTimelineData] = useState(
    Array.from({ length: 60 }, (_, i) => ({ t: i, v: 0 }))
  );

  const wsRef          = useRef(null);
  const reconnectTimer = useRef(null);
  const alertCountRef  = useRef(0);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setWsStatus('connected');

      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data);
        if (msg.type === 'init') {
          setAlerts(msg.data.alerts || []);
          setMapAlerts((msg.data.alerts || []).slice(0, 20));
          if (msg.data.stats) setStats(msg.data.stats);
        } else if (msg.type === 'alert') {
          alertCountRef.current++;
          setAlerts(prev => [msg.data, ...prev].slice(0, 500));
          setMapAlerts(prev => [msg.data, ...prev].slice(0, 25));
        } else if (msg.type === 'stats') {
          setStats(msg.data);
        }
      };

      ws.onclose = () => {
        setWsStatus('reconnecting');
        reconnectTimer.current = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
    } catch {
      setWsStatus('reconnecting');
      reconnectTimer.current = setTimeout(connect, 3000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  useEffect(() => {
    const id = setInterval(() => {
      const v = alertCountRef.current;
      alertCountRef.current = 0;
      setAttackRate(v);
      setTimelineData(prev => [...prev.slice(1), { t: Date.now(), v }]);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="app">
      <StatsBar stats={stats} wsStatus={wsStatus} />
      <main className="main-grid">
        <div className="left-col">
          <ThreatMap alerts={mapAlerts} stats={stats} attackRate={attackRate} />
          <Charts timelineData={timelineData} alerts={alerts} />
        </div>
        <div className="right-col">
          <AlertFeed alerts={alerts} />
        </div>
      </main>
    </div>
  );
}
