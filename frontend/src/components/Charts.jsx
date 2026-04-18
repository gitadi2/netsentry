import { useMemo } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';

const PIE_COLORS = [
  '#ff1a44','#ff6500','#ffc800','#00c897','#00d4ff',
  '#9b6dff','#ff4488','#44aaff',
];

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background:'var(--bg-card)', border:'1px solid var(--border)',
      borderRadius:6, padding:'6px 10px', fontSize:11, fontFamily:'var(--font-mono)',
    }}>
      <span style={{ color:'var(--cyan)' }}>{payload[0].value}</span>
      <span style={{ color:'var(--text-3)', marginLeft:4 }}>alerts/s</span>
    </div>
  );
};

export default function Charts({ timelineData, alerts }) {
  // Threat type distribution (last 200 alerts)
  const threatDist = useMemo(() => {
    const c = {};
    alerts.slice(0, 200).forEach(a => {
      const k = a.threat_type.replace(/_/g,' ');
      c[k] = (c[k] || 0) + 1;
    });
    return Object.entries(c)
      .sort(([,a],[,b]) => b - a)
      .slice(0, 7)
      .map(([name, value]) => ({ name, value }));
  }, [alerts]);

  const maxV = Math.max(...timelineData.map(d => d.v), 1);

  return (
    <div className="charts-row">
      {/* Timeline */}
      <div className="card" style={{ padding:'10px 4px 6px 0' }}>
        <div style={{ padding:'0 14px 8px', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
          <span className="card-title">Alerts / Second</span>
          <span style={{ fontSize:10, color:'var(--text-3)' }}>last 60 s</span>
        </div>
        <ResponsiveContainer width="100%" height={120}>
          <AreaChart data={timelineData} margin={{ top:4, right:12, left:0, bottom:0 }}>
            <defs>
              <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}    />
              </linearGradient>
            </defs>
            <XAxis dataKey="t" hide />
            <YAxis
              domain={[0, maxV + 1]}
              tick={{ fontSize:10, fill:'#4a5a78' }}
              tickLine={false}
              axisLine={false}
              width={24}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="v"
              stroke="#00d4ff"
              strokeWidth={1.5}
              fill="url(#cyanGrad)"
              dot={false}
              activeDot={{ r:3, fill:'#00d4ff', strokeWidth:0 }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Donut */}
      <div className="card" style={{ padding:'10px 4px 6px' }}>
        <div style={{ padding:'0 14px 6px' }}>
          <span className="card-title">Threat Types</span>
        </div>
        {threatDist.length === 0 ? (
          <div style={{ textAlign:'center', color:'var(--text-3)', fontSize:11, padding:20 }}>
            No data yet…
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={130}>
            <PieChart>
              <Pie
                data={threatDist}
                cx="50%" cy="50%"
                innerRadius={32} outerRadius={54}
                dataKey="value"
                paddingAngle={2}
                isAnimationActive={false}
              >
                {threatDist.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                formatter={(v, n) => [v, n]}
                contentStyle={{
                  background:'var(--bg-card)', border:'1px solid var(--border)',
                  borderRadius:6, fontSize:10,
                }}
                labelStyle={{ display:'none' }}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
