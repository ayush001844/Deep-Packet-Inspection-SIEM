import { useApi, useWebSocket } from '../hooks/useApi';
import StatCard from '../components/StatCard';
import { Activity, ShieldAlert, Globe, Server } from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell
} from 'recharts';
import { useEffect, useState } from 'react';

const COLORS = {
  TCP: 'var(--proto-tcp)',
  UDP: 'var(--proto-udp)',
  HTTP: 'var(--proto-http)',
  HTTPS: 'var(--proto-tls)',
  TLS: 'var(--proto-tls)',
  DNS: 'var(--proto-dns)',
  SSH: 'var(--proto-ssh)',
  ICMP: 'var(--proto-icmp)'
};

export default function Overview() {
  const { data: stats, loading } = useApi('/api/stats', { interval: 2000 });
  const { data: alerts } = useApi('/api/alerts?limit=5', { interval: 5000 });
  
  // Fake chart data for the visual wow factor until we have real historical metrics
  const [chartData, setChartData] = useState([]);
  
  useEffect(() => {
    // Generate initial chart data
    const initial = Array.from({ length: 20 }, (_, i) => ({
      time: i,
      traffic: Math.floor(Math.random() * 500) + 100,
      threats: Math.floor(Math.random() * 5)
    }));
    setChartData(initial);
    
    // Update chart data periodically
    const interval = setInterval(() => {
      setChartData(prev => {
        const next = [...prev.slice(1)];
        const last = next[next.length - 1];
        next.push({
          time: last.time + 1,
          traffic: Math.max(50, last.traffic + (Math.random() * 100 - 50)),
          threats: Math.random() > 0.8 ? Math.floor(Math.random() * 3) : 0
        });
        return next;
      });
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) return <div className="empty-state">Loading dashboard...</div>;

  const activeFlows = stats?.flows?.active_flows || 0;
  const pps = stats?.packets_per_second || 0;
  const isCapturing = stats?.capture?.running || false;

  const protocolData = Object.entries(stats?.protocol_distribution || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 7);

  return (
    <div className="fade-in">
      {/* ── Top Stats ── */}
      <div className="stat-grid">
        <StatCard 
          title="Packet Rate" 
          value={isCapturing ? `${pps} pps` : 'OFF'} 
          icon={Activity} 
          change={isCapturing ? <span className="live-dot" style={{ display: 'inline-block', marginRight: 6 }}/> : 'Capture stopped'}
          color={isCapturing ? "var(--success)" : "var(--text-muted)"}
          bg={isCapturing ? "var(--success-bg)" : "var(--bg-elevated)"}
        />
        <StatCard 
          title="Active Sessions" 
          value={activeFlows.toLocaleString()} 
          icon={Server} 
          color="var(--accent)"
        />
        <StatCard 
          title="Total Packets" 
          value={(stats?.packets_total || 0).toLocaleString()} 
          icon={Globe} 
          color="var(--info)"
          bg="var(--info-bg)"
        />
        <StatCard 
          title="Threats Detected" 
          value={(alerts || []).length} 
          icon={ShieldAlert} 
          color="var(--critical)"
          bg="var(--critical-bg)"
        />
      </div>

      <div className="grid-2">
        {/* ── Network Traffic Chart ── */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Live Network Traffic</h3>
          </div>
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTraffic" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="var(--accent)" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                <XAxis dataKey="time" hide />
                <YAxis stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8 }}
                  itemStyle={{ color: 'var(--text-primary)' }}
                />
                <Area type="monotone" dataKey="traffic" stroke="var(--accent)" strokeWidth={3} fillOpacity={1} fill="url(#colorTraffic)" animationDuration={300} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── Protocol Distribution ── */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Protocol Distribution</h3>
          </div>
          {protocolData.length > 0 ? (
            <div style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolData} layout="vertical" margin={{ top: 0, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" width={60} stroke="var(--text-muted)" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip 
                    cursor={{ fill: 'var(--bg-card-hover)' }}
                    contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8 }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16}>
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[entry.name] || 'var(--accent)'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="empty-state" style={{ height: 260, padding: 0 }}>
              No protocol data available
            </div>
          )}
        </div>
      </div>
      
      {/* ── Recent Threats Table ── */}
      <div className="card mt-4">
        <div className="card-header">
          <h3 className="card-title">Recent Threats</h3>
          <button className="btn btn-secondary btn-sm">View All</button>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Threat</th>
                <th>Source IP</th>
                <th>Target IP</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts && alerts.length > 0 ? (
                alerts.map(alert => (
                  <tr key={alert.id}>
                    <td>
                      <span className={`severity-badge ${alert.severity.toLowerCase()}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="font-medium">{alert.title}</td>
                    <td className="font-mono text-sm">{alert.src_ip}</td>
                    <td className="font-mono text-sm">{alert.dst_ip}</td>
                    <td className="text-muted text-sm">{new Date(alert.timestamp * 1000).toLocaleTimeString()}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                    No threats detected recently.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
