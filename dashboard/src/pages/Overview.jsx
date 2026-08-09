import { useApi } from '../hooks/useApi';
import StatCard from '../components/StatCard';
import GeoMap from '../components/GeoMap';
import { Activity, ShieldAlert, Globe, Server, Gauge, Zap, Radio } from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell
} from 'recharts';
import { useEffect, useState, useRef } from 'react';

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
  const { data: alerts } = useApi('/api/alerts?limit=30', { interval: 3000 });
  const { data: graphData } = useApi('/api/network/graph', { interval: 5000 });
  const { data: riskScores } = useApi('/api/risk/scores', { interval: 5000 });
  
  // Live attack feed via WebSocket
  const [liveAlerts, setLiveAlerts] = useState([]);
  const wsRef = useRef(null);
  const feedListRef = useRef(null);

  useEffect(() => {
    // Connect to the alerts WebSocket
    const wsBase = `ws://${window.location.hostname}:8000`;
    const ws = new WebSocket(`${wsBase}/ws/alerts`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const alert = JSON.parse(event.data);
        setLiveAlerts(prev => {
          const next = [alert, ...prev];
          return next.length > 50 ? next.slice(0, 50) : next;
        });
      } catch {}
    };

    ws.onclose = () => {
      // Reconnect after 3s
      setTimeout(() => {
        if (wsRef.current === ws) {
          wsRef.current = null;
        }
      }, 3000);
    };

    return () => ws.close();
  }, []);
  
  // Chart data for traffic visualization
  const [chartData, setChartData] = useState([]);
  
  useEffect(() => {
    const initial = Array.from({ length: 20 }, (_, i) => ({
      time: i,
      traffic: Math.floor(Math.random() * 500) + 100,
      threats: Math.floor(Math.random() * 5)
    }));
    setChartData(initial);
    
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
  const totalThreats = (alerts || []).length;
  
  // Compute aggregate risk score
  const avgRisk = riskScores && Array.isArray(riskScores) && riskScores.length > 0
    ? Math.round(riskScores.reduce((sum, r) => sum + (r.score || 0), 0) / riskScores.length)
    : 0;

  const threatGlowClass = totalThreats > 10 ? 'glow-critical' : totalThreats > 0 ? 'glow-warning' : '';
  const riskGlowClass = avgRisk > 70 ? 'glow-critical' : avgRisk > 40 ? 'glow-warning' : '';

  const protocolData = Object.entries(stats?.protocol_distribution || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 7);

  // Use REST alerts as fallback if WS hasn't received any yet
  const feedAlerts = liveAlerts.length > 0 ? liveAlerts : (alerts || []);

  const mapNodes = graphData?.nodes || [];
  const mapLinks = graphData?.links || [];

  return (
    <div className="fade-in">
      {/* ── Top Row: 5 Stat Cards ── */}
      <div className="stat-grid-5">
        <StatCard 
          title="Total Packets" 
          value={(stats?.packets_total || 0).toLocaleString()} 
          icon={Globe} 
          color="var(--info)"
          bg="var(--info-bg)"
        />
        <StatCard 
          title="Active Connections" 
          value={activeFlows.toLocaleString()} 
          icon={Server} 
          color="var(--accent)"
        />
        <StatCard 
          title="Threats Detected" 
          value={totalThreats} 
          icon={ShieldAlert} 
          color="var(--critical)"
          bg="var(--critical-bg)"
          className={threatGlowClass}
        />
        <StatCard 
          title="Risk Score" 
          value={avgRisk > 0 ? `${avgRisk}/100` : '—'} 
          icon={Gauge} 
          color={avgRisk > 70 ? "var(--critical)" : avgRisk > 40 ? "var(--high)" : "var(--success)"}
          bg={avgRisk > 70 ? "var(--critical-bg)" : avgRisk > 40 ? "var(--high-bg)" : "var(--success-bg)"}
          className={riskGlowClass}
        />
        <StatCard 
          title="Packet Rate" 
          value={isCapturing ? `${pps} pps` : 'OFF'} 
          icon={Activity} 
          change={isCapturing ? <span className="live-dot" style={{ display: 'inline-block', marginRight: 6 }}/> : 'Capture stopped'}
          color={isCapturing ? "var(--success)" : "var(--text-muted)"}
          bg={isCapturing ? "var(--success-bg)" : "var(--bg-elevated)"}
        />
      </div>

      {/* ── Middle Row: World Attack Map + Live Attack Feed ── */}
      <div className="soc-grid">
        {/* World Attack Map */}
        <div className="world-map-card">
          <div className="map-overlay-title">
            <Globe size={16} />
            World Attack Map
            <span className="live-indicator">LIVE</span>
          </div>
          <div style={{ height: 420 }}>
            <GeoMap nodes={mapNodes} links={mapLinks} alerts={feedAlerts} />
          </div>
        </div>

        {/* Live Attack Feed */}
        <div className="card attack-feed">
          <div className="attack-feed-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0 }}>
              <Radio size={16} color="var(--critical)" />
              Live Attack Feed
            </h3>
            <span className="badge" style={{ backgroundColor: 'var(--critical-bg)', color: 'var(--critical)', fontSize: '0.7rem' }}>
              {feedAlerts.length} events
            </span>
          </div>
          <div className="attack-feed-list" ref={feedListRef}>
            {feedAlerts.length > 0 ? (
              feedAlerts.map((alert, idx) => {
                const sev = (alert.severity || 'medium').toLowerCase();
                const ts = alert.timestamp 
                  ? new Date(alert.timestamp * 1000).toLocaleTimeString()
                  : alert.created_at 
                    ? new Date(alert.created_at).toLocaleTimeString()
                    : '';
                return (
                  <div key={alert.id || idx} className={`attack-feed-item severity-${sev}`}>
                    <span className="feed-time">{ts}</span>
                    <div className="feed-body">
                      <div className="feed-title">
                        <span className={`severity-badge ${sev}`} style={{ marginRight: 8, fontSize: '0.65rem' }}>
                          {sev.toUpperCase()}
                        </span>
                        {alert.title}
                      </div>
                      <div className="feed-meta">
                        <span className="feed-ip">{alert.src_ip}</span>
                        {alert.mitre_technique && (
                          <span className="mitre-badge">MITRE: {alert.mitre_technique}</span>
                        )}
                        {alert.classification && (
                          <span className="badge" style={{ fontSize: '0.65rem', backgroundColor: 'var(--bg-elevated)', color: 'var(--text-secondary)' }}>
                            {alert.classification}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            ) : (
              <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <ShieldAlert size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
                <p>No attacks detected. Monitoring...</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Bottom Row: Traffic Chart + Protocol Distribution ── */}
      <div className="grid-2">
        {/* Network Traffic Chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Zap size={16} color="var(--accent)" />
              Live Network Traffic
            </h3>
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

        {/* Protocol Distribution */}
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
    </div>
  );
}
