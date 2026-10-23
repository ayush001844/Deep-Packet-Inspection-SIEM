import React, { useEffect, useState, useRef, useMemo } from 'react';
import { useApi } from '../hooks/useApi';
import StatCard from '../components/StatCard';
import GeoMap from '../components/GeoMap';
import { 
  Activity, ShieldAlert, Globe, Server, Zap, Radio, 
  Ban, HardDrive, Filter, Maximize2, RefreshCw, AlertTriangle
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell, Brush
} from 'recharts';
import { WS_BASE } from '../config';
import { SkeletonCard, SkeletonChart, SkeletonList } from '../components/Skeleton';
import { normalizeSeverity } from '../utils/severity';

const PROTO_COLORS = {
  TCP: 'var(--proto-tcp)',
  UDP: 'var(--proto-udp)',
  HTTP: 'var(--proto-http)',
  HTTPS: 'var(--proto-tls)',
  TLS: 'var(--proto-tls)',
  DNS: 'var(--proto-dns)',
  SSH: 'var(--proto-ssh)',
  ICMP: 'var(--proto-icmp)',
};

function formatThroughput(bytesPerSec) {
  if (!bytesPerSec || bytesPerSec === 0) return '0 B/s';
  if (bytesPerSec < 1024) return `${bytesPerSec.toFixed(0)} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

const MAX_HISTORY_POINTS = 120; // 4 minutes of 2s intervals

export default function Overview() {
  const { data: stats, loading, refetch: refetchStats } = useApi('/api/stats', { interval: 2000 });
  const { data: alertsData } = useApi('/api/alerts?limit=50', { interval: 3000 });
  const { data: graphData } = useApi('/api/network/graph', { interval: 5000 });
  const { data: blockedData } = useApi('/api/firewall/blocked', { interval: 6000 });

  // Live attack feed via WebSocket
  const [liveAlerts, setLiveAlerts] = useState([]);
  const wsRef = useRef(null);
  const feedListRef = useRef(null);

  // Chart view controls
  const [chartMetric, setChartMetric] = useState('traffic'); // 'traffic' (pps) | 'throughput' (KB/s) | 'threats'
  const [timeWindow, setTimeWindow] = useState('all'); // '30s', '1m', '5m', 'all'
  const [enableBrush, setEnableBrush] = useState(false);
  const [feedFilter, setFeedFilter] = useState('ALL');

  useEffect(() => {
    const ws = new WebSocket(`${WS_BASE}/ws/alerts`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const alert = JSON.parse(event.data);
        setLiveAlerts(prev => {
          const next = [alert, ...prev];
          return next.length > 60 ? next.slice(0, 60) : next;
        });
      } catch {}
    };

    ws.onclose = () => {
      setTimeout(() => {
        if (wsRef.current === ws) wsRef.current = null;
      }, 3000);
    };

    return () => ws.close();
  }, []);

  // Live time-series accumulator with real timestamps
  const [historyData, setHistoryData] = useState(() => {
    const now = Date.now();
    return Array.from({ length: 30 }, (_, i) => {
      const t = new Date(now - (30 - i) * 2000);
      return {
        timestamp: t.toLocaleTimeString(),
        rawTime: t.getTime(),
        traffic: 0,
        throughput: 0,
        threats: 0,
      };
    });
  });

  useEffect(() => {
    if (!stats) return;

    const now = new Date();
    const pps = stats.packets_per_second ?? 0;
    const bps = stats.bytes_per_second ?? 0;
    const throughputKb = parseFloat((bps / 1024).toFixed(2));
    const alertsList = Array.isArray(alertsData) ? alertsData : (alertsData?.alerts || []);
    const alertCount = alertsList.length;

    setHistoryData(prev => {
      const nextPoint = {
        timestamp: now.toLocaleTimeString(),
        rawTime: now.getTime(),
        traffic: pps,
        throughput: throughputKb,
        threats: alertCount,
      };
      const updated = [...prev, nextPoint];
      return updated.length > MAX_HISTORY_POINTS ? updated.slice(updated.length - MAX_HISTORY_POINTS) : updated;
    });
  }, [stats, alertsData]);

  // Windowed chart data based on selected time filter
  const displayChartData = useMemo(() => {
    if (timeWindow === 'all') return historyData;
    const countMap = { '30s': 15, '1m': 30, '5m': 75 };
    const count = countMap[timeWindow] || historyData.length;
    return historyData.slice(-count);
  }, [historyData, timeWindow]);

  // Derive metrics
  const activeFlows = stats?.flows?.active_flows || 0;
  const pps = stats?.packets_per_second || 0;
  const bps = stats?.bytes_per_second || 0;
  const isCapturing = stats?.capture?.running || false;
  
  const alertsList = Array.isArray(alertsData) ? alertsData : (alertsData?.alerts || []);
  const feedAlerts = liveAlerts.length > 0 ? liveAlerts : alertsList;
  const totalAlerts = feedAlerts.length;

  const blockedCount = stats?.blocked_count !== undefined 
    ? stats.blocked_count 
    : (blockedData?.blocked_ips?.length || 0);

  const totalBytesTransferred = stats?.flows?.total_bytes || 0;

  // Severity counts
  const criticalCount = feedAlerts.filter(a => {
    const s = String(a.severity || '').toLowerCase();
    return s.includes('crit') || s === '4';
  }).length;

  const highCount = feedAlerts.filter(a => {
    const s = String(a.severity || '').toLowerCase();
    return s.includes('high') || s === '3';
  }).length;

  // Protocol bar chart data
  const protocolData = Object.entries(stats?.protocol_distribution || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 7);

  const totalProtoPackets = protocolData.reduce((acc, p) => acc + p.value, 0) || 1;

  // Filtered attack feed
  const displayedFeed = useMemo(() => {
    if (feedFilter === 'ALL') return feedAlerts;
    if (feedFilter === 'CRITICAL') {
      return feedAlerts.filter(a => String(a.severity).toLowerCase().includes('crit'));
    }
    if (feedFilter === 'HIGH+') {
      return feedAlerts.filter(a => {
        const s = String(a.severity).toLowerCase();
        return s.includes('crit') || s.includes('high');
      });
    }
    return feedAlerts;
  }, [feedAlerts, feedFilter]);

  const mapNodes = graphData?.nodes || [];
  const mapLinks = graphData?.links || [];

  // Render Skeleton while initial stats load
  if (loading && !stats) {
    return (
      <div className="fade-in">
        <div className="stat-grid-5" style={{ marginBottom: 20 }}>
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
        <div className="soc-grid">
          <SkeletonChart height={420} />
          <div className="card">
            <SkeletonList items={6} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in">
      {/* ── 8. Redesigned Overview Dashboard: The 5 Core Metrics ── */}
      <div className="stat-grid-5">
        {/* 1. Packets */}
        <StatCard 
          title="Total Packets" 
          value={(stats?.packets_total || 0).toLocaleString()} 
          icon={Globe} 
          change={
            isCapturing ? (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: 'var(--success)' }}>
                <span className="live-dot" /> {pps} pps
              </span>
            ) : 'Stopped'
          }
          color="var(--info)"
          bg="var(--info-bg)"
        />

        {/* 2. Active Flows */}
        <StatCard 
          title="Active Flows" 
          value={activeFlows.toLocaleString()} 
          icon={Server} 
          change={`${stats?.flows?.tcp_flows || 0} TCP • ${stats?.flows?.udp_flows || 0} UDP`}
          color="var(--accent)"
        />

        {/* 3. Security Alerts */}
        <StatCard 
          title="Security Alerts" 
          value={totalAlerts} 
          icon={ShieldAlert} 
          change={
            criticalCount > 0 
              ? `${criticalCount} Critical • ${highCount} High`
              : totalAlerts > 0 ? `${totalAlerts} Monitored` : 'Zero Threat Hits'
          }
          color={criticalCount > 0 ? "var(--critical)" : totalAlerts > 0 ? "var(--high)" : "var(--success)"}
          bg={criticalCount > 0 ? "var(--critical-bg)" : totalAlerts > 0 ? "var(--high-bg)" : "var(--success-bg)"}
          className={criticalCount > 0 ? 'glow-critical' : totalAlerts > 0 ? 'glow-warning' : ''}
        />

        {/* 4. Network Throughput */}
        <StatCard 
          title="Throughput" 
          value={formatThroughput(bps)} 
          icon={HardDrive} 
          change={`Total: ${formatBytes(totalBytesTransferred)}`}
          color="var(--proto-tls)"
          bg="hsla(175, 70%, 45%, 0.12)"
        />

        {/* 5. Blocked Traffic */}
        <StatCard 
          title="Blocked Traffic" 
          value={blockedCount} 
          icon={Ban} 
          change={blockedCount > 0 ? 'Active Auto-Firewall' : 'Rules Standing By'}
          color={blockedCount > 0 ? "var(--critical)" : "var(--text-muted)"}
          bg={blockedCount > 0 ? "var(--critical-bg)" : "var(--bg-elevated)"}
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
            
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              {['ALL', 'CRITICAL', 'HIGH+'].map(f => (
                <button
                  key={f}
                  className={`btn-tag ${feedFilter === f ? 'active' : ''}`}
                  onClick={() => setFeedFilter(f)}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <div className="attack-feed-list" ref={feedListRef}>
            {displayedFeed.length > 0 ? (
              displayedFeed.map((alert, idx) => {
                const sevInfo = normalizeSeverity(alert.severity);
                const ts = alert.timestamp 
                  ? new Date(alert.timestamp * 1000).toLocaleTimeString()
                  : alert.created_at 
                    ? new Date(alert.created_at).toLocaleTimeString()
                    : new Date().toLocaleTimeString();

                return (
                  <div key={alert.id || idx} className={`attack-feed-item severity-${sevInfo.label.toLowerCase()}`}>
                    <span className="feed-time">{ts}</span>
                    <div className="feed-body">
                      <div className="feed-title">
                        <span 
                          className="severity-pill"
                          style={{
                            color: sevInfo.color,
                            backgroundColor: sevInfo.bg,
                            border: `1px solid ${sevInfo.border}`,
                          }}
                        >
                          {sevInfo.label}
                        </span>
                        <span>{alert.title || alert.signature || alert.message || 'Suspicious Traffic Event'}</span>
                      </div>
                      <div className="feed-meta">
                        <span className="feed-ip">{alert.src_ip || 'Internal'} ➔ {alert.dst_ip || 'Target'}</span>
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
                <p>No threat alerts matching current filter.</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── 9. Upgraded Interactive Traffic Charts & Protocol Distribution ── */}
      <div className="grid-2">
        {/* Interactive Network Traffic Chart */}
        <div className="card">
          <div className="card-header" style={{ flexWrap: 'wrap', gap: 12, alignItems: 'center' }}>
            <div>
              <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Zap size={16} color="var(--accent)" />
                Interactive Telemetry
              </h3>
              <span className="text-muted text-sm">Real-time sampling with timestamps and zooming</span>
            </div>

            {/* Time Window & Metric Filters */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
              {/* Metric Switcher */}
              <div className="btn-group-pill">
                <button 
                  className={`btn-pill ${chartMetric === 'traffic' ? 'active' : ''}`}
                  onClick={() => setChartMetric('traffic')}
                >
                  Packets (pps)
                </button>
                <button 
                  className={`btn-pill ${chartMetric === 'throughput' ? 'active' : ''}`}
                  onClick={() => setChartMetric('throughput')}
                >
                  Throughput (KB/s)
                </button>
                <button 
                  className={`btn-pill ${chartMetric === 'threats' ? 'active' : ''}`}
                  onClick={() => setChartMetric('threats')}
                >
                  Alerts
                </button>
              </div>

              {/* Time Window Filter */}
              <div className="btn-group-pill">
                {['30s', '1m', '5m', 'all'].map(tw => (
                  <button 
                    key={tw}
                    className={`btn-pill ${timeWindow === tw ? 'active' : ''}`}
                    onClick={() => setTimeWindow(tw)}
                  >
                    {tw.toUpperCase()}
                  </button>
                ))}
              </div>

              {/* Zoom / Brush Toggle */}
              <button 
                className={`btn-icon-toggle ${enableBrush ? 'active' : ''}`}
                onClick={() => setEnableBrush(prev => !prev)}
                title="Toggle Zoom & Range Slider"
              >
                <Maximize2 size={14} />
              </button>
            </div>
          </div>

          <div style={{ height: enableBrush ? 300 : 260, paddingBottom: 6 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={displayChartData} margin={{ top: 10, right: 15, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="metricGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop 
                      offset="5%" 
                      stopColor={
                        chartMetric === 'throughput' ? 'var(--proto-tls)' :
                        chartMetric === 'threats' ? 'var(--critical)' : 'var(--accent)'
                      } 
                      stopOpacity={0.4}
                    />
                    <stop 
                      offset="95%" 
                      stopColor={
                        chartMetric === 'throughput' ? 'var(--proto-tls)' :
                        chartMetric === 'threats' ? 'var(--critical)' : 'var(--accent)'
                      } 
                      stopOpacity={0.0}
                    />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                <XAxis 
                  dataKey="timestamp" 
                  stroke="var(--text-muted)" 
                  fontSize={11} 
                  tickLine={false} 
                  axisLine={false}
                  minTickGap={25}
                />
                <YAxis 
                  stroke="var(--text-muted)" 
                  fontSize={11} 
                  tickLine={false} 
                  axisLine={false} 
                  tickFormatter={v => `${v}`}
                />
                <Tooltip 
                  contentStyle={{ 
                    background: 'var(--bg-elevated)', 
                    border: '1px solid var(--border-default)', 
                    borderRadius: 8,
                    boxShadow: 'var(--shadow-md)',
                  }}
                  itemStyle={{ color: 'var(--text-primary)', fontSize: 13 }}
                  labelStyle={{ color: 'var(--text-secondary)', fontWeight: 600, marginBottom: 4 }}
                  formatter={(val, name) => {
                    if (chartMetric === 'throughput') return [`${val} KB/s`, 'Throughput'];
                    if (chartMetric === 'threats') return [`${val} events`, 'Threat Alerts'];
                    return [`${val} pps`, 'Packet Rate'];
                  }}
                />
                <Area 
                  type="monotone" 
                  dataKey={chartMetric} 
                  stroke={
                    chartMetric === 'throughput' ? 'var(--proto-tls)' :
                    chartMetric === 'threats' ? 'var(--critical)' : 'var(--accent)'
                  } 
                  strokeWidth={2.5} 
                  fillOpacity={1} 
                  fill="url(#metricGradient)" 
                  animationDuration={300} 
                  isAnimationActive={false} 
                />
                {enableBrush && (
                  <Brush 
                    dataKey="timestamp" 
                    height={26} 
                    stroke="var(--accent)" 
                    fill="var(--bg-card)"
                    travellerWidth={10}
                  />
                )}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution with Percentage shares */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Protocol Distribution</h3>
            <span className="text-muted text-sm">{protocolData.length} protocols detected</span>
          </div>
          {protocolData.length > 0 ? (
            <div style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={protocolData} layout="vertical" margin={{ top: 0, right: 30, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
                  <XAxis type="number" hide />
                  <YAxis 
                    dataKey="name" 
                    type="category" 
                    width={65} 
                    stroke="var(--text-muted)" 
                    fontSize={12} 
                    tickLine={false} 
                    axisLine={false} 
                  />
                  <Tooltip 
                    cursor={{ fill: 'var(--bg-card-hover)' }}
                    contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8 }}
                    formatter={(val) => {
                      const pct = ((val / totalProtoPackets) * 100).toFixed(1);
                      return [`${val.toLocaleString()} pkts (${pct}%)`, 'Volume'];
                    }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16}>
                    {protocolData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PROTO_COLORS[entry.name] || 'var(--accent)'} />
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
