import React, { useState, useEffect, useMemo } from 'react';
import { useApi } from '../hooks/useApi';
import { 
  Pause, Play, AlertTriangle, Printer, Maximize2, 
  ChevronDown, Filter, Zap, Globe, HardDrive, Radio, ShieldAlert
} from 'lucide-react';
import { 
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, 
  AreaChart, Area, LineChart, Line, XAxis, YAxis, CartesianGrid
} from 'recharts';
import SankeyFlow from '../components/SankeyFlow';
import RadialClock from '../components/RadialClock';
import AlgorithmAlertsBar from '../components/AlgorithmAlertsBar';

// ── EU Destination Country Data & Colors ──
const EU_COUNTRIES = [
  { code: 'DE', name: 'Germany', value: 24, color: '#f97316' },
  { code: 'FR', name: 'France', value: 18, color: '#fb923c' },
  { code: 'NL', name: 'Netherlands', value: 16, color: '#facc15' },
  { code: 'GB', name: 'United Kingdom', value: 12, color: '#38bdf8' },
  { code: 'IT', name: 'Italy', value: 9, color: '#c084fc' },
  { code: 'RU', name: 'Russia', value: 7, color: '#f43f5e' },
  { code: 'BG', name: 'Bulgaria', value: 5, color: '#60a5fa' },
  { code: 'ES', name: 'Spain', value: 4, color: '#ea580c' },
  { code: 'RO', name: 'Romania', value: 3, color: '#a855f7' },
  { code: 'PL', name: 'Poland', value: 2, color: '#ec4899' },
];

// ── APAC Destination Country Data & Colors ──
const APAC_COUNTRIES = [
  { code: 'KR', name: 'South Korea', value: 68, color: '#38bdf8' },
  { code: 'SG', name: 'Singapore', value: 8, color: '#f87171' },
  { code: 'CN', name: 'China', value: 6, color: '#ef4444' },
  { code: 'JP', name: 'Japan', value: 5, color: '#f1f5f9' },
  { code: 'IN', name: 'India', value: 4, color: '#fb923c' },
  { code: 'ID', name: 'Indonesia', value: 3, color: '#34d399' },
  { code: 'VN', name: 'Vietnam', value: 2, color: '#facc15' },
  { code: 'TR', name: 'Turkey', value: 2, color: '#fb7185' },
  { code: 'TW', name: 'Taiwan', value: 1, color: '#60a5fa' },
  { code: 'BD', name: 'Bangladesh', value: 1, color: '#2dd4bf' },
];

export default function Overview() {
  const [isPaused, setIsPaused] = useState(false);
  const [selectedDashboard, setSelectedDashboard] = useState('threat-telemetry');
  
  // Real API integration
  const { data: stats } = useApi('/api/stats', { interval: isPaused ? 0 : 2000 });
  const { data: flowsData } = useApi('/api/sessions?limit=50', { interval: isPaused ? 0 : 3000 });
  const { data: alertsData } = useApi('/api/alerts?limit=50', { interval: isPaused ? 0 : 3000 });

  const activeFlows = flowsData?.sessions || [];
  const rawAlerts = Array.isArray(alertsData) ? alertsData : (alertsData?.alerts || []);

  // ── Oscilloscope Waveform Time-Series Data (Bitrate & Packet Rate) ──
  const waveformData = useMemo(() => {
    const times = ['12:00', '12:30', '13:00', '13:30', '14:00', '14:30', '15:00'];
    const pts = [];
    const pointsCount = 42;

    for (let i = 0; i < pointsCount; i++) {
      const tIdx = Math.floor((i / pointsCount) * times.length);
      const timeLabel = times[Math.min(tIdx, times.length - 1)];
      
      // Simulating high-frequency telemetry spikes
      const baseBitrate = 14 + Math.sin(i * 0.8) * 8 + (i > 22 && i < 30 ? 14 : 0);
      const jitterBit = Math.floor((Math.sin(i * 3.7) * 6) + (Math.cos(i * 1.9) * 4));
      const bitrate = Math.max(2, Math.min(38, baseBitrate + jitterBit));

      const basePps = 11 + Math.cos(i * 0.9) * 5 + (i > 24 && i < 32 ? 10 : 0);
      const jitterPps = Math.floor((Math.cos(i * 4.2) * 4) + (Math.sin(i * 2.1) * 3));
      const packets = Math.max(1, Math.min(28, basePps + jitterPps));

      pts.push({
        time: timeLabel,
        index: i,
        bitrate,
        packets,
      });
    }
    return pts;
  }, []);

  // ── Multi-Site Telemetry Data (Sites / Sensor Gateways) ──
  const siteTelemetryData = useMemo(() => {
    const hours = ['11:30', '12:00', '12:30', '13:00', '13:30', '14:00', '14:30', '15:00'];
    return hours.map((h, i) => {
      const isSpike = h === '13:30' || h === '14:00';
      return {
        time: h,
        'us-east-1': isSpike ? 28 : (4 + Math.sin(i) * 2),
        'Suncoast-Tampa': isSpike ? 34 : (2 + Math.cos(i) * 1.5),
        'Suncoast-Chicago': isSpike ? 18 : 1,
        'LumenPreScrub': isSpike ? 22 : 1.5,
        'LumenPostScrub': isSpike ? 8 : 0.5,
        'Suncoast-LasVegas': 1,
        'eastus': isSpike ? 12 : 1,
        'us-west4': 0.8,
      };
    });
  }, []);

  // ── Source Country Flow Volume Data ──
  const countryVolumeData = useMemo(() => {
    const hours = ['11:30', '12:00', '12:30', '13:00', '13:30', '14:00', '14:30', '15:00'];
    return hours.map((h) => {
      const isPeak = h === '13:30' || h === '14:00';
      return {
        time: h,
        US: isPeak ? 38 : 3,
        Unknown: isPeak ? 22 : 2,
        CN: isPeak ? 14 : 1,
        JP: isPeak ? 9 : 0.5,
        DE: isPeak ? 7 : 0.4,
      };
    });
  }, []);

  // ── Source IP Cardinality Data ──
  const cardinalityData = useMemo(() => {
    return [
      { time: '11:43', val: 13.2 },
      { time: '12:15', val: 13.5 },
      { time: '12:45', val: 13.8 },
      { time: '13:15', val: 14.1 },
      { time: '13:45', val: 14.8 },
      { time: '14:15', val: 14.6 },
      { time: '14:45', val: 14.3 },
      { time: '15:15', val: 14.0 },
      { time: '15:43', val: 13.9 },
    ];
  }, []);

  const handlePrint = () => {
    window.print();
  };

  const handleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  return (
    <div style={{ backgroundColor: '#0b0f17', minHeight: '100%', color: '#e2e8f0', padding: '14px 18px' }}>
      
      {/* ── Sub-Header Bar (Matching Netography Top Controls) ── */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingBottom: 14,
        marginBottom: 16,
        borderBottom: '1px solid #1a2230',
        flexWrap: 'wrap',
        gap: 12
      }}>
        {/* Left: Home & Dashboard Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          <h1 style={{ fontSize: 18, fontWeight: 700, margin: 0, color: '#ffffff', letterSpacing: '-0.3px' }}>
            Home
          </h1>
          <div style={{ position: 'relative' }}>
            <select
              value={selectedDashboard}
              onChange={e => setSelectedDashboard(e.target.value)}
              style={{
                background: '#161e2a',
                border: '1px solid #243042',
                color: '#cbd5e1',
                borderRadius: 4,
                padding: '6px 30px 6px 12px',
                fontSize: 12,
                cursor: 'pointer',
                appearance: 'none',
                outline: 'none',
              }}
            >
              <option value="threat-telemetry">Security & Threat Telemetry</option>
              <option value="traffic-flows">Traffic Flows & Deep Inspection</option>
              <option value="executive-soc">Executive SOC Overview</option>
            </select>
            <ChevronDown size={14} color="#94a3b8" style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
          </div>
        </div>

        {/* Right Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {/* Pause / Live stream toggle button */}
          <button
            onClick={() => setIsPaused(p => !p)}
            title={isPaused ? "Resume Live Feed" : "Pause Live Feed"}
            style={{
              width: 32,
              height: 32,
              borderRadius: '50%',
              background: '#161e2a',
              border: `1px solid ${isPaused ? '#f59e0b' : '#38bdf8'}`,
              color: isPaused ? '#f59e0b' : '#38bdf8',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
          </button>

          {/* Time range selector badge */}
          <div style={{
            background: '#161e2a',
            border: '1px solid #243042',
            borderRadius: 4,
            padding: '5px 12px',
            fontSize: 11,
            color: '#cbd5e1',
            fontFamily: 'JetBrains Mono, monospace',
            display: 'flex',
            alignItems: 'center',
            gap: 6
          }}>
            <span>2026-10-23 11:43 —</span>
            <span style={{ color: isPaused ? '#f59e0b' : '#22c55e', fontWeight: 700 }}>
              {isPaused ? 'PAUSED' : 'REALTIME*'}
            </span>
            <ChevronDown size={12} color="#64748b" />
          </div>

          {/* User Badge */}
          <div style={{
            width: 28,
            height: 28,
            borderRadius: '50%',
            background: '#10b981',
            color: '#064e3b',
            fontWeight: 800,
            fontSize: 11,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            BN
          </div>

          {/* Fullscreen Expand */}
          <button 
            onClick={handleFullscreen}
            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 4 }}
            title="Toggle Fullscreen"
          >
            <Maximize2 size={16} />
          </button>

          {/* Red Alert Indicator */}
          <div 
            title={`${rawAlerts.length} Security Threats Active`}
            style={{
              background: '#ef4444',
              color: '#ffffff',
              width: 28,
              height: 28,
              borderRadius: 4,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer'
            }}
          >
            <AlertTriangle size={16} />
          </div>

          {/* Print / Export Report */}
          <button 
            onClick={handlePrint}
            style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 4 }}
            title="Print / Save Report"
          >
            <Printer size={16} />
          </button>
        </div>
      </div>

      {/* ── ROW 1: Alerts by Algorithm (Top 20) ── */}
      <AlgorithmAlertsBar liveAlerts={rawAlerts} />

      {/* ── ROW 2: 3-Panel Distribution (EU DST, Inside->Out Sankey, APAC DST) ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1.35fr 1fr',
        gap: 16,
        marginBottom: 16
      }}>
        {/* Panel 1: EU DST */}
        <div className="card" style={{ padding: '16px 18px', background: '#131922', border: '1px solid #1e2634' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span style={{ fontSize: 10, color: '#38bdf8' }}>▼</span>
            <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: '#f1f5f9' }}>EU DST</h3>
          </div>
          <div style={{ fontSize: 10, color: '#64748b', marginBottom: 10, fontFamily: 'monospace' }}>
            Total Traffic by dstgeo.countrycode (top 10)
          </div>

          {/* Legend dots */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 10px', fontSize: 10, marginBottom: 12 }}>
            {EU_COUNTRIES.map(c => (
              <div key={c.code} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 8, height: 3, background: c.color, borderRadius: 1 }} />
                <span style={{ color: '#cbd5e1' }}>{c.code}</span>
              </div>
            ))}
          </div>

          {/* Pie / Donut Chart */}
          <div style={{ height: 210 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={EU_COUNTRIES}
                  cx="50%"
                  cy="50%"
                  outerRadius={88}
                  innerRadius={30}
                  dataKey="value"
                  stroke="#131922"
                  strokeWidth={2}
                >
                  {EU_COUNTRIES.map((entry, index) => (
                    <Cell key={`eu-cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 4, fontSize: 11 }}
                  formatter={(val, name, props) => [`${val}% traffic`, props.payload.name]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Panel 2: Inside ➔ Out Flow Visualizer */}
        <div className="card" style={{ padding: '16px 18px', background: '#131922', border: '1px solid #1e2634' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span style={{ fontSize: 10, color: '#38bdf8' }}>▼</span>
            <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: '#f1f5f9' }}>Inside ➔ Out</h3>
          </div>
          <div style={{ fontSize: 10, color: '#64748b', marginBottom: 6, fontFamily: 'monospace' }}>
            srcip ➔ dstip (top 10)
          </div>

          {/* Sankey Flow Ribbons */}
          <SankeyFlow flows={activeFlows} />
        </div>

        {/* Panel 3: APAC DST */}
        <div className="card" style={{ padding: '16px 18px', background: '#131922', border: '1px solid #1e2634' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span style={{ fontSize: 10, color: '#38bdf8' }}>▼</span>
            <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: '#f1f5f9' }}>APAC DST</h3>
          </div>
          <div style={{ fontSize: 10, color: '#64748b', marginBottom: 10, fontFamily: 'monospace' }}>
            Total Traffic by dstgeo.countrycode (top 10)
          </div>

          {/* Legend dots */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 10px', fontSize: 10, marginBottom: 12 }}>
            {APAC_COUNTRIES.map(c => (
              <div key={c.code} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 8, height: 3, background: c.color, borderRadius: 1 }} />
                <span style={{ color: '#cbd5e1' }}>{c.code}</span>
              </div>
            ))}
          </div>

          {/* Pie Chart with Dominant Cyan wedge */}
          <div style={{ height: 210 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={APAC_COUNTRIES}
                  cx="50%"
                  cy="50%"
                  outerRadius={88}
                  innerRadius={0}
                  dataKey="value"
                  stroke="#131922"
                  strokeWidth={2}
                >
                  {APAC_COUNTRIES.map((entry, index) => (
                    <Cell key={`apac-cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 4, fontSize: 11 }}
                  formatter={(val, name, props) => [`${val}% traffic`, props.payload.name]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── ROW 3: Telemetry Grid (Bitrate, Radial Clock, Gateways & Country) ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr 1fr',
        gap: 16
      }}>
        {/* Left Column: Bitrate & Packets Rate Waveforms */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Card 1: Bitrate */}
          <div className="card" style={{ padding: '14px 16px', background: '#131922', border: '1px solid #1e2634' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9' }}>Bitrate</span>
              <span style={{ fontSize: 10, color: '#f59e0b', fontFamily: 'monospace' }}>
                {(stats?.bytes_per_second ? (stats.bytes_per_second * 8 / 1000000).toFixed(1) : '24.2')} Mbps
              </span>
            </div>

            <div style={{ height: 110 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={waveformData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid stroke="#1e2634" strokeDasharray="2 2" vertical={false} />
                  <XAxis dataKey="time" stroke="#475569" fontSize={9} tickLine={false} axisLine={false} />
                  <YAxis stroke="#475569" fontSize={9} tickLine={false} axisLine={false} domain={[0, 45]} ticks={[0, 10, 20, 30, 40]} unit="M" />
                  <Line 
                    type="monotone" 
                    dataKey="bitrate" 
                    stroke="#f59e0b" 
                    strokeWidth={1.2} 
                    dot={false}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Card 2: Packets Rate */}
          <div className="card" style={{ padding: '14px 16px', background: '#131922', border: '1px solid #1e2634' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9' }}>Packets Rate</span>
              <span style={{ fontSize: 10, color: '#f97316', fontFamily: 'monospace' }}>
                {stats?.packets_per_second ?? '18'} Mpps
              </span>
            </div>

            <div style={{ height: 110 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={waveformData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="ppsFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f97316" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#f97316" stopOpacity={0.05}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e2634" strokeDasharray="2 2" vertical={false} />
                  <XAxis dataKey="time" stroke="#475569" fontSize={9} tickLine={false} axisLine={false} />
                  <YAxis stroke="#475569" fontSize={9} tickLine={false} axisLine={false} domain={[0, 35]} ticks={[0, 10, 20, 30]} unit="M" />
                  <Area 
                    type="monotone" 
                    dataKey="packets" 
                    stroke="#ea580c" 
                    strokeWidth={1.2} 
                    fill="url(#ppsFill)" 
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Center Column: Radial Clock & Source IP Cardinality */}
        <div className="card" style={{ padding: '14px 16px', background: '#131922', border: '1px solid #1e2634', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          {/* Radial Concentric Clock */}
          <RadialClock />

          {/* Source IP Cardinality */}
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid #1c2432' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#f1f5f9' }}>Source IP Cardinality</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontFamily: 'monospace' }}>14.2 k unique IPs</span>
            </div>
            <div style={{ height: 45 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={cardinalityData} margin={{ top: 4, right: 5, left: -30, bottom: 0 }}>
                  <YAxis domain={[12, 16]} stroke="#475569" fontSize={8} tickLine={false} axisLine={false} ticks={[13, 15]} unit="k" />
                  <Line type="monotone" dataKey="val" stroke="#38bdf8" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Right Column: Site Gateways & Source Country */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Card 1: Site Gateways */}
          <div className="card" style={{ padding: '14px 16px', background: '#131922', border: '1px solid #1e2634' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9' }}>Site</span>
              <span style={{ fontSize: 9, color: '#64748b' }}>Peak: 75 Gbps</span>
            </div>

            <div style={{ height: 100 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={siteTelemetryData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid stroke="#1e2634" strokeDasharray="2 2" vertical={false} />
                  <XAxis dataKey="time" stroke="#475569" fontSize={8} tickLine={false} axisLine={false} />
                  <YAxis stroke="#475569" fontSize={8} tickLine={false} axisLine={false} domain={[0, 80]} ticks={[0, 25, 50, 75]} unit="G" />
                  <Line type="monotone" dataKey="us-east-1" stroke="#3b82f6" strokeWidth={1.2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="Suncoast-Tampa" stroke="#38bdf8" strokeWidth={1.2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="Suncoast-Chicago" stroke="#fbbf24" strokeWidth={1} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="LumenPreScrub" stroke="#f59e0b" strokeWidth={1} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="eastus" stroke="#2dd4bf" strokeWidth={1} dot={false} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Micro legend */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px 8px', fontSize: 8, marginTop: 4, color: '#94a3b8' }}>
              <span style={{ color: '#3b82f6' }}>— us-east-1</span>
              <span style={{ color: '#38bdf8' }}>— Suncoast-Tampa</span>
              <span style={{ color: '#fbbf24' }}>— Suncoast-Chicago</span>
              <span style={{ color: '#f59e0b' }}>— LumenPreScrub</span>
            </div>
          </div>

          {/* Card 2: Source Country */}
          <div className="card" style={{ padding: '14px 16px', background: '#131922', border: '1px solid #1e2634' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9' }}>Source Country</span>
              <span style={{ fontSize: 9, color: '#64748b' }}>Scale: 75 Gbps</span>
            </div>

            <div style={{ height: 100 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={countryVolumeData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
                  <CartesianGrid stroke="#1e2634" strokeDasharray="2 2" vertical={false} />
                  <XAxis dataKey="time" stroke="#475569" fontSize={8} tickLine={false} axisLine={false} />
                  <YAxis stroke="#475569" fontSize={8} tickLine={false} axisLine={false} domain={[0, 80]} ticks={[0, 25, 50, 75]} unit="G" />
                  <Line type="monotone" dataKey="US" stroke="#3b82f6" strokeWidth={1.5} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="Unknown" stroke="#38bdf8" strokeWidth={1.2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="CN" stroke="#ef4444" strokeWidth={1.2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="JP" stroke="#f8fafc" strokeWidth={1} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="DE" stroke="#f59e0b" strokeWidth={1} dot={false} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* Micro legend */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px 8px', fontSize: 8, marginTop: 4, color: '#94a3b8' }}>
              <span style={{ color: '#3b82f6' }}>— US</span>
              <span style={{ color: '#38bdf8' }}>— Unknown</span>
              <span style={{ color: '#ef4444' }}>— CN</span>
              <span style={{ color: '#f8fafc' }}>— JP</span>
              <span style={{ color: '#f59e0b' }}>— DE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
