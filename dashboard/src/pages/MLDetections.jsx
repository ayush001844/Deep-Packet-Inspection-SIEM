import { useState, useEffect, useRef } from 'react';
import { useApi } from '../hooks/useApi';
import {
  Brain, ShieldAlert, Zap, Activity, Target, Radio,
  TrendingUp, AlertTriangle, CheckCircle, Clock
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, Cell, RadialBarChart, RadialBar, Legend
} from 'recharts';

// ── Attack class colours (match backend) ─────────────────────────────────────
const ATTACK_COLORS = {
  'SSH Brute Force': '#f97316',
  'DDoS':            '#ef4444',
  'Port Scan':       '#a855f7',
  'C2 Beaconing':    '#3b82f6',
  'Normal':          '#22c55e',
};

const SEVERITY_COLOR = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--low)',
  info:     'var(--info)',
};

// Confidence gauge component
function ConfidenceBar({ value, attack }) {
  const color = ATTACK_COLORS[attack] || '#6b7280';
  const pct = Math.round(value * 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, width: '100%' }}>
      <div style={{
        flex: 1, height: 8, borderRadius: 4,
        background: 'var(--bg-elevated)', overflow: 'hidden'
      }}>
        <div style={{
          width: `${pct}%`, height: '100%', borderRadius: 4,
          background: `linear-gradient(90deg, ${color}99, ${color})`,
          transition: 'width 0.6s ease',
          boxShadow: `0 0 8px ${color}66`,
        }} />
      </div>
      <span style={{ fontSize: '0.8rem', fontWeight: 700, color, minWidth: 40, textAlign: 'right' }}>
        {pct}%
      </span>
    </div>
  );
}

// Single detection card
function DetectionCard({ d, idx }) {
  const sev = (d.severity || 'medium').toLowerCase();
  const ts  = d.timestamp
    ? new Date(d.timestamp * 1000).toLocaleTimeString()
    : '—';
  const probEntries = Object.entries(d.class_probabilities || {})
    .filter(([k]) => k !== 'Normal')
    .sort((a, b) => b[1] - a[1]);

  return (
    <div
      className={`card attack-feed-item severity-${sev}`}
      style={{
        padding: '16px 20px', marginBottom: 10, borderRadius: 12,
        borderLeft: `3px solid ${ATTACK_COLORS[d.attack] || 'var(--border-default)'}`,
        background: 'var(--bg-card)',
        animation: 'fadeInSlide 0.35s ease both',
        animationDelay: `${idx * 0.04}s`,
      }}
    >
      {/* Header row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: `${ATTACK_COLORS[d.attack] || '#6b7280'}22`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Brain size={18} color={ATTACK_COLORS[d.attack] || '#6b7280'} />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary)' }}>
              {d.attack}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {d.src_ip && <span>{d.src_ip}</span>}
              {d.src_port && <span> :{d.src_port}</span>}
              {d.mitre_technique && (
                <span className="mitre-badge" style={{ marginLeft: 6 }}>
                  {d.mitre_technique}
                </span>
              )}
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <span className={`severity-badge ${sev}`} style={{ fontSize: '0.65rem', display: 'block', marginBottom: 4 }}>
            {sev.toUpperCase()}
          </span>
          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{ts}</span>
        </div>
      </div>

      {/* Confidence bar */}
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>
          AI Confidence
        </div>
        <ConfidenceBar value={d.confidence} attack={d.attack} />
      </div>

      {/* Per-class probabilities */}
      {probEntries.length > 0 && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {probEntries.slice(0, 4).map(([cls, prob]) => (
            <div key={cls} style={{
              padding: '2px 8px', borderRadius: 6,
              background: `${ATTACK_COLORS[cls] || '#6b7280'}18`,
              fontSize: '0.68rem', color: ATTACK_COLORS[cls] || 'var(--text-muted)',
              border: `1px solid ${ATTACK_COLORS[cls] || '#6b7280'}33`,
            }}>
              {cls}: {Math.round(prob * 100)}%
            </div>
          ))}
        </div>
      )}

      {/* MITRE tactic */}
      {d.mitre_tactic && (
        <div style={{ marginTop: 8, fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          <Target size={11} style={{ marginRight: 4, verticalAlign: 'middle' }} />
          MITRE: {d.mitre_tactic}
        </div>
      )}
    </div>
  );
}

// Custom tooltip for BarChart
function AttackTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{
      background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
      borderRadius: 8, padding: '10px 14px', fontSize: '0.8rem',
    }}>
      <div style={{ color: d.color || 'var(--text-primary)', fontWeight: 700 }}>{d.attack}</div>
      <div style={{ color: 'var(--text-secondary)' }}>Detections: {d.count}</div>
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────────────────
export default function MLDetections() {
  const { data: recentRaw,  } = useApi('/api/ml/recent', { interval: 3000 });
  const { data: stats }       = useApi('/api/ml/stats',  { interval: 4000 });
  const { data: mlStatus }    = useApi('/api/ml/status', { interval: 10000 });

  const [liveDetections, setLiveDetections]   = useState([]);
  const [filter, setFilter]                   = useState('All');
  const feedRef = useRef(null);

  // Merge REST detections into live state
  useEffect(() => {
    if (recentRaw && Array.isArray(recentRaw)) {
      setLiveDetections(recentRaw.filter(d => d.attack && d.attack !== 'Normal'));
    }
  }, [recentRaw]);

  const attackTypes = ['All', 'SSH Brute Force', 'DDoS', 'Port Scan', 'C2 Beaconing'];
  const filtered = filter === 'All'
    ? liveDetections
    : liveDetections.filter(d => d.attack === filter);

  const totalDetections = stats?.total_detections || 0;
  const topThreat       = stats?.top_threat || '—';
  const classData       = stats?.class_distribution || [];
  const trendData       = stats?.confidence_trend || [];
  const isLoaded        = mlStatus?.loaded ?? false;

  return (
    <div className="fade-in">
      {/* ── Page Header ── */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 12,
            background: 'linear-gradient(135deg, #6366f1, #8b5cf6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 24px #6366f166',
          }}>
            <Brain size={22} color="white" />
          </div>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              AI/ML Detection Engine
            </h2>
            <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Real-time behavioral anomaly detection · 5-class RandomForest
            </p>
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px',
              borderRadius: 8, fontSize: '0.75rem', fontWeight: 600,
              background: isLoaded ? 'var(--success-bg)' : 'var(--critical-bg)',
              color: isLoaded ? 'var(--success)' : 'var(--critical)',
              border: `1px solid ${isLoaded ? 'var(--success)' : 'var(--critical)'}33`,
            }}>
              {isLoaded
                ? <><CheckCircle size={12} /> Model Loaded</>
                : <><AlertTriangle size={12} /> Model Offline</>}
            </div>
          </div>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className="stat-grid-5" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 24 }}>
        {[
          {
            label: 'Total Detections', value: totalDetections,
            icon: ShieldAlert, color: '#ef4444', bg: '#ef444415',
          },
          {
            label: 'Top Threat Class', value: topThreat,
            icon: Target, color: ATTACK_COLORS[topThreat] || '#a855f7',
            bg: `${ATTACK_COLORS[topThreat] || '#a855f7'}18`,
          },
          {
            label: 'Attack Classes', value: mlStatus?.class_count || 5,
            icon: Brain, color: '#6366f1', bg: '#6366f115',
          },
          {
            label: 'Model Accuracy', value: isLoaded ? '100%' : 'N/A',
            icon: TrendingUp, color: '#22c55e', bg: '#22c55e15',
          },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="card" style={{ background: 'var(--bg-card)', padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10, background: bg,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <Icon size={18} color={color} />
              </div>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {value}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Charts row ── */}
      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Attack class distribution bar chart */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={16} color="var(--accent)" />
              Attack Class Distribution
            </h3>
          </div>
          {classData.length > 0 && classData.some(d => d.count > 0) ? (
            <div style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={classData} margin={{ top: 4, right: 12, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis dataKey="attack" stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false}
                    tick={{ fill: 'var(--text-muted)' }}
                    tickFormatter={v => v.split(' ')[0]}
                  />
                  <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip content={<AttackTooltip />} cursor={{ fill: 'var(--bg-card-hover)' }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} barSize={32}>
                    {classData.map((d, i) => (
                      <Cell key={i} fill={d.color} opacity={0.9} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="empty-state" style={{ height: 220, padding: 0 }}>
              <Brain size={28} style={{ opacity: 0.25, marginBottom: 8 }} />
              <p>No detections yet — run a packet capture or PCAP analysis</p>
            </div>
          )}
        </div>

        {/* Confidence trend */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Zap size={16} color="var(--accent)" />
              Confidence Trend
            </h3>
          </div>
          {trendData.length > 0 ? (
            <div style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 12, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="confGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#6366f1" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis dataKey="time" hide />
                  <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11}
                    tickLine={false} axisLine={false}
                    tickFormatter={v => `${v}%`}
                  />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8 }}
                    formatter={(v, _, p) => [`${v}%`, p.payload.attack || 'Confidence']}
                    labelFormatter={() => ''}
                  />
                  <Area
                    type="monotone" dataKey="confidence"
                    stroke="#6366f1" strokeWidth={2.5}
                    fill="url(#confGrad)" dot={{ r: 3, fill: '#6366f1', strokeWidth: 0 }}
                    activeDot={{ r: 5, strokeWidth: 0, fill: '#a5b4fc' }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="empty-state" style={{ height: 220, padding: 0 }}>
              <Activity size={28} style={{ opacity: 0.25, marginBottom: 8 }} />
              <p>Collecting confidence data…</p>
            </div>
          )}
        </div>
      </div>

      {/* ── Live Detections Feed ── */}
      <div className="card">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
          <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
            <Radio size={16} color="var(--critical)" />
            Live ML Detections
            {filtered.length > 0 && (
              <span className="badge" style={{ background: 'var(--critical-bg)', color: 'var(--critical)', fontSize: '0.7rem' }}>
                {filtered.length}
              </span>
            )}
          </h3>

          {/* Filter pills */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {attackTypes.map(t => (
              <button
                key={t}
                id={`ml-filter-${t.replace(/\s+/g, '-')}`}
                onClick={() => setFilter(t)}
                style={{
                  padding: '4px 12px', borderRadius: 20, fontSize: '0.72rem',
                  fontWeight: 600, cursor: 'pointer', border: 'none',
                  background: filter === t
                    ? (ATTACK_COLORS[t] || 'var(--accent)')
                    : 'var(--bg-elevated)',
                  color: filter === t ? '#fff' : 'var(--text-secondary)',
                  transition: 'all 0.2s ease',
                  boxShadow: filter === t ? `0 0 12px ${ATTACK_COLORS[t] || 'var(--accent)'}55` : 'none',
                }}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <div
          ref={feedRef}
          style={{ maxHeight: 520, overflowY: 'auto', padding: '4px 0' }}
        >
          {filtered.length > 0 ? (
            filtered.map((d, idx) => (
              <DetectionCard key={`${d.timestamp}-${idx}`} d={d} idx={idx} />
            ))
          ) : (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Brain size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
              <p style={{ fontWeight: 600, marginBottom: 4 }}>No ML detections yet</p>
              <p style={{ fontSize: '0.82rem' }}>
                Start a live packet capture or upload a PCAP file to see the AI engine in action
              </p>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes fadeInSlide {
          from { opacity: 0; transform: translateY(8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
