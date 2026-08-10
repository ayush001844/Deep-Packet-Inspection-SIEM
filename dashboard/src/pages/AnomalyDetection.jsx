import { useState, useEffect, useRef } from 'react';
import { useApi } from '../hooks/useApi';
import {
  Radar, AlertTriangle, Activity, TrendingUp, Zap,
  Shield, ShieldOff, Clock, Info
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, RadialBarChart, RadialBar, Legend
} from 'recharts';

const SCORE_COLOR = (score) => {
  if (score > 0.8) return '#ef4444';
  if (score > 0.6) return '#f97316';
  if (score > 0.4) return '#eab308';
  return '#22c55e';
};

function AnomalyScoreGauge({ score, threshold }) {
  const pct = Math.min(100, Math.round(score * 100));
  const thresholdPct = Math.min(100, Math.round(threshold * 100));
  const color = SCORE_COLOR(score);

  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{
        position: 'relative', width: 120, height: 120,
        margin: '0 auto 12px',
      }}>
        <svg viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="60" cy="60" r="50" fill="none" stroke="var(--bg-elevated)" strokeWidth="12" />
          <circle cx="60" cy="60" r="50" fill="none" stroke={color}
            strokeWidth="12" strokeLinecap="round"
            strokeDasharray={`${pct * 3.14} 314`}
            style={{ transition: 'stroke-dasharray 0.6s ease, stroke 0.4s ease' }}
          />
        </svg>
        <div style={{
          position: 'absolute', inset: 0, display: 'flex',
          alignItems: 'center', justifyContent: 'center', flexDirection: 'column',
        }}>
          <span style={{ fontSize: '1.6rem', fontWeight: 800, color, lineHeight: 1 }}>{pct}</span>
          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>/ 100</span>
        </div>
      </div>
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
        Threshold: <span style={{ color: '#eab308' }}>{thresholdPct}</span>
      </div>
    </div>
  );
}

function AnomalyCard({ a, idx }) {
  const ts = a.timestamp ? new Date(a.timestamp * 1000).toLocaleTimeString() : '—';
  const score = a.anomaly_score || 0;
  const color = SCORE_COLOR(score);
  const pct = Math.round(score * 100);

  return (
    <div style={{
      padding: '14px 18px', borderRadius: 10, marginBottom: 8,
      background: 'var(--bg-card)', borderLeft: `3px solid ${color}`,
      animation: 'fadeInSlide 0.3s ease both',
      animationDelay: `${idx * 0.03}s`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={15} color={color} />
          <span style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
            {a.description || 'Behavioral Anomaly'}
          </span>
        </div>
        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{ts}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--bg-elevated)' }}>
          <div style={{
            width: `${pct}%`, height: '100%', borderRadius: 3,
            background: `linear-gradient(90deg, ${color}88, ${color})`,
            boxShadow: `0 0 8px ${color}55`,
            transition: 'width 0.5s ease',
          }} />
        </div>
        <span style={{ fontSize: '0.78rem', fontWeight: 700, color, minWidth: 44, textAlign: 'right' }}>
          {pct}%
        </span>
      </div>
      {a.src_ip && (
        <div style={{ marginTop: 6, fontSize: '0.7rem', color: 'var(--text-muted)' }}>
          Source: {a.src_ip}
        </div>
      )}
    </div>
  );
}

export default function AnomalyDetection() {
  const { data: statsRaw } = useApi('/api/anomaly/stats',  { interval: 3000 });
  const { data: recentRaw } = useApi('/api/anomaly/recent', { interval: 3000 });

  const [trendData, setTrendData] = useState([]);
  const trendRef = useRef([]);

  useEffect(() => {
    // Rolling trend from recent anomalies
    if (recentRaw && Array.isArray(recentRaw)) {
      const points = recentRaw.slice(0, 30).reverse().map((a, i) => ({
        time: i,
        score: Math.round((a.anomaly_score || 0) * 100),
        isAnomaly: a.is_anomaly,
      }));
      setTrendData(points);
    }
  }, [recentRaw]);

  const stats   = statsRaw || {};
  const anomalies = (recentRaw || []).filter(a => a.is_anomaly);
  const isLoaded  = stats.model_loaded ?? false;
  const threshold = stats.threshold ?? 0.5;
  const avgScore  = stats.avg_score ?? 0;
  const maxScore  = stats.max_score ?? 0;
  const total     = stats.total_anomalies ?? 0;
  const thresholdPct = Math.min(100, Math.round((threshold / (threshold * 3 || 1)) * 100));

  return (
    <div className="fade-in">
      {/* Header */}
      <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 12, flexShrink: 0,
          background: 'linear-gradient(135deg, #ec4899, #8b5cf6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 24px #ec489966',
        }}>
          <Radar size={22} color="white" />
        </div>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 800 }}>Anomaly Detection</h2>
          <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Autoencoder-based unsupervised anomaly detection · Detects unknown threats
          </p>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <div style={{
            padding: '6px 14px', borderRadius: 8, fontSize: '0.75rem', fontWeight: 600,
            background: isLoaded ? 'var(--success-bg)' : 'var(--critical-bg)',
            color: isLoaded ? 'var(--success)' : 'var(--critical)',
          }}>
            {isLoaded ? '✓ Model Active' : '✗ Model Offline'}
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Anomalies Detected', value: total, icon: AlertTriangle, color: '#ef4444', bg: '#ef444415' },
          { label: 'Avg Anomaly Score', value: `${Math.round(avgScore * 100)}%`, icon: Activity, color: '#f97316', bg: '#f9731615' },
          { label: 'Peak Score', value: `${Math.round(maxScore * 100)}%`, icon: TrendingUp, color: '#a855f7', bg: '#a855f715' },
          { label: 'Threshold', value: `${Math.round(threshold * 100)}%`, icon: Zap, color: '#22c55e', bg: '#22c55e15' },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="card" style={{ padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon size={18} color={color} />
              </div>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>{value}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Reconstruction error trend */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={16} color="var(--accent)" />
              Anomaly Score Trend
            </h3>
          </div>
          {trendData.length > 0 ? (
            <div style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 12, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ec4899" stopOpacity={0.5} />
                      <stop offset="95%" stopColor="#ec4899" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
                  <XAxis dataKey="time" hide />
                  <YAxis domain={[0, 100]} stroke="var(--text-muted)" fontSize={11}
                    tickLine={false} axisLine={false} tickFormatter={v => `${v}%`} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8 }}
                    formatter={(v) => [`${v}%`, 'Anomaly Score']}
                    labelFormatter={() => ''}
                  />
                  <ReferenceLine y={Math.round(threshold * 100)} stroke="#eab308" strokeDasharray="4 4"
                    label={{ value: 'Threshold', position: 'right', fill: '#eab308', fontSize: 11 }} />
                  <Area type="monotone" dataKey="score"
                    stroke="#ec4899" strokeWidth={2.5} fill="url(#anomGrad)"
                    dot={false} activeDot={{ r: 4, strokeWidth: 0, fill: '#f9a8d4' }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="empty-state" style={{ height: 220, padding: 0 }}>
              <Radar size={28} style={{ opacity: 0.25, marginBottom: 8 }} />
              <p>No anomaly data yet — run a capture or PCAP analysis</p>
            </div>
          )}
        </div>

        {/* Explainer card */}
        <div className="card" style={{ padding: '24px' }}>
          <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <Info size={16} color="var(--accent)" />
            How It Works
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {[
              { step: '1', label: 'Learn Normal Patterns', desc: 'The autoencoder trains on baseline normal traffic and learns to reconstruct it perfectly.', color: '#22c55e' },
              { step: '2', label: 'Encode → Bottleneck → Decode', desc: 'Every new flow is encoded into a 3D latent space and reconstructed. Normal flows reconstruct well.', color: '#6366f1' },
              { step: '3', label: 'Reconstruction Error', desc: 'Anomalous flows cannot be reconstructed accurately — producing a high error score.', color: '#f97316' },
              { step: '4', label: 'Alert on High Error', desc: 'If the score exceeds the threshold, an anomaly alert fires — even for unknown attack types.', color: '#ef4444' },
            ].map(({ step, label, desc, color }) => (
              <div key={step} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 8, background: `${color}22`,
                  color, fontWeight: 800, fontSize: '0.8rem',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  {step}
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: 2 }}>{label}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Live anomaly feed */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Radar size={16} color="#ec4899" />
            Live Anomaly Feed
            {anomalies.length > 0 && (
              <span className="badge" style={{ background: '#ec489920', color: '#ec4899', fontSize: '0.7rem' }}>
                {anomalies.length}
              </span>
            )}
          </h3>
        </div>
        <div style={{ maxHeight: 420, overflowY: 'auto' }}>
          {anomalies.length > 0 ? (
            anomalies.map((a, i) => <AnomalyCard key={i} a={a} idx={i} />)
          ) : (
            <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Shield size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
              <p style={{ fontWeight: 600, marginBottom: 4 }}>No anomalies detected</p>
              <p style={{ fontSize: '0.82rem' }}>Traffic patterns are within normal bounds</p>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes fadeInSlide {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
