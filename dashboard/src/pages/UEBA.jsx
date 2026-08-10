import { useState, useEffect } from 'react';
import { useApi } from '../hooks/useApi';
import {
  Users, UserCheck, AlertTriangle, Globe, Clock,
  Shield, FileText, Activity, Lock, MapPin
} from 'lucide-react';

const SEV_COLOR = { high: 'var(--critical)', medium: 'var(--high)', low: 'var(--medium)' };

function UEBAAlertCard({ alert, idx }) {
  const ts = alert.timestamp
    ? new Date(alert.timestamp * 1000).toLocaleTimeString()
    : '—';
  const sev = (alert.severity || 'medium').toLowerCase();

  return (
    <div style={{
      padding: '16px 20px', borderRadius: 12, marginBottom: 10,
      background: 'var(--bg-card)',
      borderLeft: `3px solid ${SEV_COLOR[sev] || 'var(--border-default)'}`,
      animation: 'fadeInSlide 0.3s ease both',
      animationDelay: `${idx * 0.04}s`,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8,
            background: `${SEV_COLOR[sev] || 'var(--border-default)'}22`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Users size={16} color={SEV_COLOR[sev]} />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{alert.title}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              <strong>{alert.username}</strong>
              {alert.src_ip && <> · {alert.src_ip}</>}
              {alert.country && <> · 📍 {alert.country}</>}
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

      {/* Anomaly list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {(alert.anomalies || [alert.message]).map((msg, i) => (
          <div key={i} style={{
            fontSize: '0.78rem', color: 'var(--text-secondary)',
            padding: '4px 10px', borderRadius: 6,
            background: 'var(--bg-elevated)',
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <AlertTriangle size={11} color={SEV_COLOR[sev]} style={{ flexShrink: 0 }} />
            {msg}
          </div>
        ))}
      </div>

      {alert.hour !== undefined && (
        <div style={{ marginTop: 8, fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', gap: 12 }}>
          <span><Clock size={11} style={{ verticalAlign: 'middle', marginRight: 3 }} />{alert.hour}:00 UTC</span>
          {alert.event_type && <span>Event: {alert.event_type}</span>}
        </div>
      )}
    </div>
  );
}

function BaselineCard({ user }) {
  const hour = user.login_hour_mean ?? 12;
  const hourStr = `${Math.round(hour).toString().padStart(2, '0')}:00`;

  return (
    <div className="card" style={{ padding: '18px 20px', marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 38, height: 38, borderRadius: 10,
            background: 'var(--accent-bg)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <UserCheck size={18} color="var(--accent)" />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>{user.username}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {user.total_events} events tracked
            </div>
          </div>
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'right' }}>
          {user.auth_failures_24h > 0 && (
            <span style={{
              background: 'var(--critical-bg)', color: 'var(--critical)',
              padding: '2px 8px', borderRadius: 6, fontSize: '0.68rem', fontWeight: 700,
            }}>
              {user.auth_failures_24h} auth failures
            </span>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: 'Typical Login', value: hourStr, icon: Clock, color: '#6366f1' },
          { label: 'Known Countries', value: (user.known_countries || []).slice(0, 3).join(', ') || '—', icon: Globe, color: '#22c55e' },
          { label: 'Avg Files/Session', value: Math.round(user.file_access_mean || 0), icon: FileText, color: '#f97316' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} style={{
            padding: '10px 12px', borderRadius: 8, background: 'var(--bg-elevated)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <Icon size={12} color={color} />
              <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{label}</span>
            </div>
            <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)' }}>{value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function UEBA() {
  const { data: alertsRaw }  = useApi('/api/ueba/alerts', { interval: 3000 });
  const { data: usersRaw }   = useApi('/api/ueba/users',  { interval: 5000 });
  const { data: statsRaw }   = useApi('/api/ueba/stats',  { interval: 5000 });

  const [tab, setTab] = useState('alerts');
  const [testForm, setTestForm] = useState({
    username: 'ayush', event_type: 'login', src_ip: '1.2.3.4',
    country: 'RU', hour: 3, file_count: 5000, success: true,
  });
  const [testResult, setTestResult] = useState(null);

  const alerts = alertsRaw || [];
  const users  = usersRaw  || [];
  const stats  = statsRaw  || {};

  const sendTestEvent = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch('http://localhost:8000/api/ueba/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ ...testForm, timestamp: Date.now() / 1000 }),
      });
      const data = await res.json();
      setTestResult(data);
    } catch (e) {
      setTestResult({ error: e.message });
    }
  };

  return (
    <div className="fade-in">
      {/* Header */}
      <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{
          width: 44, height: 44, borderRadius: 12, flexShrink: 0,
          background: 'linear-gradient(135deg, #06b6d4, #6366f1)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 24px #06b6d466',
        }}>
          <Users size={22} color="white" />
        </div>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 800 }}>
            User & Entity Behavior Analytics
          </h2>
          <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Baseline learning · Z-score anomaly detection · Account compromise detection
          </p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{
            padding: '6px 14px', borderRadius: 8, fontSize: '0.75rem', fontWeight: 600,
            background: 'var(--accent-bg)', color: 'var(--accent)',
          }}>
            {stats.tracked_users || 0} Users Tracked
          </div>
        </div>
      </div>

      {/* Stat row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Users Monitored', value: stats.tracked_users || 0, icon: Users, color: '#6366f1', bg: '#6366f115' },
          { label: 'UEBA Alerts', value: stats.total_alerts || 0, icon: AlertTriangle, color: '#ef4444', bg: '#ef444415' },
          { label: 'High Severity', value: alerts.filter(a => a.severity === 'high').length, icon: Shield, color: '#f97316', bg: '#f9731615' },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="card" style={{ padding: '18px 20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon size={18} color={color} />
              </div>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 800, lineHeight: 1 }}>{value}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20 }}>
        {['alerts', 'users', 'simulate'].map(t => (
          <button
            key={t}
            id={`ueba-tab-${t}`}
            onClick={() => setTab(t)}
            style={{
              padding: '8px 20px', borderRadius: 8, border: 'none', cursor: 'pointer',
              fontWeight: 600, fontSize: '0.82rem',
              background: tab === t ? 'var(--accent)' : 'var(--bg-elevated)',
              color: tab === t ? '#fff' : 'var(--text-secondary)',
              transition: 'all 0.2s',
            }}
          >
            {t === 'alerts' ? `Alerts (${alerts.length})` : t === 'users' ? `Users (${users.length})` : 'Simulate Event'}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'alerts' && (
        <div>
          {alerts.length > 0 ? (
            alerts.map((a, i) => <UEBAAlertCard key={a.id || i} alert={a} idx={i} />)
          ) : (
            <div className="card" style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <UserCheck size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
              <p style={{ fontWeight: 600, marginBottom: 4 }}>No UEBA alerts</p>
              <p style={{ fontSize: '0.82rem' }}>Use the "Simulate Event" tab to generate test events</p>
            </div>
          )}
        </div>
      )}

      {tab === 'users' && (
        <div>
          {users.length > 0 ? (
            users.map((u, i) => <BaselineCard key={u.username || i} user={u} />)
          ) : (
            <div className="card" style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Users size={40} style={{ opacity: 0.2, marginBottom: 12 }} />
              <p>No user baselines yet — submit events via the Simulate tab</p>
            </div>
          )}
        </div>
      )}

      {tab === 'simulate' && (
        <div className="card" style={{ padding: '24px' }}>
          <h3 style={{ marginBottom: 20, fontSize: '1rem', fontWeight: 700 }}>
            Send a Test User Event
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 16, marginBottom: 20 }}>
            {[
              { key: 'username',   label: 'Username',    type: 'text' },
              { key: 'event_type', label: 'Event Type',  type: 'select', opts: ['login', 'file_access', 'auth_failure', 'logout'] },
              { key: 'src_ip',     label: 'Source IP',   type: 'text' },
              { key: 'country',    label: 'Country Code (e.g. RU, CN, IN)', type: 'text' },
              { key: 'hour',       label: 'Login Hour (0-23 UTC)', type: 'number' },
              { key: 'file_count', label: 'Files Accessed', type: 'number' },
            ].map(({ key, label, type, opts }) => (
              <div key={key}>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>{label}</label>
                {type === 'select' ? (
                  <select
                    value={testForm[key]}
                    onChange={e => setTestForm(f => ({ ...f, [key]: e.target.value }))}
                    style={{
                      width: '100%', padding: '8px 12px', borderRadius: 8,
                      background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
                      color: 'var(--text-primary)', fontSize: '0.85rem',
                    }}
                  >
                    {opts.map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                ) : (
                  <input
                    type={type}
                    value={testForm[key]}
                    onChange={e => setTestForm(f => ({ ...f, [key]: type === 'number' ? Number(e.target.value) : e.target.value }))}
                    style={{
                      width: '100%', padding: '8px 12px', borderRadius: 8,
                      background: 'var(--bg-elevated)', border: '1px solid var(--border-default)',
                      color: 'var(--text-primary)', fontSize: '0.85rem', boxSizing: 'border-box',
                    }}
                  />
                )}
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              id="ueba-simulate-btn"
              onClick={sendTestEvent}
              style={{
                padding: '10px 24px', borderRadius: 8, border: 'none', cursor: 'pointer',
                background: 'linear-gradient(135deg, #06b6d4, #6366f1)',
                color: '#fff', fontWeight: 700, fontSize: '0.85rem',
              }}
            >
              Send Event
            </button>
            <button
              style={{
                padding: '10px 18px', borderRadius: 8, border: 'none', cursor: 'pointer',
                background: 'var(--bg-elevated)', color: 'var(--text-secondary)',
                fontSize: '0.82rem',
              }}
              onClick={() => setTestForm({ username: 'ayush', event_type: 'login', src_ip: '1.2.3.4', country: 'RU', hour: 3, file_count: 5000, success: true })}
            >
              🔴 Suspicious Preset
            </button>
            <button
              style={{
                padding: '10px 18px', borderRadius: 8, border: 'none', cursor: 'pointer',
                background: 'var(--bg-elevated)', color: 'var(--text-secondary)',
                fontSize: '0.82rem',
              }}
              onClick={() => setTestForm({ username: 'ayush', event_type: 'login', src_ip: '192.168.1.5', country: 'IN', hour: 10, file_count: 20, success: true })}
            >
              🟢 Normal Preset
            </button>
          </div>

          {testResult && (
            <div style={{
              marginTop: 20, padding: '16px', borderRadius: 10,
              background: testResult.alert ? '#ef444415' : 'var(--bg-elevated)',
              border: `1px solid ${testResult.alert ? '#ef444433' : 'var(--border-default)'}`,
            }}>
              <div style={{ fontWeight: 700, marginBottom: 8, color: testResult.alert ? 'var(--critical)' : 'var(--success)' }}>
                {testResult.alert ? '⚠ Anomaly Detected!' : '✓ Normal Behavior'}
              </div>
              {testResult.alert && (
                <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                  {(testResult.alert.anomalies || []).map((a, i) => <div key={i}>• {a}</div>)}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <style>{`
        @keyframes fadeInSlide {
          from { opacity: 0; transform: translateY(6px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
