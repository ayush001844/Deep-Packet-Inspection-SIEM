import React, { useState, useMemo } from 'react';
import { useApi } from '../hooks/useApi';
import {
  Clock, ShieldAlert, Zap, GitMerge, Download, ChevronRight,
  Target, AlertTriangle, Crosshair, Link2, Search, Shield, Globe
} from 'lucide-react';

// ── MITRE ATT&CK stage → color & icon ──────────────────────────────
const STAGE_META = {
  'Reconnaissance':      { color: 'hsl(200, 80%, 55%)',  icon: Search },
  'Initial Access':      { color: 'hsl(25, 90%, 55%)',   icon: Globe },
  'Execution':           { color: 'hsl(45, 90%, 55%)',   icon: Zap },
  'Persistence':         { color: 'hsl(275, 70%, 60%)',  icon: Link2 },
  'Lateral Movement':    { color: 'hsl(330, 70%, 60%)',  icon: Crosshair },
  'Exfiltration':        { color: 'hsl(0, 75%, 55%)',    icon: Target },
  'Command and Control': { color: 'hsl(165, 70%, 45%)',  icon: Shield },
  'Discovery':           { color: 'hsl(55, 80%, 55%)',   icon: Search },
};

function getSeverityColor(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'hsl(0, 75%, 55%)';
  if (s === 'high')     return 'hsl(25, 90%, 55%)';
  if (s === 'medium')   return 'hsl(45, 90%, 55%)';
  return 'hsl(210, 70%, 55%)';
}

function SeverityDot({ severity }) {
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
      backgroundColor: getSeverityColor(severity), flexShrink: 0,
      boxShadow: `0 0 6px ${getSeverityColor(severity)}`,
    }} />
  );
}

// ── Incident selector sidebar ───────────────────────────────────────
function IncidentList({ incidents, selected, onSelect }) {
  return (
    <div style={{
      width: 300, flexShrink: 0,
      backgroundColor: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border-default)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      <div style={{
        padding: '18px 20px', borderBottom: '1px solid var(--border-default)',
        display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <GitMerge size={18} color="var(--accent)" />
        <div>
          <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>Incidents</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {incidents.length} campaign{incidents.length !== 1 ? 's' : ''} detected
          </div>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {incidents.length === 0 && (
          <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            No incidents yet. Traffic will be correlated into campaigns automatically.
          </div>
        )}
        {incidents.map((inc) => (
          <button
            key={inc.id}
            onClick={() => onSelect(inc.id)}
            style={{
              width: '100%', textAlign: 'left', background: 'none', border: 'none',
              borderBottom: '1px solid var(--border-subtle)',
              padding: '14px 20px', cursor: 'pointer',
              backgroundColor: selected === inc.id ? 'var(--bg-card)' : 'transparent',
              borderLeft: selected === inc.id ? '3px solid var(--accent)' : '3px solid transparent',
              transition: 'all 0.15s ease',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
              <span style={{ fontSize: '0.7rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)' }}>
                {inc.incident_id}
              </span>
              <span className={`severity-badge ${inc.severity?.toLowerCase()}`} style={{ fontSize: '0.65rem', padding: '2px 6px' }}>
                {inc.severity?.toUpperCase()}
              </span>
            </div>
            <div style={{ fontWeight: 500, fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: 4, lineHeight: 1.4 }}>
              {inc.title}
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                {new Date(inc.created_at * 1000).toLocaleDateString()}
              </span>
              <span className="badge" style={{ fontSize: '0.65rem', backgroundColor: 'var(--bg-card)', padding: '2px 6px' }}>
                {inc.status}
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// ── MITRE ATT&CK kill-chain strip ──────────────────────────────────
function AttackChain({ stages }) {
  const allStages = Object.keys(STAGE_META);
  return (
    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
      {allStages.map(stage => {
        const active = stages.includes(stage);
        const meta = STAGE_META[stage];
        const Icon = meta.icon;
        return (
          <div
            key={stage}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 10px', borderRadius: 6, fontSize: '0.72rem',
              border: `1px solid ${active ? meta.color : 'var(--border-default)'}`,
              backgroundColor: active ? `${meta.color}22` : 'transparent',
              color: active ? meta.color : 'var(--text-muted)',
              transition: 'all 0.2s',
              opacity: active ? 1 : 0.4,
            }}
          >
            <Icon size={11} />
            {stage}
          </div>
        );
      })}
    </div>
  );
}

// ── Single timeline event card ──────────────────────────────────────
function TimelineEvent({ event, index, total }) {
  const meta = STAGE_META[event.stage] || {};
  const color = meta.color || getSeverityColor(event.severity);
  const Icon = meta.icon || ShieldAlert;
  const isLast = index === total - 1;

  return (
    <div style={{ display: 'flex', gap: 16, position: 'relative' }}>
      {/* connector line */}
      {!isLast && (
        <div style={{
          position: 'absolute', left: 20, top: 42, bottom: -20,
          width: 2, background: `linear-gradient(to bottom, ${color}55, transparent)`,
          zIndex: 0,
        }} />
      )}

      {/* node icon */}
      <div style={{
        width: 40, height: 40, borderRadius: '50%', flexShrink: 0, zIndex: 1,
        backgroundColor: `${color}22`,
        border: `2px solid ${color}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: `0 0 12px ${color}44`,
      }}>
        <Icon size={16} color={color} />
      </div>

      {/* content card */}
      <div style={{
        flex: 1, marginBottom: 20,
        backgroundColor: 'var(--bg-card)',
        border: `1px solid var(--border-default)`,
        borderLeft: `3px solid ${color}`,
        borderRadius: 8, padding: '14px 18px',
        transition: 'border-color 0.2s',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <SeverityDot severity={event.severity} />
            <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{event.event}</span>
            {event.stage && event.stage !== 'Unknown' && (
              <span style={{
                fontSize: '0.68rem', padding: '2px 7px', borderRadius: 4,
                backgroundColor: `${color}22`, color: color,
                border: `1px solid ${color}55`,
              }}>
                {event.stage}
              </span>
            )}
          </div>
          <span style={{
            fontSize: '0.72rem', fontFamily: 'JetBrains Mono, monospace',
            color: 'var(--text-muted)', whiteSpace: 'nowrap', marginLeft: 12, flexShrink: 0,
          }}>
            {new Date(event.timestamp * 1000).toLocaleTimeString()}
          </span>
        </div>

        <p style={{ margin: '0 0 10px', fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
          {event.description}
        </p>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <span style={{
            fontSize: '0.7rem', padding: '2px 7px', borderRadius: 4,
            backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)',
          }}>
            {event.source}
          </span>
          <span style={{
            fontSize: '0.7rem', padding: '2px 7px', borderRadius: 4,
            backgroundColor: 'var(--bg-elevated)', color: 'var(--text-muted)',
          }}>
            {new Date(event.timestamp * 1000).toLocaleDateString()}
          </span>
        </div>
      </div>
    </div>
  );
}

// ── Timeline viewer ─────────────────────────────────────────────────
function TimelineViewer({ incidentId }) {
  const { data, loading } = useApi(`/api/incidents/${incidentId}/timeline`);

  if (loading) return (
    <div className="empty-state" style={{ flex: 1 }}>
      <Clock size={40} style={{ opacity: 0.3 }} />
      <h3>Loading timeline...</h3>
    </div>
  );

  if (!data || data.error) return (
    <div className="empty-state" style={{ flex: 1 }}>
      <AlertTriangle size={40} />
      <h3>Failed to load timeline</h3>
      <p>The timeline data could not be retrieved.</p>
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* ── Header ── */}
      <div style={{
        padding: '20px 28px', borderBottom: '1px solid var(--border-default)',
        backgroundColor: 'var(--bg-secondary)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16,
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700 }}>{data.title}</h2>
            <span className={`severity-badge ${data.severity?.toLowerCase()}`}>
              {data.severity?.toUpperCase()}
            </span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              #{data.incident_id}
            </span>
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 14 }}>
            {data.alert_count} correlated events detected
          </div>
          <AttackChain stages={data.attack_stages || []} />
        </div>

        <a
          href={`http://localhost:8000/api/incidents/${data.incident_id}/report`}
          target="_blank" rel="noreferrer"
          className="btn btn-primary"
          style={{ display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap', flexShrink: 0 }}
        >
          <Download size={14} /> Export PDF
        </a>
      </div>

      {/* ── Events ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '28px 32px' }}>
        {data.timeline && data.timeline.length > 0 ? (
          <div style={{ maxWidth: 860 }}>
            {data.timeline.map((event, idx) => (
              <TimelineEvent key={idx} event={event} index={idx} total={data.timeline.length} />
            ))}
          </div>
        ) : (
          <div className="empty-state" style={{ height: 300 }}>
            <Clock size={40} style={{ opacity: 0.3 }} />
            <h3>No events yet</h3>
            <p>Events will appear as the attack progresses.</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ───────────────────────────────────────────────────────
export default function AttackTimeline() {
  const { data: incidents, loading } = useApi('/api/incidents?limit=100', { interval: 15000 });
  const [selectedId, setSelectedId] = useState(null);

  const sortedIncidents = useMemo(() => {
    if (!incidents) return [];
    return [...incidents].sort((a, b) => {
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      return (sevOrder[a.severity?.toLowerCase()] ?? 9) - (sevOrder[b.severity?.toLowerCase()] ?? 9);
    });
  }, [incidents]);

  // Auto-select first incident
  React.useEffect(() => {
    if (sortedIncidents.length > 0 && !selectedId) {
      setSelectedId(sortedIncidents[0].id);
    }
  }, [sortedIncidents]);

  return (
    <div className="fade-in" style={{
      height: 'calc(100vh - 120px)',
      display: 'flex',
      border: '1px solid var(--border-default)',
      borderRadius: 12,
      overflow: 'hidden',
      backgroundColor: 'var(--bg-secondary)',
    }}>
      {loading ? (
        <div className="empty-state" style={{ flex: 1 }}>
          <Clock size={40} style={{ opacity: 0.3 }} />
          <h3>Loading incidents...</h3>
        </div>
      ) : (
        <>
          <IncidentList
            incidents={sortedIncidents}
            selected={selectedId}
            onSelect={setSelectedId}
          />

          {selectedId ? (
            <TimelineViewer incidentId={selectedId} />
          ) : (
            <div className="empty-state" style={{ flex: 1 }}>
              <ChevronRight size={40} style={{ opacity: 0.3 }} />
              <h3>Select an incident</h3>
              <p>Choose a campaign from the left to view its attack timeline.</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
