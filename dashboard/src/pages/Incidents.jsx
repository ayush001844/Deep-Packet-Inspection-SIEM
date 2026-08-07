import { useApi } from '../hooks/useApi';
import { ShieldAlert, GitMerge, Clock, Activity, ArrowLeft, GitCommit, Download } from 'lucide-react';
import StatCard from '../components/StatCard';
import React, { useState } from 'react';

// Inline timeline for Incidents page (minimal)
function InlineTimeline({ incidentId, onBack }) {
  const { data, loading } = useApi(`/api/incidents/${incidentId}/timeline`);
  if (loading) return <div className="empty-state">Loading timeline...</div>;
  if (!data || data.error) return <div className="empty-state">Failed to load timeline.</div>;
  return (
    <div className="fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button className="btn btn-secondary" onClick={onBack} style={{ padding: '8px' }}><ArrowLeft size={18} /></button>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>{data.title}</h2>
            <div className="text-sm text-muted" style={{ display: 'flex', gap: '10px', marginTop: '5px' }}>
              <span className="badge" style={{ backgroundColor: 'var(--bg-secondary)' }}>ID: {data.incident_id}</span>
              <span className={`severity-badge ${data.severity?.toLowerCase()}`}>{data.severity?.toUpperCase()}</span>
            </div>
          </div>
        </div>
        <a href={`http://localhost:8000/api/incidents/${data.incident_id}/report`} target="_blank" rel="noreferrer" className="btn btn-primary" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Download size={16} /> Export PDF Report
        </a>
      </div>
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Attack Timeline ({data.alert_count} Events)</h3>
        </div>
        <div style={{ padding: '20px' }}>
          {data.timeline.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', position: 'relative' }}>
              <div style={{ position: 'absolute', left: '15px', top: '20px', bottom: '20px', width: '2px', backgroundColor: 'var(--border)' }}></div>
              {data.timeline.map((event, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '20px', position: 'relative', zIndex: 1 }}>
                  <div style={{ width: '32px', height: '32px', borderRadius: '50%', backgroundColor: 'var(--bg-secondary)', border: '2px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <GitCommit size={16} color="var(--text-muted)" />
                  </div>
                  <div style={{ flex: 1, backgroundColor: 'var(--bg-secondary)', padding: '15px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <span className="font-medium">{event.event}</span>
                      <span className="text-sm text-muted font-mono">{new Date(event.timestamp * 1000).toLocaleString()}</span>
                    </div>
                    <p className="text-sm text-muted" style={{ margin: '0 0 10px 0' }}>{event.description}</p>
                    {event.stage !== 'Unknown' && (
                      <span className="badge" style={{ backgroundColor: 'var(--primary-bg)', color: 'var(--primary)', fontSize: '0.75rem' }}>{event.stage}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No events found for this timeline.</div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Incidents() {
  const { data: incidents, loading } = useApi('/api/incidents?limit=50', { interval: 10000 });
  const [selectedIncident, setSelectedIncident] = useState(null);

  if (loading && !incidents) return <div className="empty-state">Loading incidents...</div>;

  const totalIncidents = incidents?.length || 0;
  const activeIncidents = incidents?.filter(i => i.status !== 'resolved')?.length || 0;

  if (selectedIncident) {
    return <InlineTimeline incidentId={selectedIncident} onBack={() => setSelectedIncident(null)} />;
  }

  return (
    <div className="fade-in">
      <div className="stat-grid mb-4">
        <StatCard 
          title="Total Incidents" 
          value={totalIncidents} 
          icon={GitMerge}
          color="var(--accent)"
        />
        <StatCard 
          title="Active Campaigns" 
          value={activeIncidents} 
          icon={Activity}
          color="var(--warning)"
          bg="var(--warning-bg)"
        />
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Incident Management</h3>
          <p className="text-sm text-muted">Correlated alert campaigns grouped by source IP or target.</p>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Created At</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {incidents && incidents.length > 0 ? (
                incidents.map(incident => (
                  <tr key={incident.id}>
                    <td className="font-mono text-sm">{incident.incident_id}</td>
                    <td className="font-medium">
                      {incident.title}
                      {incident.evidence?.filter(e => e.type === 'mitre_tactic').length > 0 && (
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '6px' }}>
                          {incident.evidence.filter(e => e.type === 'mitre_tactic').map((e, i) => (
                            <a 
                              key={i}
                              href={e.data.url}
                              target="_blank"
                              rel="noreferrer"
                              style={{ 
                                display: 'inline-flex',
                                alignItems: 'center',
                                fontSize: '0.7rem',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                color: 'var(--critical)',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                textDecoration: 'none',
                                border: '1px solid rgba(239, 68, 68, 0.3)'
                              }}
                            >
                              {e.data.technique.split(':')[0]} {/* e.g. T1046 */}
                            </a>
                          ))}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`severity-badge ${incident.severity.toLowerCase()}`}>
                        {incident.severity.toUpperCase()}
                      </span>
                    </td>
                    <td><span className="badge" style={{ backgroundColor: 'var(--bg-secondary)' }}>{incident.status}</span></td>
                    <td className="text-muted text-sm">{new Date(incident.created_at * 1000).toLocaleString()}</td>
                    <td>
                      <button 
                        className="btn btn-secondary" 
                        style={{ padding: '4px 8px', fontSize: '0.8rem' }}
                        onClick={() => setSelectedIncident(incident.id)}
                      >
                        View Timeline
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="empty-state" style={{ height: 200 }}>
                    <ShieldAlert size={40} />
                    <h3>No incidents</h3>
                    <p>No correlated attack campaigns detected.</p>
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
