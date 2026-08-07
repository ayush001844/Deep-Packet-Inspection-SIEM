import { useApi } from '../hooks/useApi';
import { ShieldAlert, GitMerge, Clock, Activity } from 'lucide-react';
import StatCard from '../components/StatCard';
import React, { useState } from 'react';
import Timeline from './Timeline';

export default function Incidents() {
  const { data: incidents, loading } = useApi('/api/incidents?limit=50', { interval: 10000 });
  const [selectedIncident, setSelectedIncident] = useState(null);

  if (loading && !incidents) return <div className="empty-state">Loading incidents...</div>;

  const totalIncidents = incidents?.length || 0;
  const activeIncidents = incidents?.filter(i => i.status !== 'resolved')?.length || 0;

  if (selectedIncident) {
    return <Timeline incidentId={selectedIncident} onBack={() => setSelectedIncident(null)} />;
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
