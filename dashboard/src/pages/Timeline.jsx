import { useApi } from '../hooks/useApi';
import { ArrowLeft, GitCommit, ShieldAlert, Download } from 'lucide-react';

export default function Timeline({ incidentId, onBack }) {
  const { data, loading } = useApi(`/api/incidents/${incidentId}/timeline`);

  if (loading) return <div className="empty-state">Loading timeline...</div>;
  if (!data || data.error) return <div className="empty-state">Failed to load timeline.</div>;

  return (
    <div className="fade-in">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button className="btn btn-secondary" onClick={onBack} style={{ padding: '8px' }}>
            <ArrowLeft size={18} />
          </button>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>{data.title}</h2>
            <div className="text-sm text-muted" style={{ display: 'flex', gap: '10px', marginTop: '5px' }}>
              <span className="badge" style={{ backgroundColor: 'var(--bg-secondary)' }}>ID: {data.incident_id}</span>
              <span className={`severity-badge ${data.severity.toLowerCase()}`}>{data.severity.toUpperCase()}</span>
            </div>
          </div>
        </div>
        
        <a 
          href={`http://localhost:8000/api/incidents/${data.incident_id}/report`}
          target="_blank" 
          rel="noreferrer"
          className="btn btn-primary" 
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          <Download size={16} /> Export PDF Report
        </a>
      </div>

      <div className="card mb-4">
        <div className="card-header">
          <h3 className="card-title">MITRE ATT&CK Stages Identified</h3>
        </div>
        <div style={{ padding: '20px', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {data.attack_stages.length > 0 ? (
            data.attack_stages.map((stage, i) => (
              <span key={i} className="badge" style={{ backgroundColor: 'var(--primary-bg)', color: 'var(--primary)', padding: '6px 12px' }}>
                {stage}
              </span>
            ))
          ) : (
            <span className="text-muted">No specific ATT&CK tactics identified yet.</span>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Attack Timeline ({data.alert_count} Events)</h3>
        </div>
        <div style={{ padding: '20px' }}>
          {data.timeline.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', position: 'relative' }}>
              {/* Vertical line */}
              <div style={{ position: 'absolute', left: '15px', top: '20px', bottom: '20px', width: '2px', backgroundColor: 'var(--border)' }}></div>
              
              {data.timeline.map((event, idx) => (
                <div key={idx} style={{ display: 'flex', gap: '20px', position: 'relative', zIndex: 1 }}>
                  <div style={{ 
                    width: '32px', height: '32px', borderRadius: '50%', 
                    backgroundColor: 'var(--bg-secondary)', border: '2px solid var(--border)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 
                  }}>
                    <GitCommit size={16} color="var(--text-muted)" />
                  </div>
                  <div style={{ flex: 1, backgroundColor: 'var(--bg-secondary)', padding: '15px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                      <span className="font-medium" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        {event.severity === 'critical' || event.severity === 'high' ? <ShieldAlert size={14} color="var(--critical)" /> : null}
                        {event.event}
                      </span>
                      <span className="text-sm text-muted font-mono">{new Date(event.timestamp * 1000).toLocaleString()}</span>
                    </div>
                    <p className="text-sm text-muted" style={{ margin: '0 0 10px 0', whiteSpace: 'pre-wrap' }}>{event.description}</p>
                    <div style={{ display: 'flex', gap: '10px' }}>
                      {event.stage !== 'Unknown' && (
                        <span className="badge" style={{ backgroundColor: 'var(--primary-bg)', color: 'var(--primary)', fontSize: '0.75rem' }}>
                          {event.stage}
                        </span>
                      )}
                      <span className="badge" style={{ backgroundColor: 'var(--bg)', fontSize: '0.75rem' }}>
                        Source: {event.source}
                      </span>
                    </div>
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
