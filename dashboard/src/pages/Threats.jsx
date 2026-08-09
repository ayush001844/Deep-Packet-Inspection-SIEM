import { useState } from 'react';
import { useApi, apiPost } from '../hooks/useApi';
import { ShieldAlert, MapPin, Target, Activity, Search, AlertTriangle, ShieldCheck, Bot } from 'lucide-react';
import StatCard from '../components/StatCard';
import AIAssistantModal from '../components/AIAssistantModal';

export default function Threats() {
  const { data: alerts, loading } = useApi('/api/alerts?limit=50', { interval: 5000 });
  const { data: stats } = useApi('/api/stats', { interval: 5000 });
  
  const [lookupIp, setLookupIp] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);

  if (loading && !alerts) return <div className="empty-state">Loading threat intelligence...</div>;

  const totalAlerts = alerts?.length || 0;
  const criticalAlerts = alerts?.filter(a => a.severity === 'critical')?.length || 0;
  const highAlerts = alerts?.filter(a => a.severity === 'high')?.length || 0;

  const handleLookup = async () => {
    if (!lookupIp) return;
    setIsLookingUp(true);
    try {
      const res = await fetch(`/api/threats/lookup?ip=${encodeURIComponent(lookupIp)}`);
      if (res.ok) {
        setLookupResult(await res.json());
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsLookingUp(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="stat-grid">
        <StatCard 
          title="Total Threats Detected" 
          value={totalAlerts} 
          icon={ShieldAlert}
          color="var(--accent)"
        />
        <StatCard 
          title="Critical Alerts" 
          value={criticalAlerts} 
          icon={Target}
          color="var(--critical)"
          bg="var(--critical-bg)"
        />
        <StatCard 
          title="High Severity" 
          value={highAlerts} 
          icon={Activity}
          color="var(--high)"
          bg="var(--high-bg)"
        />
        <StatCard 
          title="Active Feeds" 
          value="3" 
          icon={MapPin}
          color="var(--success)"
          bg="var(--success-bg)"
        />
      </div>

      <div className="card mt-4">
        <div className="card-header">
          <h3 className="card-title"><Search size={18} /> OSINT IP Lookup</h3>
        </div>
        <div style={{ padding: '20px' }}>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
            <input 
              type="text" 
              className="input" 
              placeholder="Enter IP address (e.g. 185.x.x.x)" 
              value={lookupIp}
              onChange={e => setLookupIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleLookup()}
              style={{ width: '300px' }}
            />
            <button className="btn btn-primary" onClick={handleLookup} disabled={isLookingUp}>
              {isLookingUp ? 'Searching...' : 'Lookup'}
            </button>
          </div>

          {lookupResult && (
            <div>
              {lookupResult.data_source === 'simulated' && (
                <div style={{
                  padding: '10px 16px',
                  marginBottom: '12px',
                  backgroundColor: 'rgba(245, 158, 11, 0.1)',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  borderRadius: '8px',
                  color: '#f59e0b',
                  fontSize: '0.85rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <AlertTriangle size={16} />
                  External intel results are simulated. Connect real API keys (VirusTotal, AbuseIPDB) via environment variables for live data.
                </div>
              )}
              <div style={{ 
                padding: '16px', 
                borderRadius: '8px', 
                backgroundColor: lookupResult.summary === 'Malicious' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
                border: `1px solid ${lookupResult.summary === 'Malicious' ? 'var(--critical)' : 'var(--success)'}`,
                display: 'flex',
                gap: '16px'
              }}>
                <div style={{ marginTop: '2px' }}>
                  {lookupResult.summary === 'Malicious' 
                    ? <AlertTriangle size={24} color="var(--critical)" />
                    : <ShieldCheck size={24} color="var(--success)" />
                  }
                </div>
                <div style={{ flex: 1 }}>
                  <h4 style={{ margin: '0 0 8px 0', fontSize: '1.1rem', color: lookupResult.summary === 'Malicious' ? 'var(--critical)' : 'var(--success)' }}>
                    {lookupResult.ip} - {lookupResult.summary}
                  </h4>
                  
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '12px' }}>
                    <div className="card" style={{ padding: '12px' }}>
                      <div className="text-sm text-muted mb-2 font-medium">Local Feeds (Blocklists)</div>
                      <div>Hit Count: <strong>{lookupResult.local_feeds.feeds_hit.length}</strong></div>
                      <div>Score: <strong>{lookupResult.local_feeds.score}/10</strong></div>
                      {lookupResult.local_feeds.feeds_hit.length > 0 && (
                        <div className="text-sm mt-1" style={{ color: 'var(--critical)' }}>
                          Found in: {lookupResult.local_feeds.feeds_hit.join(', ')}
                        </div>
                      )}
                    </div>
                    <div className="card" style={{ padding: '12px' }}>
                      <div className="text-sm text-muted mb-2 font-medium">External Intel {lookupResult.data_source === 'simulated' ? '(Simulated)' : ''}</div>
                      <div>VirusTotal: <strong>{lookupResult.external_intel.virustotal.malicious}/{lookupResult.external_intel.virustotal.total}</strong></div>
                      <div>AbuseIPDB Confidence: <strong>{lookupResult.external_intel.abuseipdb.confidence_score}%</strong></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="card mt-4">
        <div className="card-header">
          <h3 className="card-title">Threat Intelligence Feed</h3>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Time</th>
                <th>Threat Details</th>
                <th>Source IP</th>
                <th>Target IP</th>
                <th>Source</th>
                <th>AI Analysis</th>
              </tr>
            </thead>
            <tbody>
              {alerts && alerts.length > 0 ? (
                alerts.map(alert => (
                  <tr key={alert.id}>
                    <td>
                      <span className={`severity-badge ${alert.severity.toLowerCase()}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="text-muted text-sm">{new Date(alert.timestamp * 1000).toLocaleString()}</td>
                    <td className="font-medium">{alert.title} <div className="text-sm text-muted mt-1">{alert.description}</div></td>
                    <td className="font-mono text-sm">{alert.src_ip}</td>
                    <td className="font-mono text-sm">{alert.dst_ip}</td>
                    <td className="text-sm text-muted">{alert.source}</td>
                    <td>
                      <button 
                        className="btn btn-sm" 
                        style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '4px 8px', fontSize: '0.75rem', backgroundColor: 'rgba(0,255,213,0.1)', color: 'var(--accent)', border: '1px solid var(--accent)' }}
                        onClick={() => setSelectedAlert(alert)}
                      >
                        <Bot size={14} /> Ask AI
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="6" className="empty-state" style={{ height: 200 }}>
                    <ShieldAlert size={40} />
                    <h3>No threats detected</h3>
                    <p>Network traffic is clean.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      
      {/* AI Modal */}
      <AIAssistantModal 
        alert={selectedAlert} 
        onClose={() => setSelectedAlert(null)} 
      />
    </div>
  );
}
