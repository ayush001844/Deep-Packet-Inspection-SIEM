import { useState, useEffect } from 'react';
import { useApi, apiPost, useWebSocket } from '../hooks/useApi';
import { Play, Square, Pause, RotateCcw, Filter, Activity, AlertTriangle, Terminal } from 'lucide-react';

export default function LiveCapture() {
  const { data: interfaces, refetch: refetchInterfaces } = useApi('/api/interfaces');
  const { data: status, refetch: refetchStatus } = useApi('/api/capture/status', { interval: 2000 });
  const { packets, connected, connect, disconnect, clearPackets } = useWebSocket('/ws/packets');
  
  const [selectedIface, setSelectedIface] = useState('');
  const [bpfFilter, setBpfFilter] = useState('');
  const [captureError, setCaptureError] = useState('');
  
  const isRunning = status?.running || false;
  const isPaused = status?.paused || false;

  useEffect(() => {
    if (isRunning && !connected) {
      connect();
    } else if (!isRunning && connected) {
      // Keep connected to view history, or could disconnect
    }
  }, [isRunning, connected, connect]);

  // Sync background thread errors to the UI
  useEffect(() => {
    if (status?.error) {
      setCaptureError(status.error);
    }
  }, [status?.error]);

  useEffect(() => {
    // Auto-select the first interface when the list loads
    if (interfaces && interfaces.length > 0 && !selectedIface) {
      // Prefer en0 (Wi-Fi on Mac), then first available
      const preferred = interfaces.find(i => i.name === 'en0') || interfaces[0];
      setSelectedIface(preferred.name);
    }
  }, [interfaces]);

  // Sort interfaces: common ones first
  const sortedInterfaces = interfaces ? [...interfaces].sort((a, b) => {
    const priority = ['en0', 'en1', 'lo0', 'en2', 'en3', 'bridge0'];
    const ai = priority.indexOf(a.name);
    const bi = priority.indexOf(b.name);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;
    return a.name.localeCompare(b.name);
  }) : [];

  const handleStart = async () => {
    // If no interface selected yet, auto-pick en0 or first available
    const iface = selectedIface || (sortedInterfaces[0]?.name) || 'en0';
    if (!iface) { setCaptureError('Please select a network interface first.'); return; }
    clearPackets();
    setCaptureError('');
    try {
      const res = await fetch(`/api/capture/start?interface=${iface}&bpf_filter=${encodeURIComponent(bpfFilter)}`, {
        method: 'POST',
      });
      if (!res.ok) {
        const err = await res.json();
        setCaptureError(err.detail || 'Failed to start capture');
        return;
      }
      setSelectedIface(iface);
      refetchStatus();
      connect();
    } catch (e) {
      setCaptureError('Could not reach backend — is it running?');
    }
  };

  const handleStop = async () => {
    await apiPost('/api/capture/stop');
    refetchStatus();
  };

  const handlePause = async () => {
    await apiPost(isPaused ? '/api/capture/resume' : '/api/capture/pause');
    refetchStatus();
  };

  const getProtoClass = (proto) => proto ? proto.toLowerCase() : '';

  return (
    <div className="fade-in flex-col" style={{ height: '100%', display: 'flex', gap: 20 }}>
      
      {/* ── Permission Error Banner ── */}
      {captureError && (
        <div style={{
          padding: '16px 20px',
          backgroundColor: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.4)',
          borderRadius: '10px',
          display: 'flex',
          gap: '14px',
          alignItems: 'flex-start',
        }}>
          <AlertTriangle size={22} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <p style={{ margin: '0 0 8px 0', fontWeight: 600, color: '#ef4444' }}>
              Capture Failed — Permission Denied
            </p>
            <p style={{ margin: '0 0 12px 0', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
              Scapy requires <strong>root privileges</strong> to sniff packets on macOS (<code>/dev/bpf</code>).
              Stop the current backend and restart it with <code>sudo</code>:
            </p>
            <div style={{
              display: 'flex', alignItems: 'center', gap: '10px',
              backgroundColor: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '10px 14px',
            }}>
              <Terminal size={16} color="#10b981" style={{ flexShrink: 0 }} />
              <code style={{ fontSize: '0.85rem', color: '#10b981', wordBreak: 'break-all' }}>
                cd "/Users/ayush/DEEP PACKET INSPECTION" &amp;&amp; sudo venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
              </code>
            </div>
          </div>
        </div>
      )}

      {/* ── Control Panel ── */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div>
              <label className="text-sm text-muted block mb-1">Interface</label>
              <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                <select 
                  value={selectedIface} 
                  onChange={e => setSelectedIface(e.target.value)}
                  disabled={isRunning}
                  className="input"
                  style={{ width: 160, cursor: 'pointer' }}
                >
                  {!sortedInterfaces || sortedInterfaces.length === 0 ? (
                    <option value="">Loading...</option>
                  ) : (
                    sortedInterfaces.map(iface => (
                      <option key={iface.name} value={iface.name}>
                        {iface.name}
                      </option>
                    ))
                  )}
                </select>
                <button
                  className="btn btn-secondary"
                  onClick={refetchInterfaces}
                  disabled={isRunning}
                  title="Refresh interface list"
                  style={{ padding: '8px', minWidth: 'unset' }}
                >
                  <RotateCcw size={14} />
                </button>
              </div>
            </div>
            
            <div>
              <label className="text-sm text-muted block mb-1">BPF Filter (optional)</label>
              <div className="relative" style={{ display: 'flex', alignItems: 'center' }}>
                <Filter size={14} className="text-muted" style={{ position: 'absolute', left: 10 }} />
                <input 
                  type="text" 
                  className="input" 
                  placeholder="e.g. tcp port 80" 
                  value={bpfFilter}
                  onChange={e => setBpfFilter(e.target.value)}
                  disabled={isRunning}
                  style={{ width: 250, paddingLeft: 30 }}
                />
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="mr-4 text-right">
              <div className="text-sm text-muted">Status</div>
              <div className="flex items-center gap-2">
                {isRunning ? (
                  isPaused ? <span className="status-badge paused">Paused</span>
                           : <span className="status-badge running">Capturing</span>
                ) : (
                  <span className="status-badge stopped">Stopped</span>
                )}
              </div>
            </div>

            {!isRunning ? (
              <button className="btn btn-primary" onClick={handleStart}>
                <Play size={16} fill="currentColor" /> Start Capture
              </button>
            ) : (
              <>
                <button className="btn btn-secondary" onClick={handlePause}>
                  {isPaused ? <Play size={16} /> : <Pause size={16} />} 
                  {isPaused ? 'Resume' : 'Pause'}
                </button>
                <button className="btn btn-danger" onClick={handleStop}>
                  <Square size={16} fill="currentColor" /> Stop
                </button>
              </>
            )}
            <button className="btn btn-secondary" onClick={clearPackets} title="Clear view">
              <RotateCcw size={16} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Packet Stream ── */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        <div className="card-header" style={{ padding: '16px 20px', margin: 0, borderBottom: '1px solid var(--border-default)', backgroundColor: 'var(--bg-elevated)' }}>
          <h3 className="card-title flex items-center gap-2">
            <Activity size={16} /> 
            Live Packet Stream 
            <span className="text-muted text-sm" style={{ fontWeight: 'normal' }}>
              ({packets.length} packets buffered)
            </span>
          </h3>
        </div>
        
        <div className="table-container" style={{ flex: 1, border: 'none', borderRadius: 0 }}>
          <table>
            <thead>
              <tr>
                <th style={{ width: 80 }}>No.</th>
                <th style={{ width: 100 }}>Time</th>
                <th style={{ width: 140 }}>Source</th>
                <th style={{ width: 140 }}>Destination</th>
                <th style={{ width: 80 }}>Protocol</th>
                <th style={{ width: 80 }}>Length</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody>
              {packets.length > 0 ? (
                packets.map((pkt, i) => (
                  <tr key={pkt.id || i}>
                    <td className="text-muted">{pkt.id}</td>
                    <td className="font-mono text-sm">{new Date(pkt.timestamp * 1000).toISOString().split('T')[1].slice(0,-1)}</td>
                    <td className="font-mono text-sm">{pkt.src_ip || pkt.src_mac || '-'} {pkt.src_port ? `:${pkt.src_port}` : ''}</td>
                    <td className="font-mono text-sm">{pkt.dst_ip || pkt.dst_mac || '-'} {pkt.dst_port ? `:${pkt.dst_port}` : ''}</td>
                    <td>
                      <span className={`proto-badge ${getProtoClass(pkt.protocol)}`}>
                        {pkt.protocol || 'Unknown'}
                      </span>
                    </td>
                    <td>{pkt.length}</td>
                    <td className="text-sm truncate" style={{ maxWidth: 300 }} title={pkt.summary}>
                      {(() => {
                        // Check for HTTP
                        const http = pkt.layers?.find(l => l.layer === 'HTTP' && l.direction === 'request');
                        if (http) return <span style={{ color: 'var(--accent)' }}>{http.method} {http.host}{http.url}</span>;
                        
                        // Check for DNS
                        const dns = pkt.layers?.find(l => l.layer === 'DNS' && l.type === 'query');
                        if (dns) return <span style={{ color: 'var(--warning)' }}>DNS: {dns.query_name}</span>;
                        
                        // Check for TLS SNI
                        if (pkt.sni) return <span style={{ color: 'var(--success)' }}>TLS SNI: {pkt.sni}</span>;
                        
                        // Fallback
                        return pkt.summary;
                      })()}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="7" className="empty-state" style={{ height: 300 }}>
                    <Activity size={48} />
                    <h3>No packets captured yet</h3>
                    <p>Select an interface and start capturing.</p>
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
