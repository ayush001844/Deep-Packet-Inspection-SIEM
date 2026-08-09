import React, { useState, useRef } from 'react';
import { UploadCloud, AlertCircle, CheckCircle, Activity, Server, Shield, AlertTriangle, Target, Crosshair } from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip
} from 'recharts';

const PROTO_COLORS = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b', '#ef4444', '#06b6d4', '#ec4899'];

const VERDICT_STYLES = {
  'Critical Threat Detected': { class: 'verdict-critical', color: 'var(--critical)', icon: AlertCircle },
  'Possible Botnet / C2 Activity': { class: 'verdict-high', color: 'var(--high)', icon: AlertTriangle },
  'Suspicious Activity Detected': { class: 'verdict-high', color: 'var(--high)', icon: AlertTriangle },
  'Low-Level Anomalies Found': { class: 'verdict-medium', color: 'var(--medium)', icon: Target },
  'Clean Traffic': { class: 'verdict-clean', color: 'var(--success)', icon: CheckCircle },
};

export default function PcapAnalysis() {
  const [file, setFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setIsUploading(true);
    setError(null);
    setResults(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/pcap/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const data = await response.json();
      if (data.error) {
        throw new Error(data.error);
      }
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setIsUploading(false);
    }
  };

  const ts = results?.threat_summary;
  const verdictStyle = ts ? (VERDICT_STYLES[ts.threat_verdict] || VERDICT_STYLES['Clean Traffic']) : null;
  const VerdictIcon = verdictStyle?.icon || CheckCircle;

  return (
    <div className="fade-in" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column', gap: '20px', overflowY: 'auto' }}>
      
      {!results ? (
        <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ textAlign: 'center', maxWidth: '600px' }}>
            <h2 style={{ fontSize: '1.75rem', marginBottom: '10px' }}>PCAP Intelligence Analysis</h2>
            <p className="text-muted" style={{ marginBottom: '30px' }}>
              Upload a .pcap or .pcapng file for deep threat analysis with MITRE ATT&CK mapping.
            </p>

            <div 
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current.click()}
              style={{
                border: `2px dashed ${isDragging ? 'var(--primary)' : 'var(--border)'}`,
                borderRadius: '12px',
                padding: '60px 40px',
                backgroundColor: isDragging ? 'rgba(59, 130, 246, 0.05)' : 'var(--bg-secondary)',
                cursor: 'pointer',
                transition: 'all 0.2s',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '15px'
              }}
            >
              <UploadCloud size={48} className={isDragging ? 'text-primary' : 'text-muted'} />
              {file ? (
                <div>
                  <h4 style={{ margin: '0 0 5px 0' }}>{file.name}</h4>
                  <p className="text-sm text-muted" style={{ margin: 0 }}>{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              ) : (
                <div>
                  <h4 style={{ margin: '0 0 5px 0' }}>Drag & Drop file here</h4>
                  <p className="text-sm text-muted" style={{ margin: 0 }}>or click to browse files</p>
                </div>
              )}
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={handleFileChange} 
                accept=".pcap,.pcapng" 
                style={{ display: 'none' }} 
              />
            </div>

            {error && (
              <div style={{ marginTop: '20px', padding: '15px', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '10px', justifyContent: 'center' }}>
                <AlertCircle size={18} /> {error}
              </div>
            )}

            <button 
              className="btn btn-primary" 
              style={{ marginTop: '30px', padding: '12px 30px', fontSize: '1rem', width: '100%' }}
              onClick={handleUpload}
              disabled={!file || isUploading}
            >
              {isUploading ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Activity className="spin" size={18} /> Analyzing File...
                </span>
              ) : (
                'Upload and Analyze'
              )}
            </button>
          </div>
        </div>
      ) : (
        <>
          {/* ── Analysis Complete Banner ── */}
          <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
              <div style={{ padding: '12px', backgroundColor: 'rgba(16, 185, 129, 0.1)', borderRadius: '12px', color: '#10b981' }}>
                <CheckCircle size={24} />
              </div>
              <div>
                <h3 style={{ margin: '0 0 5px 0' }}>Analysis Complete</h3>
                <p className="text-sm text-muted" style={{ margin: 0 }}>
                  Processed <strong>{results.total_packets?.toLocaleString()}</strong> packets from {results.file} in {results.analysis_time_seconds}s
                </p>
              </div>
            </div>
            <button className="btn btn-secondary" onClick={() => { setResults(null); setFile(null); }}>
              Analyze Another File
            </button>
          </div>

          {/* ── Threat Intelligence Summary ── */}
          {ts && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px' }}>
              {/* Verdict Card */}
              <div className={`threat-verdict-card ${verdictStyle.class}`}>
                <VerdictIcon size={40} color={verdictStyle.color} style={{ marginBottom: 12 }} />
                <h3 style={{ margin: '0 0 8px 0', fontSize: '1.1rem', color: verdictStyle.color }}>{ts.threat_verdict}</h3>
                <p className="text-muted text-sm" style={{ margin: 0 }}>
                  {ts.suspicious_count} suspicious events • {ts.critical_count} critical • {ts.high_count} high
                </p>
              </div>

              {/* Risk Indicators */}
              <div className="card" style={{ padding: '20px' }}>
                <h4 style={{ margin: '0 0 14px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Crosshair size={16} color="var(--high)" />
                  Risk Indicators
                </h4>
                {ts.risk_indicators && ts.risk_indicators.length > 0 ? (
                  ts.risk_indicators.slice(0, 4).map((ri, i) => (
                    <div key={i} className="risk-indicator-item">
                      <span className={`severity-badge ${ri.severity}`} style={{ fontSize: '0.65rem' }}>
                        {ri.severity?.toUpperCase()}
                      </span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: '0.85rem', fontWeight: 500 }}>{ri.classification}</div>
                        {ri.mitre_technique && (
                          <span className="text-muted text-sm" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                            {ri.mitre_technique} • {ri.mitre_tactic}
                          </span>
                        )}
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="text-muted text-sm">No risk indicators found</p>
                )}
              </div>

              {/* Top Talkers */}
              <div className="card" style={{ padding: '20px' }}>
                <h4 style={{ margin: '0 0 14px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Shield size={16} color="var(--accent)" />
                  Top Talkers
                </h4>
                {ts.top_talkers && ts.top_talkers.length > 0 ? (
                  ts.top_talkers.map((tt, i) => {
                    const maxBytes = ts.top_talkers[0]?.total_bytes || 1;
                    const pct = Math.round((tt.total_bytes / maxBytes) * 100);
                    const barColor = tt.threat_verdict === 'Malicious' ? 'var(--critical)' 
                      : tt.threat_verdict === 'Suspicious' ? 'var(--high)' : 'var(--accent)';
                    return (
                      <div key={i} style={{ marginBottom: 10 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem' }}>{tt.ip}</span>
                          <span className={`severity-badge ${tt.threat_verdict === 'Malicious' ? 'critical' : tt.threat_verdict === 'Suspicious' ? 'high' : 'low'}`}
                            style={{ fontSize: '0.6rem' }}>
                            {tt.threat_verdict}
                          </span>
                        </div>
                        <div className="top-talker-bar">
                          <div className="top-talker-bar-fill" style={{ width: `${pct}%`, backgroundColor: barColor }} />
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-muted text-sm">No endpoint data</p>
                )}
              </div>
            </div>
          )}

          {/* ── Protocol Hierarchy (Pie Chart) + Endpoints ── */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            {/* Protocol Pie Chart */}
            <div className="card">
              <div className="card-header"><h3 className="card-title">Protocol Distribution</h3></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '20px', padding: '10px 0' }}>
                <div style={{ width: 200, height: 200 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={results.protocol_hierarchy}
                        dataKey="count"
                        nameKey="protocol"
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={85}
                        paddingAngle={2}
                      >
                        {results.protocol_hierarchy.map((_, i) => (
                          <Cell key={i} fill={PROTO_COLORS[i % PROTO_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8, fontSize: '0.85rem' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ flex: 1 }}>
                  {results.protocol_hierarchy.map((proto, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                      <div style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: PROTO_COLORS[i % PROTO_COLORS.length], flexShrink: 0 }} />
                      <span style={{ flex: 1, fontSize: '0.85rem' }}>{proto.protocol}</span>
                      <span className="text-muted text-sm" style={{ fontFamily: 'JetBrains Mono, monospace' }}>{proto.percentage}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Top Endpoints */}
            <div className="card">
              <div className="card-header"><h3 className="card-title">Top Endpoints</h3></div>
              <table style={{ width: '100%', marginTop: '10px' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '10px', color: 'var(--text-muted)' }}>IP Address</th>
                    <th style={{ textAlign: 'right', padding: '10px', color: 'var(--text-muted)' }}>Bytes Sent</th>
                    <th style={{ textAlign: 'right', padding: '10px', color: 'var(--text-muted)' }}>Bytes Recv</th>
                  </tr>
                </thead>
                <tbody>
                  {results.endpoints.slice(0, 10).map((ep, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '10px', fontFamily: 'monospace' }}>{ep.ip}</td>
                      <td style={{ padding: '10px', textAlign: 'right', color: '#10b981' }}>{(ep.sent_bytes / 1024).toFixed(1)} KB</td>
                      <td style={{ padding: '10px', textAlign: 'right', color: '#3b82f6' }}>{(ep.recv_bytes / 1024).toFixed(1)} KB</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* PCAP Alerts Table */}
            {ts && ts.alerts && ts.alerts.length > 0 && (
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div className="card-header">
                  <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <AlertTriangle size={16} color="var(--high)" />
                    Detected Threats ({ts.alerts.length})
                  </h3>
                </div>
                <div className="table-container" style={{ maxHeight: 300, overflowY: 'auto' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Classification</th>
                        <th>Alert</th>
                        <th>MITRE</th>
                        <th>Source IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ts.alerts.map((a, i) => (
                        <tr key={i}>
                          <td>
                            <span className={`severity-badge ${(a.severity || '').toLowerCase()}`}>
                              {(a.severity || '').toUpperCase()}
                            </span>
                          </td>
                          <td className="font-medium">{a.classification || '—'}</td>
                          <td>{a.title}</td>
                          <td>
                            {a.mitre_technique && (
                              <span className="mitre-badge" style={{
                                fontSize: '0.7rem', fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                                background: 'hsla(210, 100%, 55%, 0.12)', color: 'var(--accent)',
                                fontFamily: 'JetBrains Mono, monospace'
                              }}>
                                {a.mitre_technique}
                              </span>
                            )}
                          </td>
                          <td className="font-mono text-sm">{a.src_ip}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            
            {/* DNS Queries */}
            {results.dns_queries && results.dns_queries.length > 0 && (
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div className="card-header"><h3 className="card-title">DNS Queries ({results.dns_queries.length})</h3></div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', marginTop: '15px' }}>
                  {results.dns_queries.slice(0, 50).map((dns, i) => (
                    <div key={i} style={{ padding: '8px 12px', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Server size={14} className="text-muted" />
                      <span className="text-muted text-xs">[{dns.type}]</span>
                      <span>{dns.query}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}
      
      <style>{`
        .spin {
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
