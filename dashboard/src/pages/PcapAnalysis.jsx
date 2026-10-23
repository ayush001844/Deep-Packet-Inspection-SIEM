import React, { useState, useRef, useCallback } from 'react';
import {
  UploadCloud, AlertCircle, CheckCircle, Activity, Server, Shield,
  AlertTriangle, Target, Crosshair, FileText, Play, X, RefreshCw,
  Download, Printer, Info, Loader
} from 'lucide-react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis
} from 'recharts';
import { useApi } from '../hooks/useApi';

const PROTO_COLORS = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b', '#ef4444', '#06b6d4', '#ec4899'];
const MAX_FILE_MB = 50;
const ALLOWED_EXT = ['.pcap', '.pcapng'];

const VERDICT_STYLES = {
  'Critical Threat Detected':      { cls: 'verdict-critical', color: 'var(--critical)',  icon: AlertCircle },
  'Possible Botnet / C2 Activity': { cls: 'verdict-high',     color: 'var(--high)',       icon: AlertTriangle },
  'Suspicious Activity Detected':  { cls: 'verdict-high',     color: 'var(--high)',       icon: AlertTriangle },
  'Low-Level Anomalies Found':     { cls: 'verdict-medium',   color: 'var(--medium)',     icon: Target },
  'Clean Traffic':                 { cls: 'verdict-clean',    color: 'var(--success)',    icon: CheckCircle },
};

// ── Status badge component ────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    idle:       { label: 'Ready',      color: 'var(--text-muted)',   bg: 'var(--bg-elevated)', icon: Info },
    validating: { label: 'Validating', color: 'var(--accent)',       bg: 'rgba(59,130,246,.1)', icon: Loader },
    uploading:  { label: 'Uploading',  color: 'var(--accent)',       bg: 'rgba(59,130,246,.1)', icon: Loader },
    analysing:  { label: 'Analysing',  color: '#f59e0b',             bg: 'rgba(245,158,11,.1)', icon: Activity },
    completed:  { label: 'Completed',  color: 'var(--success)',      bg: 'rgba(16,185,129,.1)', icon: CheckCircle },
    error:      { label: 'Failed',     color: 'var(--critical)',     bg: 'rgba(239,68,68,.1)',  icon: AlertCircle },
  };
  const s = map[status] || map.idle;
  const Icon = s.icon;
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 10px', borderRadius: 20, fontSize: '0.75rem', fontWeight: 600,
      color: s.color, background: s.bg,
    }}>
      <Icon size={12} className={['uploading','analysing','validating'].includes(status) ? 'spin' : ''} />
      {s.label}
    </span>
  );
}

// ── Upload progress bar ───────────────────────────────────────────────────────
function ProgressBar({ pct }) {
  return (
    <div style={{ background: 'var(--bg-secondary)', borderRadius: 4, overflow: 'hidden', height: 6, marginTop: 8 }}>
      <div style={{
        height: '100%', borderRadius: 4,
        width: `${pct}%`,
        background: 'linear-gradient(90deg, var(--accent), #10b981)',
        transition: 'width 0.3s ease',
      }} />
    </div>
  );
}

// ── Humanise bytes ────────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

// ── Friendly error messages ───────────────────────────────────────────────────
function friendlyError(msg = '') {
  if (!msg) return 'An unexpected error occurred.';
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('ERR_CONNECTION'))
    return 'Cannot reach the backend. Make sure the server is running on port 8000.';
  if (msg.includes('401') || msg.includes('Unauthorized'))
    return 'Session expired. Please log in again.';
  if (msg.includes('413') || msg.includes('too large'))
    return `File exceeds the ${MAX_FILE_MB} MB limit. Try a smaller capture.`;
  if (msg.includes('Invalid file type') || msg.includes('not a pcap'))
    return 'Only .pcap and .pcapng files are supported. Rename or re-export your capture.';
  if (msg.includes('corrupt') || msg.includes('parse'))
    return 'The file could not be parsed. It may be corrupt or in an unsupported PCAP variant.';
  return msg;
}

export default function PcapAnalysis() {
  const [file, setFile]           = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [status, setStatus]       = useState('idle');  // idle | validating | uploading | analysing | completed | error
  const [progress, setProgress]   = useState(0);
  const [results, setResults]     = useState(null);
  const [error, setError]         = useState(null);
  const fileInputRef              = useRef(null);
  const xhrRef                    = useRef(null);

  const { data: samplesData } = useApi('/api/pcap/samples');
  const samples = samplesData?.samples || [];

  // ── File validation ─────────────────────────────────────────────────────────
  const validateFile = useCallback((f) => {
    if (!f) return 'No file selected.';
    const ext = f.name.slice(f.name.lastIndexOf('.')).toLowerCase();
    if (!ALLOWED_EXT.includes(ext))
      return `Invalid file type "${ext}". Please select a .pcap or .pcapng file.`;
    if (f.size > MAX_FILE_MB * 1024 * 1024)
      return `File is too large (${fmtBytes(f.size)}). Maximum is ${MAX_FILE_MB} MB.`;
    return null;
  }, []);

  const pickFile = useCallback((f) => {
    if (!f) return;
    setError(null);
    setResults(null);
    setStatus('validating');
    const err = validateFile(f);
    if (err) { setError(err); setStatus('error'); return; }
    setFile(f);
    setStatus('idle');
  }, [validateFile]);

  const handleDragOver  = (e) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = (e) => { e.preventDefault(); setIsDragging(false); };
  const handleDrop      = (e) => { e.preventDefault(); setIsDragging(false); pickFile(e.dataTransfer.files?.[0]); };
  const handleFileChange = (e) => pickFile(e.target.files?.[0]);

  const reset = () => {
    xhrRef.current?.abort();
    setFile(null); setResults(null); setError(null);
    setStatus('idle'); setProgress(0);
  };

  // ── XHR upload with progress ────────────────────────────────────────────────
  const handleUpload = () => {
    if (!file || status === 'uploading' || status === 'analysing') return;
    setError(null); setResults(null); setProgress(0); setStatus('uploading');

    const formData = new FormData();
    formData.append('file', file);

    const token = localStorage.getItem('token');
    const xhr = new XMLHttpRequest();
    xhrRef.current = xhr;

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 80); // 0-80% for upload
        setProgress(pct);
        if (pct >= 80) setStatus('analysing');
      }
    };

    xhr.onload = () => {
      setProgress(100);
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status >= 400 || data.error || data.analysis_status === 'error') {
          setError(friendlyError(data.error || `Server error ${xhr.status}`));
          setStatus('error');
        } else {
          setResults(data);
          setStatus('completed');
        }
      } catch {
        setError('Server returned an unexpected response. Please try again.');
        setStatus('error');
      }
    };

    xhr.onerror = () => {
      setError(friendlyError('Failed to fetch'));
      setStatus('error');
    };

    xhr.onabort = () => setStatus('idle');

    xhr.open('POST', '/api/pcap/upload');
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.send(formData);
  };

  // ── Analyse a bundled sample ─────────────────────────────────────────────────
  const handleSample = async (filename) => {
    setError(null); setResults(null); setFile(null);
    setStatus('analysing'); setProgress(0);
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`/api/pcap/analyse-sample/${encodeURIComponent(filename)}`, {
        method: 'POST',
        headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      });
      setProgress(100);
      const data = await res.json();
      if (!res.ok || data.error || data.analysis_status === 'error') {
        setError(friendlyError(data.detail || data.error || `Error ${res.status}`));
        setStatus('error');
      } else {
        setResults(data);
        setStatus('completed');
      }
    } catch (err) {
      setError(friendlyError(err.message));
      setStatus('error');
    }
  };

  const ts = results?.threat_summary;
  const verdictStyle = ts ? (VERDICT_STYLES[ts.threat_verdict] || VERDICT_STYLES['Clean Traffic']) : null;
  const VerdictIcon  = verdictStyle?.icon || CheckCircle;

  const isProcessing = status === 'uploading' || status === 'analysing';

  return (
    <div className="fade-in" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column', gap: 20, overflowY: 'auto' }}>

      {/* ── UPLOAD PANEL (always visible until results) ── */}
      {!results && (
        <div className="card" style={{ padding: '30px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
            <div>
              <h2 style={{ margin: '0 0 6px', fontSize: '1.4rem', display: 'flex', alignItems: 'center', gap: 10 }}>
                <UploadCloud size={22} color="var(--accent)" />
                PCAP Intelligence Analysis
              </h2>
              <p className="text-muted text-sm" style={{ margin: 0 }}>
                Upload a .pcap or .pcapng file (max {MAX_FILE_MB} MB) for full threat analysis with MITRE ATT&amp;CK mapping.
              </p>
            </div>
            <StatusBadge status={status} />
          </div>

          {/* ── Drop Zone ── */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !file && fileInputRef.current?.click()}
            style={{
              border: `2px dashed ${isDragging ? 'var(--accent)' : file ? 'var(--success)' : 'var(--border)'}`,
              borderRadius: 12,
              padding: '40px 30px',
              backgroundColor: isDragging ? 'rgba(59,130,246,.05)' : file ? 'rgba(16,185,129,.04)' : 'var(--bg-secondary)',
              cursor: file ? 'default' : 'pointer',
              transition: 'all 0.2s',
              textAlign: 'center',
              position: 'relative',
            }}
          >
            {file ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
                <FileText size={32} color="var(--success)" />
                <div style={{ textAlign: 'left' }}>
                  <p style={{ margin: '0 0 2px', fontWeight: 600 }}>{file.name}</p>
                  <p className="text-muted text-sm" style={{ margin: 0 }}>{fmtBytes(file.size)}</p>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); reset(); }}
                  style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}
                  title="Clear file"
                >
                  <X size={18} />
                </button>
              </div>
            ) : (
              <>
                <UploadCloud size={40} color={isDragging ? 'var(--accent)' : 'var(--text-muted)'} style={{ marginBottom: 12 }} />
                <p style={{ margin: '0 0 4px', fontWeight: 500 }}>Drag &amp; drop your PCAP here</p>
                <p className="text-muted text-sm" style={{ margin: 0 }}>or click to browse • .pcap / .pcapng • max {MAX_FILE_MB} MB</p>
              </>
            )}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".pcap,.pcapng"
              style={{ display: 'none' }}
            />
          </div>

          {/* ── Progress bar ── */}
          {isProcessing && <ProgressBar pct={progress} />}

          {/* ── Error message ── */}
          {error && (
            <div style={{
              marginTop: 16, padding: '12px 16px',
              backgroundColor: 'rgba(239,68,68,.1)', color: 'var(--critical)',
              borderRadius: 8, display: 'flex', alignItems: 'flex-start', gap: 10,
              border: '1px solid rgba(239,68,68,.2)',
            }}>
              <AlertCircle size={18} style={{ flexShrink: 0, marginTop: 1 }} />
              <span style={{ fontSize: '0.9rem' }}>{error}</span>
            </div>
          )}

          {/* ── Action buttons ── */}
          <div style={{ marginTop: 20, display: 'flex', gap: 12 }}>
            <button
              className="btn btn-primary"
              style={{ flex: 1, padding: '11px 0', fontSize: '0.95rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
              onClick={handleUpload}
              disabled={!file || isProcessing}
            >
              {isProcessing ? (
                <><Activity className="spin" size={16} /> {status === 'uploading' ? `Uploading… ${progress}%` : 'Analysing…'}</>
              ) : (
                <><Play size={16} /> Upload &amp; Analyse</>
              )}
            </button>
            {isProcessing && (
              <button className="btn btn-secondary" style={{ padding: '11px 16px' }} onClick={reset}>
                Cancel
              </button>
            )}
          </div>

          {/* ── Sample files section ── */}
          {samples.length > 0 && (
            <div style={{ marginTop: 28 }}>
              <p style={{ margin: '0 0 12px', fontSize: '0.85rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <Info size={14} />
                Don't have a capture? Try one of these bundled samples:
              </p>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {samples.map(s => (
                  <button
                    key={s.filename}
                    className="btn btn-secondary"
                    style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', fontSize: '0.85rem' }}
                    onClick={() => handleSample(s.filename)}
                    disabled={isProcessing}
                  >
                    <Play size={13} />
                    <span style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 1 }}>
                      <span style={{ fontWeight: 600 }}>{s.filename}</span>
                      <span className="text-muted" style={{ fontSize: '0.72rem', lineHeight: 1.2 }}>{s.description} • {fmtBytes(s.size_bytes)}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── RESULTS ── */}
      {results && (
        <>
          {/* Banner */}
          <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{ padding: 10, backgroundColor: 'rgba(16,185,129,.1)', borderRadius: 10, color: '#10b981' }}>
                <CheckCircle size={22} />
              </div>
              <div>
                <h3 style={{ margin: '0 0 3px' }}>Analysis Complete</h3>
                <p className="text-sm text-muted" style={{ margin: 0 }}>
                  Processed <strong>{results.total_packets?.toLocaleString()}</strong> packets
                  from <strong>{results.file}</strong>
                  {results.file_size_bytes ? ` (${fmtBytes(results.file_size_bytes)})` : ''}
                  {results.analysis_time_seconds != null ? ` in ${results.analysis_time_seconds}s` : ''}
                </p>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px' }}
                onClick={() => {
                  const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
                  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
                  a.download = `PCAP_Report_${results.file}.json`; a.click();
                }}>
                <Download size={14} /> Export JSON
              </button>
              <button className="btn btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px' }}
                onClick={() => window.print()}>
                <Printer size={14} /> Print
              </button>
              <button className="btn btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px' }}
                onClick={reset}>
                <RefreshCw size={14} /> New Analysis
              </button>
            </div>
          </div>

          {/* Threat summary row */}
          {ts && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 20 }}>
              {/* Verdict */}
              <div className={`threat-verdict-card ${verdictStyle.cls}`}>
                <VerdictIcon size={36} color={verdictStyle.color} style={{ marginBottom: 10 }} />
                <h3 style={{ margin: '0 0 6px', fontSize: '1rem', color: verdictStyle.color }}>{ts.threat_verdict}</h3>
                <p className="text-muted text-sm" style={{ margin: 0 }}>
                  {ts.suspicious_count} suspicious • {ts.critical_count} critical • {ts.high_count} high
                </p>
              </div>

              {/* Risk indicators */}
              <div className="card" style={{ padding: 20 }}>
                <h4 style={{ margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Crosshair size={15} color="var(--high)" /> Risk Indicators
                </h4>
                {ts.risk_indicators?.length > 0 ? (
                  ts.risk_indicators.slice(0, 4).map((ri, i) => (
                    <div key={i} className="risk-indicator-item">
                      <span className={`severity-badge ${ri.severity}`} style={{ fontSize: '0.63rem' }}>{ri.severity?.toUpperCase()}</span>
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
                ) : <p className="text-muted text-sm">No risk indicators found.</p>}
              </div>

              {/* Top talkers */}
              <div className="card" style={{ padding: 20 }}>
                <h4 style={{ margin: '0 0 14px', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Shield size={15} color="var(--accent)" /> Top Talkers
                </h4>
                {ts.top_talkers?.length > 0 ? (
                  ts.top_talkers.map((tt, i) => {
                    const maxB = ts.top_talkers[0]?.total_bytes || 1;
                    const pct  = Math.round((tt.total_bytes / maxB) * 100);
                    const barC = tt.threat_verdict === 'Malicious' ? 'var(--critical)'
                               : tt.threat_verdict === 'Suspicious' ? 'var(--high)' : 'var(--accent)';
                    return (
                      <div key={i} style={{ marginBottom: 10 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem' }}>{tt.ip}</span>
                          <span className={`severity-badge ${tt.threat_verdict === 'Malicious' ? 'critical' : tt.threat_verdict === 'Suspicious' ? 'high' : 'low'}`}
                            style={{ fontSize: '0.6rem' }}>{tt.threat_verdict}</span>
                        </div>
                        <div className="top-talker-bar">
                          <div className="top-talker-bar-fill" style={{ width: `${pct}%`, backgroundColor: barC }} />
                        </div>
                        <div className="text-muted" style={{ fontSize: '0.72rem', marginTop: 2 }}>{fmtBytes(tt.total_bytes)}</div>
                      </div>
                    );
                  })
                ) : <p className="text-muted text-sm">No endpoint data.</p>}
              </div>
            </div>
          )}

          {/* Protocol chart + Endpoints table */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            <div className="card">
              <div className="card-header"><h3 className="card-title">Protocol Distribution</h3></div>
              {results.protocol_hierarchy?.length > 0 ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '10px 0' }}>
                  <div style={{ width: 180, height: 180 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={results.protocol_hierarchy} dataKey="count" nameKey="protocol"
                          cx="50%" cy="50%" innerRadius={45} outerRadius={80} paddingAngle={2}>
                          {results.protocol_hierarchy.map((_, i) => (
                            <Cell key={i} fill={PROTO_COLORS[i % PROTO_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-default)', borderRadius: 8, fontSize: '0.85rem' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div style={{ flex: 1 }}>
                    {results.protocol_hierarchy.map((proto, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                        <div style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: PROTO_COLORS[i % PROTO_COLORS.length], flexShrink: 0 }} />
                        <span style={{ flex: 1, fontSize: '0.85rem' }}>{proto.protocol}</span>
                        <span className="text-muted text-sm" style={{ fontFamily: 'JetBrains Mono, monospace' }}>{proto.count.toLocaleString()} ({proto.percentage}%)</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : <p className="text-muted text-sm" style={{ padding: 16 }}>No protocol data.</p>}
            </div>

            <div className="card">
              <div className="card-header"><h3 className="card-title">Top Endpoints</h3></div>
              {results.endpoints?.length > 0 ? (
                <table style={{ width: '100%', marginTop: 10 }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: '8px 10px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>IP Address</th>
                      <th style={{ textAlign: 'right', padding: '8px 10px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>Sent</th>
                      <th style={{ textAlign: 'right', padding: '8px 10px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>Received</th>
                      <th style={{ textAlign: 'right', padding: '8px 10px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>Packets</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.endpoints.slice(0, 10).map((ep, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '9px 10px', fontFamily: 'monospace', fontSize: '0.85rem' }}>{ep.ip}</td>
                        <td style={{ padding: '9px 10px', textAlign: 'right', color: '#10b981', fontSize: '0.85rem' }}>{fmtBytes(ep.sent_bytes)}</td>
                        <td style={{ padding: '9px 10px', textAlign: 'right', color: '#3b82f6', fontSize: '0.85rem' }}>{fmtBytes(ep.recv_bytes)}</td>
                        <td style={{ padding: '9px 10px', textAlign: 'right', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{ep.packets?.toLocaleString() ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <p className="text-muted text-sm" style={{ padding: 16 }}>No endpoint data.</p>}
            </div>

            {/* Detected threats */}
            {ts?.alerts?.length > 0 && (
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div className="card-header">
                  <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <AlertTriangle size={15} color="var(--high)" />
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
                        <th>Destination IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ts.alerts.map((a, i) => (
                        <tr key={i}>
                          <td><span className={`severity-badge ${(a.severity || '').toLowerCase()}`}>{(a.severity || '').toUpperCase()}</span></td>
                          <td className="font-medium">{a.classification || '—'}</td>
                          <td>{a.title}</td>
                          <td>
                            {a.mitre_technique && (
                              <span style={{ fontSize: '0.7rem', fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                                background: 'hsla(210,100%,55%,.12)', color: 'var(--accent)', fontFamily: 'JetBrains Mono, monospace' }}>
                                {a.mitre_technique}
                              </span>
                            )}
                          </td>
                          <td className="font-mono text-sm">{a.src_ip || '—'}</td>
                          <td className="font-mono text-sm">{a.dst_ip || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* DNS queries */}
            {results.dns_queries?.length > 0 && (
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div className="card-header">
                  <h3 className="card-title">
                    DNS Queries ({results.dns_queries.length})
                  </h3>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 14 }}>
                  {results.dns_queries.slice(0, 60).map((dns, i) => (
                    <div key={i} style={{ padding: '6px 12px', backgroundColor: 'var(--bg-secondary)', borderRadius: 6, fontSize: '0.88rem', display: 'flex', alignItems: 'center', gap: 7 }}>
                      <Server size={13} className="text-muted" />
                      <span className="text-muted text-xs">[{dns.type || 'A'}]</span>
                      <span>{dns.query}</span>
                    </div>
                  ))}
                  {results.dns_queries.length > 60 && (
                    <div style={{ padding: '6px 12px', color: 'var(--text-muted)', fontSize: '0.82rem', alignSelf: 'center' }}>
                      +{results.dns_queries.length - 60} more
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* HTTP requests */}
            {results.http_requests?.length > 0 && (
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div className="card-header">
                  <h3 className="card-title">HTTP Requests ({results.http_requests.length})</h3>
                </div>
                <div className="table-container" style={{ maxHeight: 240, overflowY: 'auto' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Method</th><th>Host</th><th>URL</th><th>Source IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.http_requests.slice(0, 50).map((req, i) => (
                        <tr key={i}>
                          <td><span style={{ fontWeight: 700, color: 'var(--accent)', fontSize: '0.8rem' }}>{req.method}</span></td>
                          <td className="font-mono text-sm">{req.host || '—'}</td>
                          <td className="text-sm" style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={req.url}>{req.url}</td>
                          <td className="font-mono text-sm">{req.src_ip}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .top-talker-bar { height: 5px; background: var(--bg-secondary); border-radius: 3px; margin-top: 4px; }
        .top-talker-bar-fill { height: 100%; border-radius: 3px; transition: width .4s ease; }
        .risk-indicator-item { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 10px; }
        .threat-verdict-card { padding: 24px; border-radius: 12px; text-align: center; border: 1px solid var(--border); background: var(--bg-card); }
        .verdict-critical { background: rgba(239,68,68,.07); border-color: rgba(239,68,68,.25); }
        .verdict-high     { background: rgba(245,158,11,.07); border-color: rgba(245,158,11,.25); }
        .verdict-medium   { background: rgba(168,85,247,.07); border-color: rgba(168,85,247,.25); }
        .verdict-clean    { background: rgba(16,185,129,.07); border-color: rgba(16,185,129,.25); }
      `}</style>
    </div>
  );
}
