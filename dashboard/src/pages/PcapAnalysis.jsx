import React, { useState, useRef } from 'react';
import { UploadCloud, File, AlertCircle, CheckCircle, Activity, Server, FileText } from 'lucide-react';

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

  return (
    <div className="fade-in" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {!results ? (
        <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ textAlign: 'center', maxWidth: '600px' }}>
            <h2 style={{ fontSize: '1.75rem', marginBottom: '10px' }}>PCAP File Analysis</h2>
            <p className="text-muted" style={{ marginBottom: '30px' }}>
              Upload a .pcap or .pcapng file to run it through the deep packet inspection engine.
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
          <div className="card" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
              <div style={{ padding: '12px', backgroundColor: 'rgba(16, 185, 129, 0.1)', borderRadius: '12px', color: '#10b981' }}>
                <CheckCircle size={24} />
              </div>
              <div>
                <h3 style={{ margin: '0 0 5px 0' }}>Analysis Complete</h3>
                <p className="text-sm text-muted" style={{ margin: 0 }}>
                  Processed <strong>{results.total_packets}</strong> packets from {results.file} in {results.analysis_time_seconds}s
                </p>
              </div>
            </div>
            <button className="btn btn-secondary" onClick={() => { setResults(null); setFile(null); }}>
              Analyze Another File
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            {/* Protocol Hierarchy */}
            <div className="card">
              <div className="card-header"><h3 className="card-title">Protocol Hierarchy</h3></div>
              <table style={{ width: '100%', marginTop: '10px' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '10px', color: 'var(--text-muted)' }}>Protocol</th>
                    <th style={{ textAlign: 'right', padding: '10px', color: 'var(--text-muted)' }}>Packets</th>
                    <th style={{ textAlign: 'right', padding: '10px', color: 'var(--text-muted)' }}>%</th>
                  </tr>
                </thead>
                <tbody>
                  {results.protocol_hierarchy.map((proto, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '10px' }}>
                        <span className={`proto-badge ${proto.protocol.toLowerCase()}`}>{proto.protocol}</span>
                      </td>
                      <td style={{ padding: '10px', textAlign: 'right' }}>{proto.count}</td>
                      <td style={{ padding: '10px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '10px' }}>
                          <div style={{ width: '60px', height: '6px', backgroundColor: 'var(--bg-secondary)', borderRadius: '3px', overflow: 'hidden' }}>
                            <div style={{ width: `${proto.percentage}%`, height: '100%', backgroundColor: 'var(--primary)' }}></div>
                          </div>
                          {proto.percentage}%
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
