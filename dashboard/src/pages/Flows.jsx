import React, { useState, useMemo } from 'react';
import { useApi } from '../hooks/useApi';
import { 
  Share2, Search, Filter, ArrowUpDown, ChevronLeft, ChevronRight, 
  ShieldAlert, ShieldCheck, Globe, Server, ExternalLink, X, 
  Ban, Clock, HardDrive, ArrowRight, RefreshCw, AlertTriangle
} from 'lucide-react';
import { SkeletonTable } from '../components/Skeleton';
import { API_BASE } from '../config';

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(sec) {
  if (!sec || sec < 1) return `${((sec || 0) * 1000).toFixed(0)} ms`;
  if (sec < 60) return `${sec.toFixed(1)} s`;
  const mins = Math.floor(sec / 60);
  const remSec = (sec % 60).toFixed(0);
  return `${mins}m ${remSec}s`;
}

export default function Flows() {
  const { data: flowsData, loading, error, refetch } = useApi('/api/sessions?limit=500', { interval: 3000 });
  const { data: statsData } = useApi('/api/stats', { interval: 3000 });

  // Filtering states
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Sorting states
  const [sortField, setSortField] = useState('last_seen');
  const [sortDirection, setSortDirection] = useState('desc');

  // Pagination states
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  // Flow Detail Modal state
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [actionMessage, setActionMessage] = useState(null);

  const rawFlows = flowsData?.sessions || [];
  const totalFlows = flowsData?.total || rawFlows.length;

  // Compute summary metrics
  const suspiciousCount = useMemo(() => {
    return rawFlows.filter(f => f.is_suspicious || (f.alerts && f.alerts.length > 0)).length;
  }, [rawFlows]);

  const totalBytesTransferred = useMemo(() => {
    return rawFlows.reduce((sum, f) => sum + (f.total_bytes || 0), 0);
  }, [rawFlows]);

  // Filter and sort flows
  const filteredFlows = useMemo(() => {
    let result = [...rawFlows];

    // Search filter
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase().trim();
      result = result.filter(f => 
        (f.src_ip && f.src_ip.toLowerCase().includes(q)) ||
        (f.dst_ip && f.dst_ip.toLowerCase().includes(q)) ||
        (f.sni && f.sni.toLowerCase().includes(q)) ||
        (f.http_host && f.http_host.toLowerCase().includes(q)) ||
        (f.protocol && f.protocol.toLowerCase().includes(q)) ||
        (f.app_protocol && f.app_protocol.toLowerCase().includes(q)) ||
        String(f.src_port).includes(q) ||
        String(f.dst_port).includes(q)
      );
    }

    // Protocol filter
    if (protocolFilter !== 'ALL') {
      result = result.filter(f => 
        (f.protocol && f.protocol.toUpperCase() === protocolFilter) ||
        (f.app_protocol && f.app_protocol.toUpperCase() === protocolFilter)
      );
    }

    // Status filter
    if (statusFilter === 'SUSPICIOUS') {
      result = result.filter(f => f.is_suspicious || (f.alerts && f.alerts.length > 0));
    } else if (statusFilter === 'CLEAN') {
      result = result.filter(f => !f.is_suspicious && (!f.alerts || f.alerts.length === 0));
    }

    // Sorting
    result.sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];

      if (valA === undefined || valA === null) valA = 0;
      if (valB === undefined || valB === null) valB = 0;

      if (typeof valA === 'string') {
        return sortDirection === 'asc' 
          ? valA.localeCompare(valB)
          : valB.localeCompare(valA);
      }

      return sortDirection === 'asc' ? valA - valB : valB - valA;
    });

    return result;
  }, [rawFlows, searchTerm, protocolFilter, statusFilter, sortField, sortDirection]);

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredFlows.length / pageSize));
  const paginatedFlows = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredFlows.slice(start, start + pageSize);
  }, [filteredFlows, page, pageSize]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
    setPage(1);
  };

  const handleBlockIp = async (ip, domain = '') => {
    try {
      const token = localStorage.getItem('token');
      const res = await fetch(`${API_BASE}/api/firewall/block-domain`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        },
        body: JSON.stringify({ domain: domain || ip })
      });
      if (res.ok) {
        setActionMessage(`Successfully blocked IP ${ip}`);
        setTimeout(() => setActionMessage(null), 4000);
      } else {
        setActionMessage(`Failed to block ${ip}`);
        setTimeout(() => setActionMessage(null), 4000);
      }
    } catch {
      setActionMessage(`Network error blocking ${ip}`);
      setTimeout(() => setActionMessage(null), 4000);
    }
  };

  return (
    <div className="fade-in">
      {/* ── Top Summary Metric Cards ── */}
      <div className="stat-grid-5" style={{ marginBottom: 20 }}>
        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-title">Active Flows</span>
            <div className="stat-icon-wrapper" style={{ background: 'var(--accent-glow)' }}>
              <Share2 size={20} color="var(--accent)" />
            </div>
          </div>
          <div className="stat-value">{totalFlows.toLocaleString()}</div>
          <div className="stat-sub">Concurrent stateful sessions</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-title">Threat Tracked</span>
            <div className="stat-icon-wrapper" style={{ background: 'var(--critical-bg)' }}>
              <ShieldAlert size={20} color="var(--critical)" />
            </div>
          </div>
          <div className="stat-value" style={{ color: suspiciousCount > 0 ? 'var(--critical)' : 'inherit' }}>
            {suspiciousCount}
          </div>
          <div className="stat-sub">Flows matched by IDS/TI</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-title">Total Flow Volume</span>
            <div className="stat-icon-wrapper" style={{ background: 'var(--info-bg)' }}>
              <HardDrive size={20} color="var(--info)" />
            </div>
          </div>
          <div className="stat-value">{formatBytes(totalBytesTransferred)}</div>
          <div className="stat-sub">Aggregated session payloads</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-title">TCP / UDP Split</span>
            <div className="stat-icon-wrapper" style={{ background: 'var(--bg-elevated)' }}>
              <Server size={20} color="var(--proto-tcp)" />
            </div>
          </div>
          <div className="stat-value" style={{ fontSize: '1.25rem' }}>
            {statsData?.flows?.tcp_flows ?? 0} TCP / {statsData?.flows?.udp_flows ?? 0} UDP
          </div>
          <div className="stat-sub">Transport protocol ratio</div>
        </div>

        <div className="stat-card">
          <div className="stat-header">
            <span className="stat-title">Filtered Flows</span>
            <div className="stat-icon-wrapper" style={{ background: 'var(--bg-elevated)' }}>
              <Filter size={20} color="var(--text-secondary)" />
            </div>
          </div>
          <div className="stat-value">{filteredFlows.length.toLocaleString()}</div>
          <div className="stat-sub">Showing on this view</div>
        </div>
      </div>

      {actionMessage && (
        <div className="alert-banner info" style={{ marginBottom: 16 }}>
          <AlertTriangle size={16} />
          <span>{actionMessage}</span>
        </div>
      )}

      {/* ── Filter Bar & Controls ── */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', justifyContent: 'space-between' }}>
          {/* Search box */}
          <div style={{ position: 'relative', flex: '1 1 280px', minWidth: 240 }}>
            <Search size={16} className="text-muted" style={{ position: 'absolute', left: 12, top: 12 }} />
            <input 
              type="text" 
              className="input" 
              placeholder="Filter by IP, Port, Hostname, SNI, Protocol..." 
              value={searchTerm}
              onChange={e => { setSearchTerm(e.target.value); setPage(1); }}
              style={{ paddingLeft: 38, width: '100%' }}
            />
          </div>

          {/* Protocol dropdown */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label className="text-muted" style={{ fontSize: 13, fontWeight: 500 }}>Protocol:</label>
            <select 
              className="input" 
              value={protocolFilter} 
              onChange={e => { setProtocolFilter(e.target.value); setPage(1); }}
              style={{ width: 120, padding: '8px 12px' }}
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="TLS">TLS / HTTPS</option>
              <option value="HTTP">HTTP</option>
              <option value="DNS">DNS</option>
              <option value="ICMP">ICMP</option>
              <option value="SSH">SSH</option>
            </select>
          </div>

          {/* Status dropdown */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label className="text-muted" style={{ fontSize: 13, fontWeight: 500 }}>Status:</label>
            <select 
              className="input" 
              value={statusFilter} 
              onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
              style={{ width: 140, padding: '8px 12px' }}
            >
              <option value="ALL">All Flows</option>
              <option value="SUSPICIOUS">Suspicious Only</option>
              <option value="CLEAN">Clean Only</option>
            </select>
          </div>

          {/* Page size dropdown */}
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <label className="text-muted" style={{ fontSize: 13, fontWeight: 500 }}>Page Size:</label>
            <select 
              className="input" 
              value={pageSize} 
              onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}
              style={{ width: 85, padding: '8px 10px' }}
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          <button 
            className="btn btn-secondary" 
            onClick={() => refetch()} 
            title="Refresh Flow Table"
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Upgraded Flow Table ── */}
      <div className="card">
        {loading && rawFlows.length === 0 ? (
          <SkeletonTable rows={8} cols={7} />
        ) : filteredFlows.length === 0 ? (
          <div className="empty-state" style={{ padding: '48px 24px' }}>
            <Share2 size={40} style={{ opacity: 0.3, marginBottom: 12 }} />
            <h3>No Network Flows Found</h3>
            <p className="text-muted">No sessions match your search or filter criteria.</p>
          </div>
        ) : (
          <>
            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th style={{ width: 40 }}>Status</th>
                    <th onClick={() => handleSort('src_ip')} style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Source IP:Port {sortField === 'src_ip' && <ArrowUpDown size={12} />}
                      </div>
                    </th>
                    <th>Direction</th>
                    <th onClick={() => handleSort('dst_ip')} style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Destination IP:Port {sortField === 'dst_ip' && <ArrowUpDown size={12} />}
                      </div>
                    </th>
                    <th onClick={() => handleSort('protocol')} style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Protocol {sortField === 'protocol' && <ArrowUpDown size={12} />}
                      </div>
                    </th>
                    <th>Application / Host</th>
                    <th onClick={() => handleSort('total_packets')} style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Packets {sortField === 'total_packets' && <ArrowUpDown size={12} />}
                      </div>
                    </th>
                    <th onClick={() => handleSort('total_bytes')} style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Bytes {sortField === 'total_bytes' && <ArrowUpDown size={12} />}
                      </div>
                    </th>
                    <th onClick={() => handleSort('duration')} style={{ cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        Duration {sortField === 'duration' && <ArrowUpDown size={12} />}
                      </div>
                    </th>
                    <th style={{ textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedFlows.map((flow, idx) => {
                    const isSuspicious = flow.is_suspicious || (flow.alerts && flow.alerts.length > 0);
                    return (
                      <tr 
                        key={flow.flow_id || idx}
                        className={isSuspicious ? 'table-row-danger' : ''}
                        style={{ cursor: 'pointer' }}
                        onClick={() => setSelectedFlow(flow)}
                      >
                        <td>
                          {isSuspicious ? (
                            <span title="Suspicious Flow / Threat Hit" style={{ color: 'var(--critical)' }}>
                              <ShieldAlert size={16} />
                            </span>
                          ) : (
                            <span title="Clean Flow" style={{ color: 'var(--success)' }}>
                              <ShieldCheck size={16} />
                            </span>
                          )}
                        </td>
                        <td className="mono" style={{ fontSize: 13, fontWeight: 500 }}>
                          <span>{flow.src_ip}</span>
                          <span className="text-muted">:{flow.src_port}</span>
                          {flow.src_geo?.country && (
                            <span className="geo-tag" style={{ marginLeft: 6 }}>{flow.src_geo.country}</span>
                          )}
                        </td>
                        <td style={{ color: 'var(--text-muted)' }}>
                          <ArrowRight size={14} />
                        </td>
                        <td className="mono" style={{ fontSize: 13, fontWeight: 500 }}>
                          <span>{flow.dst_ip}</span>
                          <span className="text-muted">:{flow.dst_port}</span>
                          {flow.dst_geo?.country && (
                            <span className="geo-tag" style={{ marginLeft: 6 }}>{flow.dst_geo.country}</span>
                          )}
                        </td>
                        <td>
                          <span className={`badge badge-proto badge-${(flow.protocol || '').toLowerCase()}`}>
                            {flow.protocol}
                          </span>
                        </td>
                        <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {flow.sni ? (
                            <span title={flow.sni} style={{ color: 'var(--proto-tls)' }}>{flow.sni}</span>
                          ) : flow.http_host ? (
                            <span title={flow.http_host} style={{ color: 'var(--proto-http)' }}>{flow.http_host}</span>
                          ) : flow.app_protocol ? (
                            <span className="text-secondary">{flow.app_protocol}</span>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                        <td>
                          <div style={{ fontSize: 13 }}>{(flow.total_packets || 0).toLocaleString()}</div>
                          <div className="text-muted" style={{ fontSize: 11 }}>
                            {flow.packets_fwd} ↑ / {flow.packets_rev} ↓
                          </div>
                        </td>
                        <td>
                          <div style={{ fontSize: 13 }}>{formatBytes(flow.total_bytes)}</div>
                          <div className="text-muted" style={{ fontSize: 11 }}>
                            {formatBytes(flow.bytes_fwd)} ↑ / {formatBytes(flow.bytes_rev)} ↓
                          </div>
                        </td>
                        <td className="mono" style={{ fontSize: 12 }}>
                          {formatDuration(flow.duration)}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }} onClick={e => e.stopPropagation()}>
                            <button 
                              className="btn btn-secondary btn-sm"
                              onClick={() => setSelectedFlow(flow)}
                              title="Inspect Flow Details"
                            >
                              Inspect
                            </button>
                            <button 
                              className="btn btn-danger btn-sm"
                              onClick={() => handleBlockIp(flow.dst_ip, flow.sni || flow.http_host)}
                              title={`Block destination IP ${flow.dst_ip}`}
                            >
                              Block
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* ── Table Pagination Bar ── */}
            <div className="table-pagination">
              <span className="text-muted">
                Showing {((page - 1) * pageSize) + 1} - {Math.min(page * pageSize, filteredFlows.length)} of {filteredFlows.length} flows
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button 
                  className="btn btn-secondary btn-sm" 
                  disabled={page <= 1} 
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                >
                  <ChevronLeft size={16} /> Prev
                </button>
                <span style={{ fontSize: 13, padding: '0 8px' }}>
                  Page {page} of {totalPages}
                </span>
                <button 
                  className="btn btn-secondary btn-sm" 
                  disabled={page >= totalPages} 
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                >
                  Next <ChevronRight size={16} />
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* ── Flow Inspector Drawer / Modal ── */}
      {selectedFlow && (
        <div className="global-search-backdrop" onClick={() => setSelectedFlow(null)}>
          <div 
            className="global-search-modal" 
            style={{ maxWidth: 700 }}
            onClick={e => e.stopPropagation()}
          >
            <div className="card-header" style={{ borderBottom: '1px solid var(--border-default)', padding: '16px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Share2 size={20} color="var(--accent)" />
                <h3 className="card-title" style={{ margin: 0 }}>Flow Inspection Details</h3>
              </div>
              <button className="btn-icon-secondary" onClick={() => setSelectedFlow(null)}>
                <X size={18} />
              </button>
            </div>

            <div style={{ padding: '20px', maxHeight: '75vh', overflowY: 'auto' }}>
              {/* Flow Key banner */}
              <div style={{ background: 'var(--bg-secondary)', padding: '12px 16px', borderRadius: 'var(--radius-md)', marginBottom: 16 }}>
                <div className="text-muted" style={{ fontSize: 11, marginBottom: 4 }}>CANONICAL 5-TUPLE KEY</div>
                <div className="mono" style={{ fontSize: 13, wordBreak: 'break-all', color: 'var(--text-primary)' }}>
                  {selectedFlow.flow_id}
                </div>
              </div>

              {/* Endpoints Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
                <div className="card" style={{ padding: 14 }}>
                  <div className="text-muted" style={{ fontSize: 12, marginBottom: 4 }}>Source Host</div>
                  <div className="mono" style={{ fontSize: 15, fontWeight: 600 }}>{selectedFlow.src_ip}</div>
                  <div className="text-secondary" style={{ fontSize: 12 }}>Port {selectedFlow.src_port}</div>
                  {selectedFlow.src_geo && (
                    <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                      📍 {selectedFlow.src_geo.country || 'Unknown'} {selectedFlow.src_geo.city ? `(${selectedFlow.src_geo.city})` : ''}
                    </div>
                  )}
                </div>

                <div className="card" style={{ padding: 14 }}>
                  <div className="text-muted" style={{ fontSize: 12, marginBottom: 4 }}>Target Destination</div>
                  <div className="mono" style={{ fontSize: 15, fontWeight: 600 }}>{selectedFlow.dst_ip}</div>
                  <div className="text-secondary" style={{ fontSize: 12 }}>Port {selectedFlow.dst_port}</div>
                  {selectedFlow.dst_geo && (
                    <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                      📍 {selectedFlow.dst_geo.country || 'Unknown'} {selectedFlow.dst_geo.city ? `(${selectedFlow.dst_geo.city})` : ''}
                    </div>
                  )}
                </div>
              </div>

              {/* Traffic Metrics */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
                <div style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div className="text-muted" style={{ fontSize: 11 }}>Packets</div>
                  <div style={{ fontSize: 16, fontWeight: 600, marginTop: 4 }}>
                    {(selectedFlow.total_packets || 0).toLocaleString()}
                  </div>
                  <div className="text-muted" style={{ fontSize: 11, marginTop: 2 }}>
                    {selectedFlow.packets_fwd} fwd / {selectedFlow.packets_rev} rev
                  </div>
                </div>

                <div style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div className="text-muted" style={{ fontSize: 11 }}>Bytes Transferred</div>
                  <div style={{ fontSize: 16, fontWeight: 600, marginTop: 4 }}>
                    {formatBytes(selectedFlow.total_bytes)}
                  </div>
                  <div className="text-muted" style={{ fontSize: 11, marginTop: 2 }}>
                    {formatBytes(selectedFlow.bytes_fwd)} fwd / {formatBytes(selectedFlow.bytes_rev)} rev
                  </div>
                </div>

                <div style={{ background: 'var(--bg-secondary)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div className="text-muted" style={{ fontSize: 11 }}>Session Duration</div>
                  <div style={{ fontSize: 16, fontWeight: 600, marginTop: 4 }}>
                    {formatDuration(selectedFlow.duration)}
                  </div>
                  <div className="text-muted" style={{ fontSize: 11, marginTop: 2 }}>
                    TCP State: {selectedFlow.tcp_state || 'ESTABLISHED'}
                  </div>
                </div>
              </div>

              {/* Protocol & Application Details */}
              <div className="card" style={{ padding: 16, marginBottom: 16 }}>
                <h4 style={{ fontSize: 13, marginBottom: 10, color: 'var(--text-secondary)' }}>APPLICATION & LAYER 7 INFO</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 13 }}>
                  <div>
                    <span className="text-muted">Transport:</span> <strong>{selectedFlow.protocol}</strong>
                  </div>
                  <div>
                    <span className="text-muted">Application Layer:</span> <strong>{selectedFlow.app_protocol || 'N/A'}</strong>
                  </div>
                  {selectedFlow.sni && (
                    <div style={{ gridColumn: 'span 2' }}>
                      <span className="text-muted">TLS Server Name (SNI):</span> <code className="mono" style={{ color: 'var(--proto-tls)' }}>{selectedFlow.sni}</code>
                    </div>
                  )}
                  {selectedFlow.http_host && (
                    <div style={{ gridColumn: 'span 2' }}>
                      <span className="text-muted">HTTP Host:</span> <code className="mono" style={{ color: 'var(--proto-http)' }}>{selectedFlow.http_host}</code>
                    </div>
                  )}
                </div>
              </div>

              {/* Alerts & Threat intel */}
              {selectedFlow.alerts && selectedFlow.alerts.length > 0 && (
                <div className="alert-banner critical" style={{ marginBottom: 16 }}>
                  <ShieldAlert size={18} />
                  <div>
                    <strong>Threat Alerts Triggered ({selectedFlow.alerts.length}):</strong>
                    <ul style={{ marginTop: 6, paddingLeft: 18 }}>
                      {selectedFlow.alerts.map((al, i) => (
                        <li key={i}>{al}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', marginTop: 10 }}>
                <button 
                  className="btn btn-secondary" 
                  onClick={() => setSelectedFlow(null)}
                >
                  Close
                </button>
                <button 
                  className="btn btn-danger"
                  onClick={() => {
                    handleBlockIp(selectedFlow.dst_ip, selectedFlow.sni || selectedFlow.http_host);
                    setSelectedFlow(null);
                  }}
                >
                  <Ban size={15} style={{ marginRight: 6 }} /> Block Destination IP ({selectedFlow.dst_ip})
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
