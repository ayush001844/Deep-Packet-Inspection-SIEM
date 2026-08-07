import React, { useState } from 'react';
import { useApi } from '../hooks/useApi';
import { List, Search, ChevronLeft, ChevronRight, Activity, Filter } from 'lucide-react';

export default function PacketLog() {
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(100);
  
  const [filters, setFilters] = useState({
    protocol: '',
    src_ip: '',
    dst_ip: '',
  });

  const queryParams = new URLSearchParams({
    limit,
    offset,
    ...(filters.protocol && { protocol: filters.protocol }),
    ...(filters.src_ip && { src_ip: filters.src_ip }),
    ...(filters.dst_ip && { dst_ip: filters.dst_ip }),
  }).toString();

  const { data, loading, refetch } = useApi(`/api/packets?${queryParams}`, { interval: 0 });

  const packets = data?.data || [];
  const total = data?.total || 0;

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
    setOffset(0); // Reset to first page on filter change
  };

  const handleApplyFilters = () => {
    refetch();
  };

  const getProtoClass = (proto) => proto ? proto.toLowerCase() : '';

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const handlePrevPage = () => {
    if (offset >= limit) setOffset(offset - limit);
  };

  const handleNextPage = () => {
    if (offset + limit < total) setOffset(offset + limit);
  };

  return (
    <div className="fade-in flex-col" style={{ height: '100%', display: 'flex', gap: 20 }}>
      {/* ── Header & Filters ── */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            <List size={24} color="var(--accent)" />
            Packet Log
          </h2>
        </div>

        <div style={{ display: 'flex', gap: 15, flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label className="text-sm text-muted block mb-1">Protocol</label>
            <div className="relative">
              <Filter size={14} className="text-muted" style={{ position: 'absolute', left: 10, top: 12 }} />
              <input 
                type="text" 
                name="protocol"
                className="input w-full" 
                placeholder="e.g. TCP, UDP, DNS" 
                value={filters.protocol}
                onChange={handleFilterChange}
                style={{ paddingLeft: 30 }}
                onKeyDown={(e) => e.key === 'Enter' && handleApplyFilters()}
              />
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label className="text-sm text-muted block mb-1">Source IP</label>
            <div className="relative">
              <Search size={14} className="text-muted" style={{ position: 'absolute', left: 10, top: 12 }} />
              <input 
                type="text" 
                name="src_ip"
                className="input w-full" 
                placeholder="e.g. 192.168.1.100" 
                value={filters.src_ip}
                onChange={handleFilterChange}
                style={{ paddingLeft: 30 }}
                onKeyDown={(e) => e.key === 'Enter' && handleApplyFilters()}
              />
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <label className="text-sm text-muted block mb-1">Destination IP</label>
            <div className="relative">
              <Search size={14} className="text-muted" style={{ position: 'absolute', left: 10, top: 12 }} />
              <input 
                type="text" 
                name="dst_ip"
                className="input w-full" 
                placeholder="e.g. 8.8.8.8" 
                value={filters.dst_ip}
                onChange={handleFilterChange}
                style={{ paddingLeft: 30 }}
                onKeyDown={(e) => e.key === 'Enter' && handleApplyFilters()}
              />
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button className="btn btn-primary" onClick={handleApplyFilters}>
              Search
            </button>
          </div>
        </div>
      </div>

      {/* ── Packet Table ── */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        <div className="card-header" style={{ padding: '16px 20px', margin: 0, borderBottom: '1px solid var(--border-default)', backgroundColor: 'var(--bg-elevated)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 className="card-title flex items-center gap-2">
            <Activity size={16} /> 
            Historical Packets
            <span className="text-muted text-sm" style={{ fontWeight: 'normal' }}>
              ({total} packets found)
            </span>
          </h3>
          
          <div className="flex items-center gap-4 text-sm">
            <span className="text-muted">
              Page {currentPage} of {totalPages || 1}
            </span>
            <div className="flex gap-2">
              <button 
                className="btn btn-secondary" 
                style={{ padding: '6px 12px', minWidth: 'unset' }}
                onClick={handlePrevPage}
                disabled={offset === 0}
              >
                <ChevronLeft size={16} /> Prev
              </button>
              <button 
                className="btn btn-secondary" 
                style={{ padding: '6px 12px', minWidth: 'unset' }}
                onClick={handleNextPage}
                disabled={offset + limit >= total}
              >
                Next <ChevronRight size={16} />
              </button>
            </div>
          </div>
        </div>
        
        <div className="table-container" style={{ flex: 1, border: 'none', borderRadius: 0 }}>
          {loading && packets.length === 0 ? (
            <div className="empty-state" style={{ height: 300 }}>
              <Activity size={48} className="spin" />
              <h3>Loading packets...</h3>
            </div>
          ) : (
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
                      <List size={48} />
                      <h3>No packets found</h3>
                      <p>Try adjusting your filters or capture more traffic.</p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
