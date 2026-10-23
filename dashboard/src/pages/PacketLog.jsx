import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useApi } from '../hooks/useApi';
import { List, Search, ChevronLeft, ChevronRight, Activity, Filter, RefreshCw } from 'lucide-react';
import { SkeletonTable } from '../components/Skeleton';

export default function PacketLog() {
  const [searchParams] = useSearchParams();
  const [offset, setOffset] = useState(0);
  const [limit, setLimit] = useState(50);
  
  const [filters, setFilters] = useState({
    protocol: '',
    src_ip: '',
    dst_ip: '',
  });

  // Handle URL query parameters from Global Search
  useEffect(() => {
    const filterParam = searchParams.get('filter');
    const portParam = searchParams.get('port');
    if (filterParam) {
      if (filterParam.includes('.') || filterParam.includes(':')) {
        setFilters(prev => ({ ...prev, src_ip: filterParam }));
      } else {
        setFilters(prev => ({ ...prev, protocol: filterParam }));
      }
    }
  }, [searchParams]);

  const queryParams = new URLSearchParams({
    limit,
    offset,
    ...(filters.protocol && { protocol: filters.protocol }),
    ...(filters.src_ip && { src_ip: filters.src_ip }),
    ...(filters.dst_ip && { dst_ip: filters.dst_ip }),
  }).toString();

  const { data, loading, refetch } = useApi(`/api/packets?${queryParams}`, { interval: 0 });

  const packets = data?.packets || [];
  const total = data?.total || 0;

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters(prev => ({ ...prev, [name]: value }));
    setOffset(0);
  };

  const handleApplyFilters = () => {
    refetch();
  };

  const handleResetFilters = () => {
    setFilters({ protocol: '', src_ip: '', dst_ip: '' });
    setOffset(0);
  };

  const getProtoClass = (proto) => proto ? proto.toLowerCase() : '';

  const totalPages = Math.max(1, Math.ceil(total / limit));
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
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            <List size={22} color="var(--accent)" />
            Packet Log & Deep Inspection
          </h2>
          <button 
            className="btn btn-secondary btn-sm" 
            onClick={() => refetch()}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: 180 }}>
            <label className="text-sm text-muted block mb-1">Protocol</label>
            <div className="relative">
              <Filter size={14} className="text-muted" style={{ position: 'absolute', left: 10, top: 12 }} />
              <input 
                type="text" 
                name="protocol"
                className="input w-full" 
                placeholder="e.g. TCP, UDP, DNS, TLS" 
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
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" onClick={handleApplyFilters}>
              Filter
            </button>
            <button className="btn btn-secondary" onClick={handleResetFilters}>
              Reset
            </button>
          </div>
        </div>
      </div>

      {/* ── Packet Table ── */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 0 }}>
        <div className="card-header" style={{ padding: '14px 20px', margin: 0, borderBottom: '1px solid var(--border-default)', backgroundColor: 'var(--bg-elevated)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 className="card-title flex items-center gap-2" style={{ margin: 0 }}>
            <Activity size={16} /> 
            Captured Packets
            <span className="text-muted text-sm" style={{ fontWeight: 'normal' }}>
              ({total.toLocaleString()} total)
            </span>
          </h3>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }} className="text-muted">
              <span>Page size:</span>
              <select 
                className="input" 
                value={limit} 
                onChange={e => { setLimit(Number(e.target.value)); setOffset(0); }}
                style={{ padding: '4px 8px', fontSize: 12 }}
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="text-muted" style={{ fontSize: 13 }}>
                Page {currentPage} of {totalPages}
              </span>
              <div style={{ display: 'flex', gap: 4 }}>
                <button 
                  className="btn btn-secondary btn-sm" 
                  onClick={handlePrevPage}
                  disabled={offset === 0}
                >
                  <ChevronLeft size={14} /> Prev
                </button>
                <button 
                  className="btn btn-secondary btn-sm" 
                  onClick={handleNextPage}
                  disabled={offset + limit >= total}
                >
                  Next <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </div>
        </div>
        
        <div className="table-responsive" style={{ flex: 1, border: 'none', borderRadius: 0 }}>
          {loading && packets.length === 0 ? (
            <div style={{ padding: 16 }}>
              <SkeletonTable rows={10} cols={7} />
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 80 }}>No.</th>
                  <th style={{ width: 110 }}>Time</th>
                  <th style={{ width: 160 }}>Source</th>
                  <th style={{ width: 160 }}>Destination</th>
                  <th style={{ width: 90 }}>Protocol</th>
                  <th style={{ width: 80 }}>Length</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {packets.length > 0 ? (
                  packets.map((pkt, i) => (
                    <tr key={pkt.id || i}>
                      <td className="text-muted mono" style={{ fontSize: 12 }}>{pkt.id}</td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {pkt.timestamp ? new Date(pkt.timestamp * 1000).toLocaleTimeString() : '—'}
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        <span>{pkt.src_ip || pkt.src_mac || '-'}</span>
                        {pkt.src_port && <span className="text-muted">:{pkt.src_port}</span>}
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        <span>{pkt.dst_ip || pkt.dst_mac || '-'}</span>
                        {pkt.dst_port && <span className="text-muted">:{pkt.dst_port}</span>}
                      </td>
                      <td>
                        <span className={`badge badge-proto badge-${getProtoClass(pkt.protocol)}`}>
                          {pkt.protocol || 'Unknown'}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>{pkt.length} B</td>
                      <td className="text-sm truncate" style={{ maxWidth: 380 }} title={pkt.summary}>
                        {(() => {
                          const http = pkt.layers?.find(l => l.layer === 'HTTP' && l.direction === 'request');
                          if (http) return <span style={{ color: 'var(--accent)' }}>{http.method} {http.host}{http.url}</span>;
                          
                          const dns = pkt.layers?.find(l => l.layer === 'DNS' && l.type === 'query');
                          if (dns) return <span style={{ color: 'var(--proto-dns)' }}>DNS: {dns.query_name}</span>;
                          
                          if (pkt.sni) return <span style={{ color: 'var(--proto-tls)' }}>TLS SNI: {pkt.sni}</span>;
                          
                          return pkt.summary;
                        })()}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="7" className="empty-state" style={{ height: 260 }}>
                      <List size={40} style={{ opacity: 0.3, marginBottom: 8 }} />
                      <h3>No packets found</h3>
                      <p className="text-muted">No packets matched your filter conditions.</p>
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
