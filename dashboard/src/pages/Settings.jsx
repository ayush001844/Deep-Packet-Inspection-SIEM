import React, { useState } from 'react';
import { useApi } from '../hooks/useApi';
import { Shield, Server, Settings as SettingsIcon, ShieldOff, Globe, AlertCircle, CheckCircle2 } from 'lucide-react';

export default function Settings() {
  const { data: firewallData, loading, refetch } = useApi('/api/firewall/blocked');
  const [unblocking, setUnblocking] = useState(null);
  const [domainToBlock, setDomainToBlock] = useState('');
  const [isBlocking, setIsBlocking] = useState(false);
  const [blockResult, setBlockResult] = useState(null); // { domain, ips }

  const handleUnblock = async (ip) => {
    setUnblocking(ip);
    try {
      const res = await fetch(`/api/firewall/unblock/${ip}`, { method: 'POST' });
      if (res.ok) refetch();
    } catch (err) {
      console.error(err);
    }
    setUnblocking(null);
  };

  const handleBlockDomain = async (e) => {
    e.preventDefault();
    if (!domainToBlock) return;

    setIsBlocking(true);
    setBlockResult(null);
    try {
      const res = await fetch('/api/firewall/block-domain', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domainToBlock }),
      });
      const data = await res.json();
      if (res.ok) {
        setBlockResult({ domain: data.domain, ips: data.ips_blocked });
        setDomainToBlock('');
        refetch();
      } else {
        setBlockResult({ error: data.detail || 'Failed to block domain' });
      }
    } catch (err) {
      console.error(err);
      setBlockResult({ error: 'Network error — could not reach backend' });
    }
    setIsBlocking(false);
  };

  // Use rich entries if available, fallback to raw IPs
  const entries = firewallData?.entries || (firewallData?.blocked_ips || []).map(ip => ({ ip, domain: '', reason: '' }));

  return (
    <div className="fade-in">
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>System Settings</h2>
        <p className="text-sm text-muted" style={{ margin: '5px 0 0 0' }}>
          Configure SIEM parameters and manage active firewall blocks.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
        {/* Left column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="card">
            <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Server color="var(--primary)" />
              <h3 className="card-title">Backend Connection</h3>
            </div>
            <div style={{ padding: '20px' }}>
              <div style={{ marginBottom: '15px' }}>
                <label className="text-sm font-medium" style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)' }}>API Endpoint</label>
                <input type="text" className="input" defaultValue="http://localhost:8000" readOnly />
              </div>
              <div>
                <label className="text-sm font-medium" style={{ display: 'block', marginBottom: '6px', color: 'var(--text-muted)' }}>WebSocket Endpoint</label>
                <input type="text" className="input" defaultValue="ws://localhost:8000/ws/packets" readOnly />
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <SettingsIcon color="var(--accent)" />
              <h3 className="card-title">Threat Intel Feeds</h3>
            </div>
            <div style={{ padding: '20px' }}>
              {['CINS Army', 'Emerging Threats', 'Blocklist.de'].map(feed => (
                <div key={feed} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                  <span style={{ fontSize: '0.9rem' }}>{feed}</span>
                  <span className="badge" style={{ backgroundColor: 'rgba(16,185,129,0.15)', color: '#10b981' }}>Active</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Firewall panel */}
        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield color="var(--critical)" />
            <h3 className="card-title">Active Firewall Blocks (pfctl)</h3>
            <span style={{ marginLeft: 'auto', fontSize: '0.8rem', padding: '4px 10px', backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444', borderRadius: '999px' }}>
              {entries.length} rule{entries.length !== 1 ? 's' : ''} active
            </span>
          </div>

          {/* Block form */}
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)' }}>
            <form onSubmit={handleBlockDomain} style={{ display: 'flex', gap: '10px' }}>
              <div style={{ position: 'relative', flex: 1 }}>
                <Globe size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  className="input"
                  placeholder="Enter domain (e.g. youtube.com) or IP address"
                  value={domainToBlock}
                  onChange={e => setDomainToBlock(e.target.value)}
                  style={{ paddingLeft: '36px', width: '100%' }}
                  required
                />
              </div>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={isBlocking || !domainToBlock}
                style={{ whiteSpace: 'nowrap' }}
              >
                {isBlocking ? 'Resolving...' : '🚫 Block Target'}
              </button>
            </form>

            {/* Result feedback */}
            {blockResult && !blockResult.error && (
              <div style={{ marginTop: '12px', padding: '10px 14px', backgroundColor: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: '8px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <CheckCircle2 size={18} color="#10b981" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div>
                  <p style={{ margin: 0, fontSize: '0.9rem', fontWeight: 600, color: '#10b981' }}>
                    {blockResult.domain} blocked successfully
                  </p>
                  <p style={{ margin: '4px 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Resolved &amp; blocked {blockResult.ips.length} IP address{blockResult.ips.length > 1 ? 'es' : ''}: {blockResult.ips.join(', ')}
                  </p>
                </div>
              </div>
            )}
            {blockResult?.error && (
              <div style={{ marginTop: '12px', padding: '10px 14px', backgroundColor: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <AlertCircle size={18} color="#ef4444" />
                <span style={{ fontSize: '0.9rem', color: '#ef4444' }}>{blockResult.error}</span>
              </div>
            )}
          </div>

          {/* Blocked entries table */}
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Blocked IPs</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading && !firewallData ? (
                  <tr><td colSpan="3" style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>Loading...</td></tr>
                ) : entries.length > 0 ? (
                  // Group by domain for cleaner display
                  Object.entries(
                    entries.reduce((acc, entry) => {
                      const key = entry.domain || entry.ip;
                      if (!acc[key]) acc[key] = { domain: entry.domain, ips: [] };
                      acc[key].ips.push(entry.ip);
                      return acc;
                    }, {})
                  ).map(([key, group]) => (
                    <tr key={key}>
                      <td>
                        {group.domain ? (
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <Globe size={14} color="var(--text-muted)" />
                            <span style={{ fontWeight: 600 }}>{group.domain}</span>
                          </div>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Direct IP block</span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '5px' }}>
                          {group.ips.map(ip => (
                            <code key={ip} style={{ fontSize: '0.78rem', padding: '2px 7px', backgroundColor: 'var(--bg-secondary)', borderRadius: '4px', color: '#ef4444' }}>
                              {ip}
                            </code>
                          ))}
                        </div>
                      </td>
                      <td style={{ width: '110px' }}>
                        {group.ips.map(ip => (
                          <button
                            key={ip}
                            className="btn btn-secondary"
                            style={{ padding: '5px 10px', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '5px', marginBottom: '4px' }}
                            onClick={() => handleUnblock(ip)}
                            disabled={unblocking === ip}
                          >
                            <ShieldOff size={13} />
                            {unblocking === ip ? '...' : `Unblock ${ip}`}
                          </button>
                        ))}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="3" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      <Shield size={32} style={{ opacity: 0.3, marginBottom: '10px', display: 'block', margin: '0 auto 10px' }} />
                      <p style={{ margin: 0 }}>No active firewall blocks.</p>
                      <p style={{ margin: '6px 0 0 0', fontSize: '0.8rem' }}>
                        Try blocking <strong>youtube.com</strong> above. Run backend with <code>sudo</code> to enforce rules via pfctl.
                      </p>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
