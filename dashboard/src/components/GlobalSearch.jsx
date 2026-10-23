import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Search, X, Globe, ShieldAlert, Server, Radio, 
  ArrowRight, CornerDownLeft, ExternalLink, Hash, Copy, Check
} from 'lucide-react';
import { useApi } from '../hooks/useApi';

const NAVIGATION_ITEMS = [
  { title: 'Dashboard Overview', category: 'Pages', path: '/', description: 'Executive metrics, throughput, live rates & world attack map' },
  { title: 'Live Packet Capture', category: 'Pages', path: '/capture', description: 'Real-time sniffer controls, pcap stream buffer' },
  { title: 'Packet Log & Inspection', category: 'Pages', path: '/packets', description: 'Raw packet table, protocol decoder, payload viewer' },
  { title: 'Active Network Flows', category: 'Pages', path: '/flows', description: 'Bidirectional sessions, top talkers, flow durations' },
  { title: 'Threat Intelligence', category: 'Pages', path: '/threats', description: 'Security alert feed, IOC blacklist matches, threat levels' },
  { title: 'Incident Response', category: 'Pages', path: '/incidents', description: 'Case management, mitigation timeline, SOAR playbooks' },
  { title: 'Network Topology Map', category: 'Pages', path: '/map', description: 'Force-directed graph of node interactions' },
  { title: 'Attack Timeline', category: 'Pages', path: '/timeline', description: 'Chronological security events and anomaly spikes' },
  { title: 'MITRE ATT&CK Matrix', category: 'Pages', path: '/mitre', description: 'Tactics and techniques heat map' },
  { title: 'AI & ML Detection', category: 'Pages', path: '/ml', description: 'Multi-class supervised ML models & confidence scores' },
  { title: 'Anomaly Autoencoder', category: 'Pages', path: '/anomaly', description: 'Unsupervised reconstruction loss anomaly detector' },
  { title: 'User & Entity Behavior (UEBA)', category: 'Pages', path: '/ueba', description: 'Peer group deviations and risk scoring' },
  { title: 'PCAP Offline Analysis', category: 'Pages', path: '/pcap', description: 'Upload .pcap files, inspect DNS, HTTP, TLS, & IOCs' },
  { title: 'Firewall & DPI Rules', category: 'Pages', path: '/rules', description: 'Signature rules, domain blacklist, IP blocking rules' },
  { title: 'System Settings', category: 'Pages', path: '/settings', description: 'Interface bindings, capture filters, notification webhooks' },
];

const COMMON_PORTS = [
  { port: 80, proto: 'HTTP', service: 'Web / Unencrypted', risk: 'Medium' },
  { port: 443, proto: 'HTTPS / TLS', service: 'Secure Web / SSL', risk: 'Low' },
  { port: 53, proto: 'DNS', service: 'Domain Name System', risk: 'Info' },
  { port: 22, proto: 'SSH', service: 'Secure Shell Remote Access', risk: 'High' },
  { port: 21, proto: 'FTP', service: 'File Transfer Protocol', risk: 'High' },
  { port: 25, proto: 'SMTP', service: 'Simple Mail Transfer', risk: 'Medium' },
  { port: 3389, proto: 'RDP', service: 'Remote Desktop Protocol', risk: 'Critical' },
  { port: 445, proto: 'SMB', service: 'Server Message Block', risk: 'Critical' },
  { port: 8080, proto: 'HTTP-Proxy', service: 'Alternate Web / Proxies', risk: 'Medium' },
  { port: 123, proto: 'NTP', service: 'Network Time Protocol', risk: 'Low' },
];

export default function GlobalSearch({ isOpen, onClose }) {
  const [query, setQuery] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [copiedText, setCopiedText] = useState(null);
  
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const navigate = useNavigate();

  // Fetch contextual network data
  const { data: alertsData } = useApi('/api/alerts?limit=50', { immediate: isOpen });
  const { data: packetsData } = useApi('/api/packets?limit=50', { immediate: isOpen });
  const { data: sessionsData } = useApi('/api/sessions?limit=50', { immediate: isOpen });
  const { data: blockedData } = useApi('/api/firewall/blocked', { immediate: isOpen });

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setSelectedIndex(0);
    } else {
      setQuery('');
      setCopiedText(null);
    }
  }, [isOpen]);

  // Aggregate searchable items
  const searchResults = useMemo(() => {
    const q = query.toLowerCase().trim();
    const results = [];

    // 1. Pages & Features
    NAVIGATION_ITEMS.forEach(item => {
      if (!q || item.title.toLowerCase().includes(q) || item.description.toLowerCase().includes(q)) {
        results.push({
          id: `page-${item.path}`,
          type: 'Pages',
          title: item.title,
          subtitle: item.description,
          icon: ExternalLink,
          action: () => {
            navigate(item.path);
            onClose();
          },
        });
      }
    });

    // 2. IP Addresses (unique list from sessions, packets, and blocked)
    const ipMap = new Map();

    (sessionsData?.sessions || []).forEach(s => {
      if (s.src_ip && !ipMap.has(s.src_ip)) {
        ipMap.set(s.src_ip, { ip: s.src_ip, type: 'Active Flow Source', extra: s.protocol || 'IP', suspicious: s.is_suspicious });
      }
      if (s.dst_ip && !ipMap.has(s.dst_ip)) {
        ipMap.set(s.dst_ip, { ip: s.dst_ip, type: 'Active Flow Target', extra: s.protocol || 'IP', suspicious: s.is_suspicious });
      }
    });

    (packetsData?.packets || []).forEach(p => {
      if (p.src_ip && !ipMap.has(p.src_ip)) {
        ipMap.set(p.src_ip, { ip: p.src_ip, type: 'Captured Host', extra: p.protocol || 'IP' });
      }
      if (p.dst_ip && !ipMap.has(p.dst_ip)) {
        ipMap.set(p.dst_ip, { ip: p.dst_ip, type: 'Destination Host', extra: p.protocol || 'IP' });
      }
    });

    (blockedData?.blocked_ips || []).forEach(ip => {
      if (!ipMap.has(ip)) {
        ipMap.set(ip, { ip, type: 'Firewall Blocked', extra: 'BLOCKED', suspicious: true });
      } else {
        const item = ipMap.get(ip);
        item.extra = 'BLOCKED';
        item.suspicious = true;
      }
    });

    ipMap.forEach(({ ip, type, extra, suspicious }) => {
      if (!q || ip.toLowerCase().includes(q) || type.toLowerCase().includes(q)) {
        results.push({
          id: `ip-${ip}`,
          type: 'IPs',
          title: ip,
          subtitle: `${type} • ${extra}`,
          badge: suspicious ? 'SUSPICIOUS' : 'HOST',
          badgeColor: suspicious ? 'var(--critical)' : 'var(--accent)',
          icon: Globe,
          action: () => {
            navigate(`/packets?filter=${encodeURIComponent(ip)}`);
            onClose();
          },
          copyVal: ip,
        });
      }
    });

    // 3. Domains & Hosts
    const domainSet = new Set();
    (sessionsData?.sessions || []).forEach(s => {
      if (s.sni) domainSet.add({ domain: s.sni, type: 'TLS SNI', ip: s.dst_ip });
      if (s.http_host) domainSet.add({ domain: s.http_host, type: 'HTTP Host', ip: s.dst_ip });
    });
    (packetsData?.packets || []).forEach(p => {
      if (p.dns_query) domainSet.add({ domain: p.dns_query, type: 'DNS Query', ip: p.dst_ip });
      if (p.http_host) domainSet.add({ domain: p.http_host, type: 'HTTP Host', ip: p.dst_ip });
      if (p.tls_sni) domainSet.add({ domain: p.tls_sni, type: 'TLS SNI', ip: p.dst_ip });
    });

    domainSet.forEach(({ domain, type, ip }) => {
      if (!q || domain.toLowerCase().includes(q) || type.toLowerCase().includes(q)) {
        results.push({
          id: `domain-${domain}`,
          type: 'Domains',
          title: domain,
          subtitle: `${type} → Target IP: ${ip || 'unknown'}`,
          icon: Globe,
          action: () => {
            navigate(`/packets?filter=${encodeURIComponent(domain)}`);
            onClose();
          },
          copyVal: domain,
        });
      }
    });

    // 4. Ports & Protocols
    COMMON_PORTS.forEach(item => {
      const match = !q || 
        String(item.port).includes(q) || 
        item.proto.toLowerCase().includes(q) || 
        item.service.toLowerCase().includes(q);

      if (match) {
        results.push({
          id: `port-${item.port}`,
          type: 'Ports',
          title: `Port ${item.port} (${item.proto})`,
          subtitle: item.service,
          badge: item.risk,
          badgeColor: item.risk === 'Critical' ? 'var(--critical)' : item.risk === 'High' ? 'var(--high)' : 'var(--accent)',
          icon: Hash,
          action: () => {
            navigate(`/packets?port=${item.port}`);
            onClose();
          },
        });
      }
    });

    // 5. Security Alerts & Threat Signatures
    const alertsList = Array.isArray(alertsData) ? alertsData : (alertsData?.alerts || []);
    alertsList.forEach((alert, idx) => {
      const msg = alert.signature || alert.message || alert.type || 'Security Alert';
      const src = alert.src_ip || 'N/A';
      const dst = alert.dst_ip || 'N/A';
      const sev = alert.severity || 'high';

      if (!q || msg.toLowerCase().includes(q) || src.includes(q) || dst.includes(q) || sev.toLowerCase().includes(q)) {
        results.push({
          id: `alert-${idx}`,
          type: 'Threats',
          title: msg,
          subtitle: `Src: ${src} → Dst: ${dst} • Severity: ${String(sev).toUpperCase()}`,
          badge: String(sev).toUpperCase(),
          badgeColor: String(sev).toLowerCase().includes('crit') ? 'var(--critical)' : 'var(--high)',
          icon: ShieldAlert,
          action: () => {
            navigate('/threats');
            onClose();
          },
        });
      }
    });

    // Filter by active tab
    if (activeTab === 'all') return results;
    return results.filter(r => r.type.toLowerCase() === activeTab.toLowerCase());
  }, [query, activeTab, sessionsData, packetsData, blockedData, alertsData, navigate, onClose]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (!isOpen) return;

      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex(prev => (prev < searchResults.length - 1 ? prev + 1 : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex(prev => (prev > 0 ? prev - 1 : Math.max(0, searchResults.length - 1)));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (searchResults[selectedIndex]) {
          searchResults[selectedIndex].action();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, searchResults, selectedIndex, onClose]);

  const handleCopy = (e, val) => {
    e.stopPropagation();
    try {
      navigator.clipboard.writeText(val);
      setCopiedText(val);
      setTimeout(() => setCopiedText(null), 1500);
    } catch {}
  };

  if (!isOpen) return null;

  return (
    <div className="global-search-backdrop" onClick={onClose}>
      <div className="global-search-modal" onClick={e => e.stopPropagation()}>
        {/* Search Input Bar */}
        <div className="global-search-header">
          <Search size={20} className="search-icon" />
          <input
            ref={inputRef}
            type="text"
            className="global-search-input"
            placeholder="Search across IPs, domains, ports, protocols, alerts, and pages..."
            value={query}
            onChange={e => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
          />
          {query && (
            <button className="global-search-clear" onClick={() => setQuery('')}>
              <X size={16} />
            </button>
          )}
          <span className="search-kbd-hint">ESC to close</span>
        </div>

        {/* Category Tabs */}
        <div className="global-search-tabs">
          {['all', 'ips', 'domains', 'ports', 'threats', 'pages'].map(tab => (
            <button
              key={tab}
              className={`search-tab ${activeTab === tab ? 'active' : ''}`}
              onClick={() => {
                setActiveTab(tab);
                setSelectedIndex(0);
              }}
            >
              {tab.toUpperCase()}
            </button>
          ))}
        </div>

        {/* Results List */}
        <div className="global-search-results" ref={listRef}>
          {searchResults.length === 0 ? (
            <div className="search-empty">
              <Search size={32} style={{ opacity: 0.3, marginBottom: 8 }} />
              <p>No results found for "{query}"</p>
              <small>Try searching for an IP (192.168.1.1), port (443), protocol (TLS), or alert signature</small>
            </div>
          ) : (
            searchResults.map((item, idx) => {
              const Icon = item.icon || Radio;
              const isSelected = idx === selectedIndex;

              return (
                <div
                  key={item.id}
                  className={`search-result-item ${isSelected ? 'selected' : ''}`}
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(idx)}
                >
                  <div className="search-item-icon">
                    <Icon size={18} />
                  </div>
                  
                  <div className="search-item-content">
                    <div className="search-item-title-row">
                      <span className="search-item-title">{item.title}</span>
                      {item.badge && (
                        <span 
                          className="search-badge" 
                          style={{ color: item.badgeColor, borderColor: item.badgeColor }}
                        >
                          {item.badge}
                        </span>
                      )}
                    </div>
                    <span className="search-item-subtitle">{item.subtitle}</span>
                  </div>

                  <div className="search-item-actions">
                    {item.copyVal && (
                      <button
                        className="search-action-btn"
                        title="Copy to clipboard"
                        onClick={e => handleCopy(e, item.copyVal)}
                      >
                        {copiedText === item.copyVal ? <Check size={14} color="var(--success)" /> : <Copy size={14} />}
                      </button>
                    )}
                    <span className="search-enter-hint">
                      <CornerDownLeft size={13} />
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="global-search-footer">
          <div className="footer-shortcuts">
            <span><kbd>↑</kbd> <kbd>↓</kbd> Navigate</span>
            <span><kbd>↵</kbd> Select</span>
            <span><kbd>ESC</kbd> Close</span>
          </div>
          <span className="results-count">{searchResults.length} matching items</span>
        </div>
      </div>
    </div>
  );
}
