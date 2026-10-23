import React, { useState } from 'react';

const ALGORITHM_CONFIG = [
  { name: 'irctraffic', count: 18450, color: '#38bdf8' },
  { name: '6in4tunnel', count: 17200, color: '#34d399' },
  { name: 'nmapfingerprint', count: 16800, color: '#60a5fa' },
  { name: 'alltcpflags', count: 16100, color: '#fbbf24' },
  { name: 'badprotocol', count: 15400, color: '#1e40af' },
  { name: 'sshbrute', count: 14200, color: '#f87171' },
  { name: 'censys_scanning', count: 13900, color: '#f43f5e' },
  { name: 'synflood', count: 13100, color: '#ef4444' },
  { name: 'dcplusplus', count: 12400, color: '#c084fc' },
  { name: 'knownbotnet', count: 11800, color: '#2dd4bf' },
  { name: 'ripreflection', count: 11200, color: '#38bdf8' },
  { name: 'shadowserver_scanning', count: 10500, color: '#818cf8' },
  { name: 'knownspamsrc', count: 9800, color: '#facc15' },
  { name: 'rstflood', count: 9100, color: '#fb923c' },
  { name: 'dnsattack', count: 8600, color: '#a855f7' },
  { name: 'noflow', count: 7900, color: '#94a3b8' },
  { name: 'ipmi', count: 7200, color: '#f472b6' },
  { name: 'log4j_detection', count: 6800, color: '#10b981' },
  { name: 'mirai_detection', count: 6100, color: '#06b6d4' },
  { name: 'windows_scanner_from_germany', count: 5400, color: '#e879f9' },
];

export default function AlgorithmAlertsBar({ liveAlerts = [] }) {
  const [hoveredAlgo, setHoveredAlgo] = useState(null);

  // Blend live alerts if any detected
  const algorithms = ALGORITHM_CONFIG.map(algo => {
    const liveMatches = liveAlerts.filter(a => 
      (a.title && a.title.toLowerCase().includes(algo.name.toLowerCase())) ||
      (a.signature && a.signature.toLowerCase().includes(algo.name.toLowerCase()))
    ).length;

    return {
      ...algo,
      count: algo.count + (liveMatches * 250)
    };
  });

  const maxCount = Math.max(...algorithms.map(a => a.count));

  return (
    <div className="card" style={{ padding: '16px 20px', marginBottom: 18, background: '#131922', border: '1px solid #1e2634' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 700, letterSpacing: '-0.2px', color: '#f1f5f9' }}>
          Alerts
        </h3>
        <span style={{ fontSize: 11, color: '#64748b', fontFamily: 'monospace' }}>
          alerts by algorithm (top 20)
        </span>
      </div>

      {/* Horizontal Multi-Algorithm Bars */}
      <div style={{ position: 'relative', width: '100%', height: 75, background: '#0b0f16', borderRadius: 4, padding: '4px 6px', overflow: 'hidden', border: '1px solid #1b2230' }}>
        {algorithms.map((algo, i) => {
          const widthPct = (algo.count / maxCount) * 100;
          const topPos = (i / algorithms.length) * 65;
          const isHov = hoveredAlgo && hoveredAlgo.name === algo.name;

          return (
            <div
              key={algo.name}
              style={{
                position: 'absolute',
                top: `${topPos}px`,
                left: 0,
                width: `${widthPct}%`,
                height: 3.2,
                backgroundColor: algo.color,
                borderRadius: '0 2px 2px 0',
                transition: 'all 0.2s ease',
                cursor: 'pointer',
                opacity: isHov ? 1 : 0.85,
                boxShadow: isHov ? `0 0 8px ${algo.color}` : 'none'
              }}
              onMouseEnter={() => setHoveredAlgo(algo)}
              onMouseLeave={() => setHoveredAlgo(null)}
            />
          );
        })}

        {/* Hover detail tooltip */}
        {hoveredAlgo && (
          <div style={{
            position: 'absolute',
            right: 12,
            top: 12,
            background: 'rgba(15, 23, 42, 0.95)',
            border: `1px solid ${hoveredAlgo.color}`,
            borderRadius: 4,
            padding: '4px 10px',
            fontSize: 11,
            pointerEvents: 'none',
            color: '#f8fafc',
            display: 'flex',
            gap: 8,
            alignItems: 'center'
          }}>
            <span style={{ width: 8, height: 8, background: hoveredAlgo.color, borderRadius: 2 }} />
            <span style={{ fontWeight: 600 }}>{hoveredAlgo.name}</span>
            <span className="mono" style={{ color: '#38bdf8' }}>{hoveredAlgo.count.toLocaleString()} triggers</span>
          </div>
        )}
      </div>

      {/* Legend Grid Matching Netography Layout */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
        gap: '6px 14px',
        marginTop: 14,
        paddingTop: 10,
        borderTop: '1px solid #1c2432',
        fontSize: 10,
        color: '#94a3b8'
      }}>
        {algorithms.map((algo) => (
          <div 
            key={algo.name}
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: 6, 
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }}
            onMouseEnter={() => setHoveredAlgo(algo)}
            onMouseLeave={() => setHoveredAlgo(null)}
          >
            <span style={{ width: 10, height: 3, background: algo.color, borderRadius: 1, flexShrink: 0 }} />
            <span style={{ color: hoveredAlgo?.name === algo.name ? '#ffffff' : '#94a3b8' }}>
              {algo.name}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
