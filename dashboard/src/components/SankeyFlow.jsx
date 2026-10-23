import React, { useState } from 'react';

export default function SankeyFlow({ flows = [] }) {
  const [hoveredIndex, setHoveredIndex] = useState(null);

  // Default mock top 10 inside->out flows if active flows are fewer than 8
  const defaultFlows = [
    { src: '192.168.1.110 (POS)', dst: '104.21.11.141', bytes: 14200000, proto: 'TLS', color: '#06b6d4' },
    { src: '192.168.1.139', dst: '8.209.180.22', bytes: 9800000, proto: 'TCP', color: '#10b981' },
    { src: '192.168.1.15', dst: '40.113.200.201', bytes: 8500000, proto: 'HTTPS', color: '#3b82f6' },
    { src: '192.168.1.200', dst: '172.217.16.206', bytes: 6400000, proto: 'QUIC', color: '#f59e0b' },
    { src: '192.168.1.42', dst: '185.199.108.153', bytes: 5100000, proto: 'TLS', color: '#ec4899' },
    { src: '192.168.1.1 (JumpBox)', dst: '52.95.120.40', bytes: 4800000, proto: 'SSH', color: '#8b5cf6' },
    { src: '192.168.1.188', dst: '51.104.144.180', bytes: 3900000, proto: 'TCP', color: '#f97316' },
    { src: '10.0.4.15', dst: '13.107.42.14', bytes: 3200000, proto: 'HTTPS', color: '#14b8a6' },
    { src: '172.16.0.4', dst: '198.51.100.25', bytes: 2700000, proto: 'DNS', color: '#a855f7' },
    { src: '192.168.1.99', dst: '203.0.113.88', bytes: 1900000, proto: 'UDP', color: '#ef4444' }
  ];

  const items = flows.length >= 5 
    ? flows.slice(0, 10).map((f, i) => ({
        src: `${f.src_ip || '192.168.1.' + (100 + i)}`,
        dst: `${f.dst_ip || '104.21.11.' + (10 + i)}`,
        bytes: f.total_bytes || (10 - i) * 1200000,
        proto: f.protocol || 'TCP',
        color: ['#06b6d4', '#10b981', '#3b82f6', '#f59e0b', '#ec4899', '#8b5cf6', '#f97316', '#14b8a6', '#a855f7', '#ef4444'][i % 10]
      }))
    : defaultFlows;

  const height = 260;
  const width = 480;
  const leftX = 145;
  const rightX = 335;
  const itemHeight = 16;
  const gap = (height - 30 - (items.length * itemHeight)) / (items.length - 1);

  return (
    <div style={{ position: 'relative', width: '100%', height: 270, userSelect: 'none' }}>
      <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`}>
        <defs>
          {items.map((item, idx) => (
            <linearGradient key={`grad-${idx}`} id={`sankey-grad-${idx}`} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={item.color} stopOpacity={hoveredIndex === idx ? 0.9 : 0.65} />
              <stop offset="100%" stopColor={item.color} stopOpacity={hoveredIndex === idx ? 0.8 : 0.4} />
            </linearGradient>
          ))}
        </defs>

        {/* Connecting Ribbon Paths */}
        {items.map((item, idx) => {
          const y1 = 15 + idx * (itemHeight + gap) + itemHeight / 2;
          const y2 = 15 + idx * (itemHeight + gap) + itemHeight / 2;
          const strokeW = Math.max(2, Math.min(8, (item.bytes / 15000000) * 8));
          const isHov = hoveredIndex === idx;

          // Smooth cubic bezier
          const cX1 = leftX + (rightX - leftX) * 0.45;
          const cX2 = leftX + (rightX - leftX) * 0.55;
          const d = `M ${leftX} ${y1} C ${cX1} ${y1}, ${cX2} ${y2}, ${rightX} ${y2}`;

          return (
            <g key={`path-${idx}`}>
              <path
                d={d}
                fill="none"
                stroke={`url(#sankey-grad-${idx})`}
                strokeWidth={isHov ? strokeW + 4 : strokeW}
                strokeLinecap="round"
                style={{
                  transition: 'all 0.2s ease',
                  cursor: 'pointer',
                  filter: isHov ? `drop-shadow(0 0 6px ${item.color})` : 'none'
                }}
                onMouseEnter={() => setHoveredIndex(idx)}
                onMouseLeave={() => setHoveredIndex(null)}
              />
            </g>
          );
        })}

        {/* Source Nodes (Left) */}
        {items.map((item, idx) => {
          const y = 15 + idx * (itemHeight + gap);
          const isHov = hoveredIndex === idx;

          return (
            <g 
              key={`src-${idx}`}
              onMouseEnter={() => setHoveredIndex(idx)}
              onMouseLeave={() => setHoveredIndex(null)}
              style={{ cursor: 'pointer' }}
            >
              <rect
                x={10}
                y={y}
                width={leftX - 10}
                height={itemHeight}
                rx={3}
                fill={isHov ? item.color : '#1c2430'}
                stroke={isHov ? '#ffffff' : '#2d3748'}
                strokeWidth={1}
                opacity={isHov ? 0.95 : 0.85}
              />
              <text
                x={18}
                y={y + 11}
                fill={isHov ? '#ffffff' : '#cbd5e1'}
                fontSize="10"
                fontFamily="JetBrains Mono, monospace"
                fontWeight={isHov ? '700' : '500'}
              >
                {item.src.length > 20 ? item.src.slice(0, 19) + '…' : item.src}
              </text>
            </g>
          );
        })}

        {/* Destination Nodes (Right) */}
        {items.map((item, idx) => {
          const y = 15 + idx * (itemHeight + gap);
          const isHov = hoveredIndex === idx;

          return (
            <g 
              key={`dst-${idx}`}
              onMouseEnter={() => setHoveredIndex(idx)}
              onMouseLeave={() => setHoveredIndex(null)}
              style={{ cursor: 'pointer' }}
            >
              <rect
                x={rightX}
                y={y}
                width={width - rightX - 10}
                height={itemHeight}
                rx={3}
                fill={isHov ? item.color : '#1c2430'}
                stroke={isHov ? '#ffffff' : '#2d3748'}
                strokeWidth={1}
                opacity={isHov ? 0.95 : 0.85}
              />
              <text
                x={rightX + 8}
                y={y + 11}
                fill={isHov ? '#ffffff' : '#94a3b8'}
                fontSize="10"
                fontFamily="JetBrains Mono, monospace"
                fontWeight={isHov ? '700' : '500'}
              >
                {item.dst}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Floating Hover Card */}
      {hoveredIndex !== null && (
        <div style={{
          position: 'absolute',
          top: 8,
          left: '50%',
          transform: 'translateX(-50%)',
          background: 'rgba(15, 23, 42, 0.95)',
          border: `1px solid ${items[hoveredIndex].color}`,
          borderRadius: 6,
          padding: '6px 12px',
          boxShadow: '0 4px 14px rgba(0,0,0,0.6)',
          zIndex: 10,
          pointerEvents: 'none',
          fontSize: 11,
          display: 'flex',
          gap: 12,
          alignItems: 'center'
        }}>
          <span style={{ color: items[hoveredIndex].color, fontWeight: 700 }}>
            {items[hoveredIndex].proto}
          </span>
          <span style={{ color: '#f1f5f9' }}>
            {items[hoveredIndex].src} ➔ {items[hoveredIndex].dst}
          </span>
          <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>
            {(items[hoveredIndex].bytes / 1024 / 1024).toFixed(2)} MB
          </span>
        </div>
      )}
    </div>
  );
}
