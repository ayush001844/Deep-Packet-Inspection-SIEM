import React, { useState } from 'react';

export default function RadialClock() {
  const [hoveredSlice, setHoveredSlice] = useState(null);

  const size = 260;
  const center = size / 2;
  const hours = ['11:00', '12:00', '13:00', '14:00', '15:00'];
  const minuteTicks = [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55];
  
  const ringWidth = 14;
  const innerRadius = 38;

  // Generate slice colors simulating time-bucketed activity
  const ringsData = hours.map((hour, hIdx) => {
    return Array.from({ length: 12 }, (_, mIdx) => {
      // Deterministic activity simulation for visual excellence
      const hash = (hIdx * 17 + mIdx * 29) % 100;
      let color = '#0f172a'; // idle
      let level = 'Idle';
      let count = 0;

      if (hIdx === 4 || (hIdx === 3 && mIdx > 6)) {
        if (hash > 60) {
          color = '#f87171'; // > 22k
          level = '> 22k pkts/min';
          count = 24500 + hash * 50;
        } else if (hash > 25) {
          color = '#fb923c'; // ~ 15k
          level = '~ 15k pkts/min';
          count = 14800 + hash * 40;
        } else {
          color = '#2dd4bf'; // ~ 5k
          level = '~ 5k pkts/min';
          count = 5200 + hash * 20;
        }
      } else if (hIdx >= 2) {
        if (hash > 50) {
          color = '#fb923c';
          level = '~ 15k pkts/min';
          count = 15200;
        } else {
          color = '#2dd4bf';
          level = '~ 5k pkts/min';
          count = 4900;
        }
      } else {
        color = hash > 70 ? '#2dd4bf' : '#1e293b';
        level = hash > 70 ? '~ 5k pkts/min' : 'Low activity';
        count = hash > 70 ? 4600 : 1200;
      }

      return {
        hour,
        minute: mIdx * 5,
        color,
        level,
        count
      };
    });
  });

  // SVG arc path helper
  const polarToCartesian = (cx, cy, r, angleDeg) => {
    const angleRad = ((angleDeg - 90) * Math.PI) / 180.0;
    return {
      x: cx + r * Math.cos(angleRad),
      y: cy + r * Math.sin(angleRad),
    };
  };

  const describeArc = (x, y, rInner, rOuter, startAngle, endAngle) => {
    const startInner = polarToCartesian(x, y, rInner, endAngle);
    const endInner = polarToCartesian(x, y, rInner, startAngle);
    const startOuter = polarToCartesian(x, y, rOuter, startAngle);
    const endOuter = polarToCartesian(x, y, rOuter, endAngle);
    const arcSweep = endAngle - startAngle <= 180 ? '0' : '1';

    return [
      'M', startOuter.x, startOuter.y,
      'A', rOuter, rOuter, 0, arcSweep, 1, endOuter.x, endOuter.y,
      'L', startInner.x, startInner.y,
      'A', rInner, rInner, 0, arcSweep, 0, endInner.x, endInner.y,
      'Z',
    ].join(' ');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', userSelect: 'none' }}>
      <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6, fontWeight: 500 }}>
        2026-10-23 11:43 - 2026-10-23 15:43
      </div>

      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size}>
          {/* Minute Labels (Outer Dial) */}
          {minuteTicks.map((min) => {
            const angle = (min / 60) * 360;
            const pt = polarToCartesian(center, center, center - 10, angle);
            return (
              <text
                key={`tick-${min}`}
                x={pt.x}
                y={pt.y + 3}
                fill="#64748b"
                fontSize="9"
                fontWeight="600"
                textAnchor="middle"
                fontFamily="JetBrains Mono, monospace"
              >
                {min}
              </text>
            );
          })}

          {/* Radial Guideline Rays */}
          {minuteTicks.map((min) => {
            const angle = (min / 60) * 360;
            const pt1 = polarToCartesian(center, center, innerRadius - 4, angle);
            const pt2 = polarToCartesian(center, center, center - 18, angle);
            return (
              <line
                key={`ray-${min}`}
                x1={pt1.x}
                y1={pt1.y}
                x2={pt2.x}
                y2={pt2.y}
                stroke="#1e293b"
                strokeWidth="1"
                strokeDasharray="2 2"
              />
            );
          })}

          {/* Rings & Segmented Arcs */}
          {ringsData.map((ring, hIdx) => {
            const rIn = innerRadius + hIdx * ringWidth;
            const rOut = rIn + ringWidth - 2;

            return (
              <g key={`ring-${hIdx}`}>
                {ring.map((slice, mIdx) => {
                  const startAngle = (mIdx / 12) * 360 + 0.5;
                  const endAngle = ((mIdx + 1) / 12) * 360 - 0.5;
                  const path = describeArc(center, center, rIn, rOut, startAngle, endAngle);
                  const isHov = hoveredSlice && hoveredSlice.hour === slice.hour && hoveredSlice.minute === slice.minute;

                  return (
                    <path
                      key={`slice-${hIdx}-${mIdx}`}
                      d={path}
                      fill={slice.color}
                      stroke={isHov ? '#ffffff' : '#090d16'}
                      strokeWidth={isHov ? 1.5 : 0.75}
                      style={{
                        cursor: 'pointer',
                        transition: 'opacity 0.15s, stroke 0.15s',
                        opacity: isHov ? 1 : 0.88,
                      }}
                      onMouseEnter={() => setHoveredSlice(slice)}
                      onMouseLeave={() => setHoveredSlice(null)}
                    />
                  );
                })}
              </g>
            );
          })}

          {/* Concentric Hour Labels */}
          {hours.map((h, i) => (
            <text
              key={`hour-lbl-${i}`}
              x={center}
              y={center - innerRadius - i * ringWidth + 4}
              fill="#94a3b8"
              fontSize="7"
              fontWeight="700"
              textAnchor="middle"
              fontFamily="JetBrains Mono, monospace"
            >
              {h}
            </text>
          ))}

          {/* Center Hub */}
          <circle cx={center} cy={center} r={innerRadius - 6} fill="#0d141f" stroke="#1e293b" strokeWidth="1" />
          <text
            x={center}
            y={center - 3}
            fill="#38bdf8"
            fontSize="9"
            fontWeight="700"
            textAnchor="middle"
            fontFamily="JetBrains Mono, monospace"
          >
            REALTIME
          </text>
          <text
            x={center}
            y={center + 8}
            fill="#64748b"
            fontSize="8"
            textAnchor="middle"
          >
            RADIAL
          </text>
        </svg>

        {/* Hover Tooltip */}
        {hoveredSlice && (
          <div style={{
            position: 'absolute',
            top: 6,
            left: '50%',
            transform: 'translateX(-50%)',
            background: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid #38bdf8',
            borderRadius: 5,
            padding: '4px 8px',
            fontSize: 10,
            whiteSpace: 'nowrap',
            pointerEvents: 'none',
            zIndex: 10,
            color: '#f8fafc',
            textAlign: 'center'
          }}>
            <strong>{hoveredSlice.hour}:{String(hoveredSlice.minute).padStart(2, '0')}</strong> • {hoveredSlice.level} ({hoveredSlice.count.toLocaleString()} pkts)
          </div>
        )}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, alignItems: 'center', marginTop: 8, fontSize: 10, color: '#94a3b8' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ width: 10, height: 4, background: '#f87171', borderRadius: 2 }} />
          <span>&gt; 22k</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ width: 10, height: 4, background: '#fb923c', borderRadius: 2 }} />
          <span>~ 15k</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ width: 10, height: 4, background: '#2dd4bf', borderRadius: 2 }} />
          <span>~ 5k</span>
        </div>
        <span style={{ color: '#64748b', fontStyle: 'italic' }}>Slice: a minute</span>
      </div>
    </div>
  );
}
