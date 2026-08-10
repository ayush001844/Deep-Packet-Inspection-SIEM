import React, { useRef, useEffect, useState, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Network, Globe, Share2, Info, Radio } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import GeoMap from '../components/GeoMap';

export default function NetworkMap() {
  const { data: graphData, loading } = useApi('/api/network/graph', { interval: 5000 });
  const { data: riskScores } = useApi('/api/risk/scores', { interval: 5000 });
  const [viewMode, setViewMode] = useState('geo'); // 'geo' or 'graph'
  const containerRef = useRef();
  const fgRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    const measure = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight || 600,
        });
      }
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  const handleNodeClick = useCallback(node => {
    if (fgRef.current) {
      fgRef.current.centerAt(node.x, node.y, 800);
      fgRef.current.zoom(4, 800);
    }
  }, []);

  const rawNodes = graphData?.nodes || [];
  const links = graphData?.links || [];
  const isDemo = graphData?.is_demo === true;

  // Create a lookup for risk scores
  const scoreMap = React.useMemo(() => {
    const map = {};
    if (riskScores && Array.isArray(riskScores)) {
      riskScores.forEach(r => { map[r.ip] = r.score; });
    }
    return map;
  }, [riskScores]);

  // Enrich nodes with risk scores
  const nodes = React.useMemo(() => {
    return rawNodes.map(node => ({
      ...node,
      riskScore: scoreMap[node.id] || 0
    }));
  }, [rawNodes, scoreMap]);

  if (loading && !graphData) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 'calc(100vh - 150px)' }}>
        <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
          <Network size={48} style={{ opacity: 0.3, marginBottom: '12px' }} />
          <p>Loading network topology...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="fade-in" style={{ height: 'calc(100vh - 120px)', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '14px 20px',
        backgroundColor: 'var(--bg-elevated)',
        borderBottom: '1px solid var(--border)',
        borderRadius: '8px 8px 0 0',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Network size={20} color="var(--primary)" />
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>
            {isDemo ? 'Network Map (Demo Data)' : `Network Map — ${nodes.length} hosts, ${links.length} flows`}
          </h2>
          {isDemo && (
            <span style={{
              fontSize: '0.75rem', padding: '3px 10px',
              backgroundColor: 'rgba(245,158,11,0.15)', color: '#f59e0b',
              borderRadius: '999px', border: '1px solid rgba(245,158,11,0.3)',
              display: 'flex', alignItems: 'center', gap: '5px'
            }}>
              <Info size={12} /> Start Live Capture for real traffic
            </span>
          )}
          {!isDemo && (
            <span style={{
              fontSize: '0.75rem', padding: '3px 10px',
              backgroundColor: 'rgba(16,185,129,0.15)', color: '#10b981',
              borderRadius: '999px', border: '1px solid rgba(16,185,129,0.3)',
              display: 'flex', alignItems: 'center', gap: '5px'
            }}>
              <Radio size={12} /> Live
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className={`btn ${viewMode === 'geo' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setViewMode('geo')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Globe size={15} /> Geo Map
          </button>
          <button
            className={`btn ${viewMode === 'graph' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setViewMode('graph')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Share2 size={15} /> Force Graph
          </button>
        </div>
      </div>

      {/* Map area */}
      <div
        ref={containerRef}
        style={{
          flex: 1,
          backgroundColor: '#0a0a0b',
          borderRadius: '0 0 8px 8px',
          border: '1px solid var(--border)',
          borderTop: 'none',
          overflow: 'hidden',
          position: 'relative',
        }}
      >
        {viewMode === 'graph' ? (
          <ForceGraph2D
            ref={fgRef}
            width={dimensions.width}
            height={dimensions.height}
            graphData={{ nodes, links }}
            nodeLabel={node => {
              const risk = node.risk_score || 0;
              const attack = node.ml_attack || '';
              const type = node.node_type || 'unknown';
              return [
                node.label || node.id,
                `Type: ${type}`,
                `Risk Score: ${risk}/100`,
                attack ? `AI Detected: ${attack}` : '',
                `Attack Count: ${node.attack_count || 0}`,
              ].filter(Boolean).join('\n');
            }}
            nodeColor={node => {
              const risk = node.risk_score || 0;
              if (risk >= 75) return '#ef4444';
              if (risk >= 50) return '#f97316';
              if (risk >= 25) return '#eab308';
              const typeColors = { database: '#8b5cf6', web_server: '#3b82f6', internal: '#22c55e', external: '#64748b' };
              return typeColors[node.node_type] || '#3b82f6';
            }}
            nodeRelSize={6}
            nodeVal={node => Math.max(1, 1 + (node.attack_count || 0) * 0.8 + (node.val || 1) * 0.4)}
            linkColor={link => link.is_suspicious ? '#ef4444' : 'rgba(255,255,255,0.15)'}
            linkWidth={link => link.is_suspicious ? 2.5 : 1}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkLabel={link => link.protocol || ''}
            backgroundColor="#0a0a0b"
            onNodeClick={handleNodeClick}
            onNodeDragEnd={node => { node.fx = node.x; node.fy = node.y; }}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = (node.label || node.id).split('.').slice(-2).join('.');
              const fontSize = Math.max(10 / globalScale, 3.5);
              const risk = node.risk_score || 0;
              const attackCount = node.attack_count || 0;
              // Size: base + attack_count contribution
              const r = Math.sqrt(Math.max(0, node.val || 1)) * 3 + 4 + Math.min(attackCount * 0.5, 6);

              // Glow color
              const glowColor = risk >= 75 ? '#ef4444' : risk >= 50 ? '#f97316' : risk >= 25 ? '#eab308' : null;
              if (glowColor) { ctx.shadowColor = glowColor; ctx.shadowBlur = 14; }

              // Node shape by type
              const nodeType = node.node_type || 'unknown';
              const fillColor = risk >= 75 ? '#ef4444' : risk >= 50 ? '#f97316' : risk >= 25 ? '#eab308'
                : nodeType === 'database' ? '#8b5cf6' : nodeType === 'web_server' ? '#3b82f6'
                : nodeType === 'internal' ? '#22c55e' : nodeType === 'attacker' ? '#ef4444' : '#64748b';

              ctx.fillStyle = fillColor;

              if (nodeType === 'database') {
                // Diamond shape for databases
                ctx.beginPath();
                ctx.moveTo(node.x, node.y - r * 1.2);
                ctx.lineTo(node.x + r * 1.2, node.y);
                ctx.lineTo(node.x, node.y + r * 1.2);
                ctx.lineTo(node.x - r * 1.2, node.y);
                ctx.closePath();
                ctx.fill();
              } else if (nodeType === 'attacker') {
                // Star/alert shape
                ctx.beginPath();
                for (let i = 0; i < 6; i++) {
                  const angle = (i * Math.PI) / 3;
                  const rr = i % 2 === 0 ? r * 1.3 : r * 0.65;
                  i === 0 ? ctx.moveTo(node.x + rr * Math.cos(angle), node.y + rr * Math.sin(angle))
                          : ctx.lineTo(node.x + rr * Math.cos(angle), node.y + rr * Math.sin(angle));
                }
                ctx.closePath();
                ctx.fill();
              } else {
                // Circle for all others
                ctx.beginPath();
                ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
                ctx.fill();
              }
              ctx.shadowBlur = 0;

              // Draw label
              ctx.font = `${fontSize}px Inter, sans-serif`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'top';
              ctx.fillStyle = 'rgba(255,255,255,0.8)';
              ctx.fillText(label, node.x, node.y + r + 3);

              // Risk badge on high-risk nodes
              if (risk >= 25) {
                const badgeFontSize = Math.max(8 / globalScale, 3);
                ctx.font = `bold ${badgeFontSize}px Inter, sans-serif`;
                ctx.fillStyle = glowColor || '#eab308';
                ctx.fillText(`${risk}`, node.x, node.y - r - badgeFontSize - 1);
              }
            }}
          />
        ) : (
          <GeoMap nodes={nodes} links={links} />
        )}

        {/* Legend */}
        <div style={{
          position: 'absolute', bottom: '16px', right: '16px',
          backgroundColor: 'rgba(15,15,20,0.92)',
          backdropFilter: 'blur(8px)',
          padding: '12px 16px',
          borderRadius: '10px',
          border: '1px solid var(--border)',
          minWidth: '185px',
        }}>
          <h4 style={{ margin: '0 0 10px 0', fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Intelligence Legend</h4>
          {[
            { color: '#22c55e', label: 'Internal Host (safe)', shape: 'circle' },
            { color: '#3b82f6', label: 'Web Server',           shape: 'circle' },
            { color: '#8b5cf6', label: 'Database ◆',          shape: 'diamond' },
            { color: '#eab308', label: 'Medium Risk (25+)',    shape: 'circle' },
            { color: '#f97316', label: 'High Risk (50+)',      shape: 'circle' },
            { color: '#ef4444', label: 'Attacker ★ (75+)',    shape: 'star' },
          ].map(({ color, label }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '7px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }} />
              <span style={{ fontSize: '0.78rem' }}>{label}</span>
            </div>
          ))}
          <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{ width: '20px', height: '2px', backgroundColor: '#ef4444' }} />
              <span style={{ fontSize: '0.78rem' }}>Suspicious Flow</span>
            </div>
          </div>
        </div>

        {/* Stats overlay */}
        <div style={{
          position: 'absolute', top: '16px', left: '16px',
          display: 'flex', gap: '10px',
        }}>
          {[
            { label: 'Hosts', value: nodes.length, color: '#3b82f6' },
            { label: 'Flows', value: links.length, color: '#8b5cf6' },
            { label: 'Attackers', value: nodes.filter(n => n.node_type === 'attacker' || n.group === 1).length, color: '#ef4444' },
            { label: 'High Risk', value: nodes.filter(n => (n.risk_score || 0) >= 50).length, color: '#f97316' },
          ].map(stat => (
            <div key={stat.label} style={{
              backgroundColor: 'rgba(15,15,20,0.85)',
              backdropFilter: 'blur(8px)',
              padding: '8px 14px',
              borderRadius: '8px',
              border: `1px solid ${stat.color}33`,
              textAlign: 'center',
            }}>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, color: stat.color }}>{stat.value}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{stat.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
