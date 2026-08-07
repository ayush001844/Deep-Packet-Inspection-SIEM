import React, { useRef, useEffect, useState, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Network, Globe, Share2, Info, Radio } from 'lucide-react';
import { useApi } from '../hooks/useApi';
import GeoMap from '../components/GeoMap';

export default function NetworkMap() {
  const { data: graphData, loading } = useApi('/api/network/graph', { interval: 5000 });
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

  const nodes = graphData?.nodes || [];
  const links = graphData?.links || [];
  const isDemo = graphData?.is_demo === true;

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
            nodeLabel={node => `${node.label || node.id}\n${node.id}`}
            nodeColor={node => node.group === 1 ? '#ef4444' : '#3b82f6'}
            nodeRelSize={6}
            nodeVal={node => node.val || 1}
            linkColor={link => link.is_suspicious ? '#ef4444' : 'rgba(255,255,255,0.15)'}
            linkWidth={link => link.is_suspicious ? 2.5 : 1}
            linkDirectionalArrowLength={4}
            linkDirectionalArrowRelPos={1}
            linkLabel={link => link.protocol || ''}
            backgroundColor="#0a0a0b"
            onNodeClick={handleNodeClick}
            onNodeDragEnd={node => { node.fx = node.x; node.fy = node.y; }}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const label = node.label || node.id;
              const fontSize = Math.max(10 / globalScale, 4);
              const r = Math.sqrt(Math.max(0, node.val || 1)) * 4 + 4;
              
              // Draw glow for suspicious
              if (node.group === 1) {
                ctx.shadowColor = '#ef4444';
                ctx.shadowBlur = 12;
              }
              
              // Draw circle
              ctx.beginPath();
              ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false);
              ctx.fillStyle = node.group === 1 ? '#ef4444' : '#3b82f6';
              ctx.fill();
              ctx.shadowBlur = 0;
              
              // Draw label
              ctx.font = `${fontSize}px Inter, sans-serif`;
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = 'rgba(255,255,255,0.85)';
              ctx.fillText(label, node.x, node.y + r + fontSize + 2);
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
          minWidth: '160px',
        }}>
          <h4 style={{ margin: '0 0 10px 0', fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Legend</h4>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#3b82f6', boxShadow: '0 0 6px #3b82f6' }}></div>
            <span style={{ fontSize: '0.85rem' }}>Normal Host</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
            <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: '#ef4444', boxShadow: '0 0 6px #ef4444' }}></div>
            <span style={{ fontSize: '0.85rem' }}>Suspicious / Blocked</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div style={{ width: '20px', height: '2px', backgroundColor: '#ef4444' }}></div>
            <span style={{ fontSize: '0.85rem' }}>Suspicious Flow</span>
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
            { label: 'Suspicious', value: nodes.filter(n => n.group === 1).length, color: '#ef4444' },
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
