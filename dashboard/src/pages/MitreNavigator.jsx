import { useState, useEffect, useCallback } from 'react';
import { Shield, Target, BarChart3, Info, RefreshCw, Link2 } from 'lucide-react';

const API = 'http://localhost:8000';

// Heat level to color mapping
const HEAT_COLORS = {
  none: 'var(--bg-glass)',
  low: '#1a3a2a',
  medium: '#3a3a1a',
  high: '#3a2a1a',
  critical: '#3a1a1a',
};

const HEAT_BORDER_COLORS = {
  none: 'var(--border-subtle)',
  low: '#22c55e44',
  medium: '#eab30844',
  high: '#f9731644',
  critical: '#ef444488',
};

const HEAT_TEXT_COLORS = {
  none: 'var(--text-muted)',
  low: '#4ade80',
  medium: '#fbbf24',
  high: '#fb923c',
  critical: '#f87171',
};

const HEAT_BADGE_COLORS = {
  none: 'transparent',
  low: '#22c55e33',
  medium: '#eab30833',
  high: '#f9731633',
  critical: '#ef444444',
};

export default function MitreNavigator() {
  const [matrixData, setMatrixData] = useState(null);
  const [coverageData, setCoverageData] = useState(null);
  const [attackChain, setAttackChain] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('matrix'); // 'matrix' or 'chain'

  const token = localStorage.getItem('access_token');
  const headers = { Authorization: `Bearer ${token}` };

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [matrixRes, coverageRes, chainRes] = await Promise.all([
        fetch(`${API}/api/mitre/matrix`, { headers }),
        fetch(`${API}/api/mitre/coverage`, { headers }),
        fetch(`${API}/api/mitre/attack-chain`, { headers }),
      ]);
      if (matrixRes.ok) setMatrixData(await matrixRes.json());
      if (coverageRes.ok) setCoverageData(await coverageRes.json());
      if (chainRes.ok) setAttackChain(await chainRes.json());
    } catch (err) {
      console.error('Failed to fetch MITRE data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) {
    return (
      <div className="empty-state">
        <RefreshCw className="spin" size={32} />
        <p>Loading MITRE ATT&CK Matrix...</p>
      </div>
    );
  }

  if (!matrixData) {
    return (
      <div className="empty-state">
        <Shield size={48} />
        <h3>MITRE ATT&CK Navigator</h3>
        <p>Unable to load matrix data. Ensure the backend is running.</p>
      </div>
    );
  }

  return (
    <div className="mitre-navigator">
      {/* Header */}
      <div className="mitre-header">
        <div className="mitre-header-title">
          <Shield size={24} />
          <h2>MITRE ATT&CK Navigator</h2>
        </div>
        <div className="mitre-header-stats">
          <div className="mitre-stat-pill">
            <Target size={14} />
            <span>{matrixData.detected_techniques} / {matrixData.total_techniques} techniques detected</span>
          </div>
          <div className="mitre-stat-pill highlight">
            <BarChart3 size={14} />
            <span>{matrixData.coverage_percent}% coverage</span>
          </div>
          <button className="mitre-refresh-btn" onClick={fetchData} title="Refresh data">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 4, marginBottom: 20 }}>
        {['matrix', 'chain'].map(t => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            style={{
              padding: '8px 20px', borderRadius: 8, border: 'none', cursor: 'pointer',
              fontWeight: 600, fontSize: '0.82rem',
              background: activeTab === t ? 'var(--accent)' : 'var(--bg-elevated)',
              color: activeTab === t ? '#fff' : 'var(--text-secondary)',
              transition: 'all 0.2s',
            }}
          >
            {t === 'matrix' ? 'ATT&CK Matrix' : 'Attack Chain'}
          </button>
        ))}
      </div>

      {activeTab === 'chain' && attackChain && (
        <div className="mitre-attack-chain">
          <div style={{ padding: '20px', background: 'var(--bg-card)', borderRadius: '12px' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px' }}>
              <Link2 size={20} color="var(--accent)" />
              Detected Attack Timeline
            </h3>
            {attackChain.chain && attackChain.chain.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {attackChain.chain.map((step, idx) => (
                  <div key={idx} style={{
                    display: 'flex', gap: '16px', alignItems: 'stretch'
                  }}>
                    {/* Timeline line and dot */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <div style={{
                        width: '12px', height: '12px', borderRadius: '50%',
                        background: 'var(--accent)',
                        boxShadow: '0 0 8px var(--accent)',
                        zIndex: 1
                      }} />
                      {idx < attackChain.chain.length - 1 && (
                        <div style={{ flex: 1, width: '2px', background: 'var(--border-subtle)', margin: '4px 0' }} />
                      )}
                    </div>
                    {/* Content */}
                    <div style={{
                      flex: 1, padding: '16px', borderRadius: '8px',
                      background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)',
                      marginBottom: idx < attackChain.chain.length - 1 ? '0' : '16px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                        <div>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {new Date(step.timestamp * 1000).toLocaleTimeString()}
                          </span>
                          <div style={{ fontWeight: 600, fontSize: '0.95rem', color: 'var(--text-primary)', marginTop: '4px' }}>
                            {step.technique} - {step.name}
                          </div>
                        </div>
                        <span className={`severity-badge ${step.severity.toLowerCase()}`} style={{ height: 'fit-content' }}>
                          {step.severity.toUpperCase()}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                        <strong>Tactic:</strong> {step.tactic}
                      </div>
                      {step.src_ip && (
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          <strong>Source IP:</strong> {step.src_ip}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: 'var(--text-muted)' }}>No attack chain data available.</p>
            )}
          </div>
        </div>
      )}

      {activeTab === 'matrix' && coverageData && (
        <div className="mitre-coverage-section">
          <h3>Tactic Coverage</h3>
          <div className="mitre-coverage-grid">
            {coverageData.tactics.map(tactic => (
              <div key={tactic.tactic_id} className="mitre-coverage-bar-item">
                <div className="mitre-coverage-label">
                  <span className="mitre-coverage-name">{tactic.tactic_name}</span>
                  <span className="mitre-coverage-pct">{tactic.detected_techniques}/{tactic.total_techniques}</span>
                </div>
                <div className="mitre-coverage-track">
                  <div
                    className="mitre-coverage-fill"
                    style={{
                      width: `${Math.max(tactic.coverage_percent, 2)}%`,
                      background: tactic.coverage_percent > 50 ? 'var(--accent-red)' :
                                  tactic.coverage_percent > 20 ? 'var(--accent-amber)' :
                                  tactic.total_hits > 0 ? 'var(--accent-green)' : 'var(--glass-border)',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="mitre-legend">
        <span className="mitre-legend-label">Heat:</span>
        {Object.entries(HEAT_TEXT_COLORS).map(([level, color]) => (
          <span key={level} className="mitre-legend-item" style={{ color }}>
            <span className="mitre-legend-dot" style={{ background: color }} />
            {level === 'none' ? 'No detections' : level.charAt(0).toUpperCase() + level.slice(1)}
          </span>
        ))}
      </div>

      {/* ATT&CK Matrix Grid */}
      <div className="mitre-matrix-container">
        <div className="mitre-matrix-grid">
          {matrixData.tactics.map(tactic => {
            const techniques = matrixData.matrix[tactic.id] || [];
            return (
              <div key={tactic.id} className="mitre-tactic-column">
                <div className="mitre-tactic-header">
                  <span className="mitre-tactic-name">{tactic.name}</span>
                  <span className="mitre-tactic-count">{techniques.length}</span>
                </div>
                <div className="mitre-technique-list">
                  {techniques.map(tech => (
                    <div
                      key={`${tactic.id}-${tech.id}`}
                      className={`mitre-technique-cell ${selectedTechnique?.id === tech.id ? 'selected' : ''}`}
                      style={{
                        background: HEAT_COLORS[tech.heat],
                        borderColor: HEAT_BORDER_COLORS[tech.heat],
                        color: HEAT_TEXT_COLORS[tech.heat],
                      }}
                      onClick={() => setSelectedTechnique(tech)}
                      title={`${tech.id}: ${tech.name} (${tech.count} detections)`}
                    >
                      <span className="mitre-tech-id">{tech.id}</span>
                      <span className="mitre-tech-name">{tech.name}</span>
                      {tech.count > 0 && (
                        <span
                          className="mitre-tech-badge"
                          style={{ background: HEAT_BADGE_COLORS[tech.heat], color: HEAT_TEXT_COLORS[tech.heat] }}
                        >
                          {tech.count}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Technique Detail Panel */}
          </div>
        </div>
      )}
      
      {/* Detail Panel */}
      {selectedTechnique && activeTab === 'matrix' && (
        <div className="mitre-detail-panel">
          <div className="mitre-detail-header">
            <Info size={16} />
            <span>Technique Details</span>
            <button className="mitre-detail-close" onClick={() => setSelectedTechnique(null)}>×</button>
          </div>
          <div className="mitre-detail-body">
            <div className="mitre-detail-row">
              <span className="mitre-detail-label">Technique ID</span>
              <span className="mitre-detail-value" style={{ color: HEAT_TEXT_COLORS[selectedTechnique.heat] }}>
                {selectedTechnique.id}
              </span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-label">Name</span>
              <span className="mitre-detail-value">{selectedTechnique.name}</span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-label">Detections</span>
              <span className="mitre-detail-value" style={{ color: HEAT_TEXT_COLORS[selectedTechnique.heat] }}>
                {selectedTechnique.count}
              </span>
            </div>
            <div className="mitre-detail-row">
              <span className="mitre-detail-label">Heat Level</span>
              <span
                className="mitre-detail-badge"
                style={{ background: HEAT_BADGE_COLORS[selectedTechnique.heat], color: HEAT_TEXT_COLORS[selectedTechnique.heat] }}
              >
                {selectedTechnique.heat.toUpperCase()}
              </span>
            </div>
            <a
              className="mitre-detail-link"
              href={`https://attack.mitre.org/techniques/${selectedTechnique.id}/`}
              target="_blank"
              rel="noopener noreferrer"
            >
              View on MITRE ATT&CK →
            </a>
          </div>
        </div>
      )}
    </div>
  );
}
