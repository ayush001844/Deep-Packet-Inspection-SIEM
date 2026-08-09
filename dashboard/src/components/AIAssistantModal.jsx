import { useState, useEffect } from 'react';
import { X, Bot, Shield, CheckCircle, BrainCircuit } from 'lucide-react';
import { apiPost } from '../hooks/useApi';

export default function AIAssistantModal({ alert, onClose }) {
  const [loading, setLoading] = useState(true);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!alert) return;

    const fetchAnalysis = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await apiPost('/api/ai/explain', alert);
        setAnalysis(result);
      } catch (err) {
        console.error(err);
        setError("The AI Assistant could not process this request.");
      } finally {
        setLoading(false);
      }
    };

    fetchAnalysis();
  }, [alert]);

  if (!alert) return null;

  return (
    <div className="modal-overlay" onClick={onClose} style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.7)', zIndex: 999,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      backdropFilter: 'blur(5px)'
    }}>
      <div className="modal-content" onClick={e => e.stopPropagation()} style={{
        backgroundColor: 'var(--surface)',
        width: '600px',
        maxWidth: '90%',
        maxHeight: '85vh',
        borderRadius: '12px',
        border: '1px solid var(--border)',
        boxShadow: '0 10px 40px rgba(0,255,213,0.1)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}>
        
        {/* Header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: 'rgba(0,255,213,0.05)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              background: 'var(--accent)', padding: '6px', borderRadius: '50%',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 10px var(--accent)'
            }}>
              <BrainCircuit size={20} color="#000" />
            </div>
            <h3 style={{ margin: 0, color: 'var(--accent)', textShadow: '0 0 5px var(--accent)' }}>
              AI Security Analyst
            </h3>
          </div>
          <button onClick={onClose} style={{ 
            background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' 
          }}>
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '20px', overflowY: 'auto', flex: 1 }}>
          <div style={{ marginBottom: '20px' }}>
            <h4 style={{ margin: '0 0 8px 0', color: '#fff' }}>Alert Subject:</h4>
            <div style={{ 
              padding: '10px', background: 'rgba(255,255,255,0.05)', 
              borderRadius: '6px', fontSize: '0.9rem' 
            }}>
              <span style={{ fontWeight: 'bold' }}>[{alert.severity.toUpperCase()}]</span> {alert.title}
            </div>
          </div>

          {loading ? (
            <div style={{ textAlign: 'center', padding: '40px 0' }}>
              <div className="ai-pulse" style={{
                width: '50px', height: '50px', borderRadius: '50%',
                background: 'var(--accent)', margin: '0 auto 20px',
                animation: 'pulse 1.5s infinite'
              }}></div>
              <p style={{ color: 'var(--accent)', margin: 0 }}>Analyzing threat patterns...</p>
            </div>
          ) : error ? (
            <div style={{ color: 'var(--critical)', textAlign: 'center', padding: '20px' }}>
              {error}
            </div>
          ) : analysis ? (
            <div className="fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              
              <div>
                <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--high)', margin: '0 0 10px 0' }}>
                  <Shield size={16} /> Explanation
                </h4>
                <p style={{ margin: 0, lineHeight: 1.5, fontSize: '0.95rem', color: 'var(--text-muted)' }}>
                  {analysis.explanation}
                </p>
              </div>

              <div>
                <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--warning)', margin: '0 0 10px 0' }}>
                  <Bot size={16} /> Reasoning
                </h4>
                <p style={{ margin: 0, lineHeight: 1.5, fontSize: '0.95rem', color: 'var(--text-muted)' }}>
                  {analysis.reason}
                </p>
              </div>

              <div>
                <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent)', margin: '0 0 10px 0' }}>
                  <CheckCircle size={16} /> MITRE Context
                </h4>
                <p style={{ margin: 0, lineHeight: 1.5, fontSize: '0.95rem', color: 'var(--text-muted)' }}>
                  {analysis.mitre_context}
                </p>
              </div>

              <div>
                <h4 style={{ margin: '0 0 10px 0', color: '#fff' }}>Recommended Actions</h4>
                <ul style={{ margin: 0, paddingLeft: '20px', color: 'var(--text-muted)', fontSize: '0.95rem' }}>
                  {analysis.recommendations?.map((rec, i) => (
                    <li key={i} style={{ marginBottom: '8px' }}>{rec}</li>
                  ))}
                </ul>
              </div>

            </div>
          ) : null}
        </div>
        
        {/* Footer */}
        <div style={{
          padding: '12px 20px',
          borderTop: '1px solid var(--border)',
          backgroundColor: 'rgba(0,0,0,0.2)',
          textAlign: 'right',
          fontSize: '0.8rem',
          color: 'var(--text-muted)'
        }}>
          Generated by DeepGuard AI Assistant
        </div>
      </div>
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes pulse {
          0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 213, 0.7); }
          70% { transform: scale(1); box-shadow: 0 0 0 15px rgba(0, 255, 213, 0); }
          100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 255, 213, 0); }
        }
      `}} />
    </div>
  );
}
