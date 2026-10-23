import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Lock, User, ShieldAlert, KeyRound, ShieldCheck } from 'lucide-react';

export default function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = await login(username, password);
    if (!result.success) {
      setError(result.error || 'Login failed. Please check your credentials.');
    }
    
    setIsLoading(false);
  };

  const handleQuickLogin = (u, p) => {
    setUsername(u);
    setPassword(p);
    setIsLoading(true);
    setError('');
    setTimeout(async () => {
      const result = await login(u, p);
      if (!result.success) {
        setError(result.error || 'Login failed.');
      }
      setIsLoading(false);
    }, 50);
  };

  return (
    <div style={{
      height: '100vh',
      width: '100vw',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--bg-primary)',
      backgroundImage: 'radial-gradient(circle at center, hsla(210, 100%, 55%, 0.12) 0%, var(--bg-primary) 70%)',
      position: 'fixed',
      top: 0,
      left: 0,
      zIndex: 9999
    }}>
      <div className="card" style={{ width: '100%', maxWidth: '440px', padding: '36px', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-default)', boxShadow: 'var(--shadow-lg)' }}>
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '60px', height: '60px', borderRadius: '16px', backgroundColor: 'var(--accent-glow)', color: 'var(--accent)', marginBottom: '14px' }}>
            <ShieldAlert size={32} />
          </div>
          <h2 style={{ margin: '0 0 6px 0', fontSize: '1.65rem', fontWeight: 700, letterSpacing: '-0.5px' }}>PacketAnalyzer-Pro</h2>
          <p className="text-muted" style={{ margin: 0, fontSize: '0.9rem' }}>SOC & SIEM Inspection Platform</p>
        </div>

        {/* Quick Demo Credentials Box */}
        <div style={{
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-md)',
          padding: '12px 14px',
          marginBottom: '20px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>
            <KeyRound size={14} color="var(--accent)" />
            <span>DEFAULT CREDENTIALS (CLICK TO AUTO-FILL):</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handleQuickLogin('admin', 'admin')}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '8px 10px', height: 'auto', textAlign: 'left' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontWeight: 700, color: 'var(--accent)', fontSize: '0.8rem' }}>
                <ShieldCheck size={13} /> Admin
              </div>
              <span className="mono text-muted" style={{ fontSize: '0.72rem' }}>admin / admin</span>
            </button>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => handleQuickLogin('analyst', 'analyst')}
              style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '8px 10px', height: 'auto', textAlign: 'left' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontWeight: 700, color: 'var(--proto-tls)', fontSize: '0.8rem' }}>
                <User size={13} /> Analyst
              </div>
              <span className="mono text-muted" style={{ fontSize: '0.72rem' }}>analyst / analyst</span>
            </button>
          </div>
        </div>

        {error && (
          <div style={{ padding: '10px 14px', backgroundColor: 'var(--critical-bg)', borderLeft: '4px solid var(--critical)', color: 'var(--critical)', borderRadius: '4px', marginBottom: '18px', fontSize: '0.85rem' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Username</label>
            <div style={{ position: 'relative' }}>
              <User size={16} className="text-muted" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input 
                type="text" 
                className="input" 
                value={username}
                onChange={e => setUsername(e.target.value)}
                style={{ width: '100%', paddingLeft: '38px' }}
                placeholder="Enter username (e.g. admin)"
                required
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: '6px', fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={16} className="text-muted" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input 
                type="password" 
                className="input" 
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', paddingLeft: '38px' }}
                placeholder="Enter password (e.g. admin)"
                required
              />
            </div>
          </div>

          <button 
            type="submit" 
            className="btn btn-primary" 
            style={{ width: '100%', padding: '11px', fontSize: '0.95rem', marginTop: '6px', justifyContent: 'center' }}
            disabled={isLoading}
          >
            {isLoading ? 'Authenticating...' : 'Secure Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
