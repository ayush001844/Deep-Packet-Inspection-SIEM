import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Lock, User, ShieldAlert } from 'lucide-react';

export default function Login() {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = await login(username, password);
    if (!result.success) {
      setError(result.error || 'Login failed. Please check your credentials.');
    }
    
    setIsLoading(false);
  };

  return (
    <div style={{
      height: '100vh',
      width: '100vw',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'var(--bg)',
      backgroundImage: 'radial-gradient(circle at center, rgba(59, 130, 246, 0.1) 0%, rgba(10, 10, 11, 1) 70%)',
      position: 'fixed',
      top: 0,
      left: 0,
      zIndex: 9999
    }}>
      <div className="card" style={{ width: '100%', maxWidth: '420px', padding: '40px', backgroundColor: 'var(--bg-elevated)', border: '1px solid var(--border)', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)' }}>
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '64px', height: '64px', borderRadius: '16px', backgroundColor: 'rgba(59, 130, 246, 0.1)', color: 'var(--primary)', marginBottom: '15px' }}>
            <ShieldAlert size={32} />
          </div>
          <h2 style={{ margin: '0 0 10px 0', fontSize: '1.75rem', fontWeight: 600 }}>PacketAnalyzer-Pro</h2>
          <p className="text-muted" style={{ margin: 0 }}>Sign in to access your SOC dashboard</p>
        </div>

        {error && (
          <div style={{ padding: '12px 15px', backgroundColor: 'rgba(239, 68, 68, 0.1)', borderLeft: '4px solid #ef4444', color: '#ef4444', borderRadius: '4px', marginBottom: '20px', fontSize: '0.9rem' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Username</label>
            <div style={{ position: 'relative' }}>
              <User size={18} className="text-muted" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input 
                type="text" 
                className="input" 
                value={username}
                onChange={e => setUsername(e.target.value)}
                style={{ width: '100%', paddingLeft: '40px' }}
                placeholder="Enter username"
                required
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={18} className="text-muted" style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)' }} />
              <input 
                type="password" 
                className="input" 
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', paddingLeft: '40px' }}
                placeholder="Enter password"
                required
              />
            </div>
          </div>

          <button 
            type="submit" 
            className="btn btn-primary" 
            style={{ width: '100%', padding: '12px', fontSize: '1rem', marginTop: '10px', justifyContent: 'center' }}
            disabled={isLoading}
          >
            {isLoading ? 'Authenticating...' : 'Secure Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}
