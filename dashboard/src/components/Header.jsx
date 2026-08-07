import { Bell, Search, User, LogOut } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';

export default function Header({ title = "Dashboard" }) {
  const { user, logout } = useAuth();
  return (
    <header className="header">
      <div className="header-title">{title}</div>
      
      <div className="header-actions">
        <div className="relative" style={{ display: 'flex', alignItems: 'center' }}>
          <Search size={16} className="text-muted" style={{ position: 'absolute', left: 10 }} />
          <input 
            type="text" 
            placeholder="Search IPs, domains, hashes..." 
            className="input" 
            style={{ paddingLeft: 34, width: 280 }}
          />
        </div>
        
        <button className="btn btn-secondary" style={{ padding: '8px', borderRadius: '50%' }}>
          <Bell size={18} />
        </button>
        
        <button 
          className="btn btn-secondary" 
          style={{ padding: '8px', borderRadius: '50%', color: 'var(--text)', gap: '8px' }}
          onClick={logout}
          title="Sign Out"
        >
          <LogOut size={18} />
        </button>
      </div>
    </header>
  );
}
