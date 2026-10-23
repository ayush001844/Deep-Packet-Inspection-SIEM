import React from 'react';
import { 
  Menu, Search, Sun, Moon, LogOut, Radio, Shield, 
  Command, SlidersHorizontal
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';

export default function Header({ 
  title = "Dashboard", 
  onToggleMobile = () => {}, 
  onOpenSearch = () => {} 
}) {
  const { user, logout } = useAuth();
  const { theme, isDark, toggleTheme } = useTheme();

  const isMac = typeof window !== 'undefined' && navigator.platform.toUpperCase().indexOf('MAC') >= 0;

  return (
    <header className="header" style={{ background: '#0e1219', borderBottom: '1px solid #1a2230', height: 56 }}>
      <div className="header-left">
        {/* Mobile Hamburger Toggle */}
        <button 
          className="header-mobile-toggle" 
          onClick={onToggleMobile}
          aria-label="Toggle navigation menu"
        >
          <Menu size={20} />
        </button>

        {/* Netography-Style Spectrum Zigzag Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <svg width="40" height="20" viewBox="0 0 54 24" fill="none">
            <polyline points="2,11 10,3 17,19 25,7 33,16 40,4 52,11" stroke="#f43f5e" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            <polyline points="2,14 10,6 17,22 25,10 33,19 40,7 52,14" stroke="#fb923c" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            <polyline points="2,17 10,9 17,25 25,13 33,22 40,10 52,17" stroke="#38bdf8" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span style={{ fontSize: 13, fontWeight: 800, letterSpacing: '2.5px', color: '#f1f5f9', fontFamily: 'Inter, sans-serif' }}>
            NETOGRAPHY
          </span>
        </div>

        <div style={{ width: 1, height: 18, background: '#243042', margin: '0 6px' }} />

        <div className="header-title-wrapper">
          <h2 className="header-title" style={{ fontSize: 13, color: '#94a3b8', fontWeight: 500 }}>{title}</h2>
        </div>
      </div>
      
      <div className="header-actions">
        {/* Global Omnisearch Trigger */}
        <div 
          className="header-search-trigger" 
          onClick={onOpenSearch} 
          role="button" 
          tabIndex={0}
          title="Search IPs, domains, ports, alerts (Ctrl+K or ⌘K)"
          style={{ background: '#141a24', border: '1px solid #202b3b', height: 34, padding: '0 12px' }}
        >
          <Search size={15} className="search-trigger-icon" />
          <span className="search-trigger-text" style={{ fontSize: 12 }}>Search IPs, domains, alerts...</span>
          <kbd className="search-trigger-kbd" style={{ background: '#0e1219', borderColor: '#202b3b' }}>
            {isMac ? '⌘K' : 'Ctrl K'}
          </kbd>
        </div>

        {/* Theme Switcher */}
        <button 
          className="theme-toggle-btn" 
          onClick={toggleTheme}
          title={`Switch to ${isDark ? 'Light' : 'Dark'} mode`}
          aria-label="Toggle theme"
          style={{ width: 34, height: 34, background: '#141a24', borderColor: '#202b3b' }}
        >
          {isDark ? (
            <Sun size={16} className="theme-icon sun" />
          ) : (
            <Moon size={16} className="theme-icon moon" />
          )}
        </button>
        
        {/* Sign Out */}
        <button 
          className="btn-icon-secondary" 
          onClick={logout}
          title="Sign Out"
          aria-label="Sign out"
          style={{ width: 34, height: 34, background: '#141a24', borderColor: '#202b3b' }}
        >
          <LogOut size={16} />
        </button>
      </div>
    </header>
  );
}
