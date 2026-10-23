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
    <header className="header">
      <div className="header-left">
        {/* Mobile Hamburger Toggle */}
        <button 
          className="header-mobile-toggle" 
          onClick={onToggleMobile}
          aria-label="Toggle navigation menu"
        >
          <Menu size={20} />
        </button>

        <div className="header-title-wrapper">
          <h2 className="header-title">{title}</h2>
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
        >
          <Search size={16} className="search-trigger-icon" />
          <span className="search-trigger-text">Search IPs, domains, alerts...</span>
          <kbd className="search-trigger-kbd">
            {isMac ? '⌘K' : 'Ctrl K'}
          </kbd>
        </div>

        {/* Theme Switcher (Dark / Light) */}
        <button 
          className="theme-toggle-btn" 
          onClick={toggleTheme}
          title={`Switch to ${isDark ? 'Light' : 'Dark'} mode`}
          aria-label="Toggle theme"
        >
          {isDark ? (
            <Sun size={18} className="theme-icon sun" />
          ) : (
            <Moon size={18} className="theme-icon moon" />
          )}
        </button>
        
        {/* Sign Out */}
        <button 
          className="btn-icon-secondary" 
          onClick={logout}
          title="Sign Out of SOC Session"
          aria-label="Sign out"
        >
          <LogOut size={18} />
        </button>
      </div>
    </header>
  );
}
