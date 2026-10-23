import React, { useState, useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import GlobalSearch from './GlobalSearch';

export default function Layout() {
  const location = useLocation();
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);

  // Close mobile sidebar on route change
  useEffect(() => {
    setIsMobileOpen(false);
  }, [location.pathname]);

  // Global keyboard shortcut for Cmd+K / Ctrl+K
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const titles = {
    '/': 'Dashboard Overview',
    '/capture': 'Live Packet Capture',
    '/packets': 'Packet Log & Deep Inspection',
    '/flows': 'Active Network Flows',
    '/threats': 'Security Alerts & Threat Intel',
    '/incidents': 'Incident Response & Case Management',
    '/map': 'Network Topology & Force Graph',
    '/timeline': 'Attack Timeline & Event Stream',
    '/mitre': 'MITRE ATT&CK Matrix Navigator',
    '/ml': 'AI & Supervised ML Detection',
    '/anomaly': 'Autoencoder Anomaly Detection',
    '/ueba': 'User & Entity Behavior Analytics (UEBA)',
    '/pcap': 'Offline PCAP Analysis',
    '/rules': 'Firewall & DPI Detection Rules',
    '/settings': 'System Settings & Capture Config',
  };

  const title = titles[location.pathname] || 'PacketAnalyzer-Pro';

  return (
    <div className="app-layout">
      <Sidebar 
        isMobileOpen={isMobileOpen} 
        onCloseMobile={() => setIsMobileOpen(false)} 
      />
      
      <div className="main-content">
        <Header 
          title={title} 
          onToggleMobile={() => setIsMobileOpen(prev => !prev)}
          onOpenSearch={() => setIsSearchOpen(true)}
        />
        
        <main className="page-content">
          <Outlet />
        </main>
      </div>

      <GlobalSearch 
        isOpen={isSearchOpen} 
        onClose={() => setIsSearchOpen(false)} 
      />
    </div>
  );
}
