import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  Activity, ShieldAlert, List, AlertTriangle, Box, 
  Map, Settings, Server, FileText, Clock, FileBarChart, 
  Brain, Radar, Users, Share2, Radio, X, Cpu, ShieldCheck
} from 'lucide-react';

const navSections = [
  {
    title: 'OVERVIEW',
    items: [
      { label: 'Overview', path: '/', icon: Activity },
    ],
  },
  {
    title: 'TRAFFIC ANALYSIS',
    items: [
      { label: 'Live Capture', path: '/capture', icon: Radio },
      { label: 'Packet Log', path: '/packets', icon: List },
      { label: 'PCAP Analysis', path: '/pcap', icon: FileBarChart },
    ],
  },
  {
    title: 'FLOWS',
    items: [
      { label: 'Active Flows', path: '/flows', icon: Share2 },
    ],
  },
  {
    title: 'THREAT DETECTION',
    items: [
      { label: 'Security Alerts', path: '/threats', icon: ShieldAlert },
      { label: 'Incidents', path: '/incidents', icon: AlertTriangle },
      { label: 'Attack Timeline', path: '/timeline', icon: Clock },
      { label: 'Network Map', path: '/map', icon: Map },
      { label: 'ATT&CK Matrix', path: '/mitre', icon: Box },
      { label: 'AI Detection', path: '/ml', icon: Brain },
      { label: 'Anomaly Detection', path: '/anomaly', icon: Radar },
      { label: 'UEBA', path: '/ueba', icon: Users },
    ],
  },
  {
    title: 'RULES & SYSTEM',
    items: [
      { label: 'Detection Rules', path: '/rules', icon: FileText },
      { label: 'Settings', path: '/settings', icon: Settings },
    ],
  },
];

export default function Sidebar({ isMobileOpen = false, onCloseMobile = () => {} }) {
  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div 
          className="sidebar-backdrop" 
          onClick={onCloseMobile} 
          aria-label="Close navigation"
        />
      )}

      <aside className={`sidebar ${isMobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">
            <Server size={22} color="white" />
          </div>
          <div className="sidebar-brand-text">
            <h1>PacketAnalyzer-Pro</h1>
            <span>SOC & SIEM Platform</span>
          </div>
          {isMobileOpen && (
            <button 
              className="sidebar-mobile-close" 
              onClick={onCloseMobile}
              aria-label="Close sidebar"
            >
              <X size={20} />
            </button>
          )}
        </div>
        
        <nav className="sidebar-nav">
          {navSections.map(section => (
            <div key={section.title} className="sidebar-section">
              <div className="sidebar-section-label">{section.title}</div>
              {section.items.map(item => (
                <NavLink 
                  key={item.path} 
                  to={item.path} 
                  className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
                  onClick={onCloseMobile}
                >
                  <item.icon size={18} className="sidebar-item-icon" />
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Engine status footer */}
        <div className="sidebar-footer">
          <div className="engine-status-pill">
            <span className="live-dot" />
            <div className="engine-status-text">
              <div className="engine-status-title">DPI Engine Active</div>
              <div className="engine-status-sub">Zero-Packet Drop Buffer</div>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}
