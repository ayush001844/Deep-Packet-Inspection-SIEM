import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  Home, ShieldAlert, LayoutGrid, Crosshair, Gauge, 
  Eye, Wrench, Box, ChevronsRight, ChevronsLeft, X,
  Radio, List, FileBarChart, Clock, Share2, Brain, Radar, Users, FileText, Settings
} from 'lucide-react';

// Rail icons matching Netography left navigation
const railItems = [
  { label: 'Overview', path: '/', icon: Home },
  { label: 'Threats', path: '/threats', icon: ShieldAlert },
  { label: 'Flows', path: '/flows', icon: LayoutGrid },
  { label: 'ATT&CK Matrix', path: '/mitre', icon: Crosshair },
  { label: 'Live Capture', path: '/capture', icon: Gauge },
  { label: 'Packet Inspection', path: '/packets', icon: Eye },
  { label: 'Detection Rules', path: '/rules', icon: Wrench },
  { label: 'Topology Map', path: '/map', icon: Box },
];

const expandedSections = [
  {
    title: 'OVERVIEW',
    items: [
      { label: 'Overview', path: '/', icon: Home },
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
      { label: 'Attack Timeline', path: '/timeline', icon: Clock },
      { label: 'ATT&CK Matrix', path: '/mitre', icon: Crosshair },
      { label: 'AI Detection', path: '/ml', icon: Brain },
      { label: 'Anomaly Radar', path: '/anomaly', icon: Radar },
      { label: 'UEBA', path: '/ueba', icon: Users },
      { label: 'Topology Map', path: '/map', icon: Box },
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

export default function Sidebar({ 
  isMobileOpen = false, 
  onCloseMobile = () => {},
  isCollapsed = false,
  onToggleCollapse = () => {}
}) {
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

      <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''} ${isMobileOpen ? 'mobile-open' : ''}`}>
        {/* Rail Top Toggle Button */}
        <div style={{
          height: 48,
          display: 'flex',
          alignItems: 'center',
          justifyContent: isCollapsed ? 'center' : 'space-between',
          padding: isCollapsed ? '0' : '0 14px',
          borderBottom: '1px solid #1a2230',
          background: '#0c1017'
        }}>
          {!isCollapsed && (
            <span style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.8px' }}>
              NAVIGATION
            </span>
          )}
          <button
            onClick={onToggleCollapse}
            title={isCollapsed ? "Expand Sidebar" : "Collapse to Rail"}
            style={{
              background: 'none',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: 6,
              borderRadius: 4
            }}
          >
            {isCollapsed ? <ChevronsRight size={18} /> : <ChevronsLeft size={18} />}
          </button>
        </div>

        {/* Navigation Content */}
        <nav className="sidebar-nav" style={{ padding: isCollapsed ? '8px 0' : '10px' }}>
          {isCollapsed ? (
            /* Compact Icon Rail (Matching Netography) */
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
              {railItems.map(item => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  title={item.label}
                  className={({ isActive }) => `sidebar-rail-btn ${isActive ? 'active' : ''}`}
                  onClick={onCloseMobile}
                >
                  <item.icon size={19} />
                </NavLink>
              ))}
            </div>
          ) : (
            /* Full Expanded Nav */
            expandedSections.map(section => (
              <div key={section.title} className="sidebar-section">
                <div className="sidebar-section-label">{section.title}</div>
                {section.items.map(item => (
                  <NavLink 
                    key={item.path} 
                    to={item.path} 
                    className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
                    onClick={onCloseMobile}
                  >
                    <item.icon size={17} className="sidebar-item-icon" />
                    <span>{item.label}</span>
                  </NavLink>
                ))}
              </div>
            ))
          )}
        </nav>

        {/* Engine status indicator */}
        {!isCollapsed && (
          <div className="sidebar-footer">
            <div className="engine-status-pill">
              <span className="live-dot" />
              <div className="engine-status-text">
                <div className="engine-status-title">DPI Engine Active</div>
                <div className="engine-status-sub">Zero-Packet Drop Buffer</div>
              </div>
            </div>
          </div>
        )}
      </aside>
    </>
  );
}
