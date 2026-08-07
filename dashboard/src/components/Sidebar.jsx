import { NavLink } from 'react-router-dom';
import { 
  Activity, Shield, List, AlertTriangle, Box, 
  Map, Settings, Server, FileText, Clock, FileBarChart
} from 'lucide-react';

const navItems = [
  { label: 'Overview', path: '/', icon: Activity },
  { label: 'Live Capture', path: '/capture', icon: Radio },
  { label: 'Packet Log', path: '/packets', icon: List },
  { label: 'Threats', path: '/threats', icon: Shield },
  { label: 'Incidents', path: '/incidents', icon: AlertTriangle },
  { label: 'Network Map', path: '/map', icon: Map },
  { label: 'Timeline', path: '/timeline', icon: Clock },
  { label: 'PCAP Analysis', path: '/pcap', icon: FileBarChart },
  { label: 'Rules Engine', path: '/rules', icon: FileText },
  { label: 'Settings', path: '/settings', icon: Settings },
];

function Radio(props) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
    </svg>
  );
}

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Server size={20} color="white" />
        </div>
        <div>
          <h1>PacketAnalyzer-Pro</h1>
          <span>SOC & SIEM Platform</span>
        </div>
      </div>
      
      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Dashboard</div>
        {navItems.slice(0, 3).map(item => (
          <NavLink 
            key={item.path} 
            to={item.path} 
            className={({isActive}) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon />
            {item.label}
          </NavLink>
        ))}
        
        <div className="sidebar-section-label" style={{marginTop: 16}}>Security</div>
        {navItems.slice(3, 7).map(item => (
          <NavLink 
            key={item.path} 
            to={item.path} 
            className={({isActive}) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon />
            {item.label}
          </NavLink>
        ))}
        
        <div className="sidebar-section-label" style={{marginTop: 16}}>Tools</div>
        {navItems.slice(7).map(item => (
          <NavLink 
            key={item.path} 
            to={item.path} 
            className={({isActive}) => `sidebar-link ${isActive ? 'active' : ''}`}
          >
            <item.icon />
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
