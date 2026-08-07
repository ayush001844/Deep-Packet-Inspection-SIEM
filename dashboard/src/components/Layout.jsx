import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

export default function Layout() {
  const location = useLocation();
  
  // Basic routing to title mapping
  const titles = {
    '/': 'Dashboard Overview',
    '/capture': 'Live Capture',
    '/packets': 'Packet Log',
    '/threats': 'Threat Intelligence',
    '/incidents': 'Incident Management',
    '/map': 'Network Visualization',
    '/pcap': 'PCAP Analysis',
    '/rules': 'Detection Rules',
    '/timeline': 'Attack Timeline',
    '/settings': 'Settings'
  };

  const title = titles[location.pathname] || 'PacketAnalyzer-Pro';

  return (
    <div className="app-layout">
      <Sidebar />
      <div className="main-content">
        <Header title={title} />
        <main className="page-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
