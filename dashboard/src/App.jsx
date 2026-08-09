import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Overview from './pages/Overview';
import LiveCapture from './pages/LiveCapture';
import Threats from './pages/Threats';
import AttackTimeline from './pages/Timeline';
import PcapAnalysis from './pages/PcapAnalysis';
import Rules from './pages/Rules';
import Incidents from './pages/Incidents';
import NetworkMap from './pages/NetworkMap';
import Settings from './pages/Settings';
import Login from './pages/Login';
import PacketLog from './pages/PacketLog';
import MitreNavigator from './pages/MitreNavigator';
import { useAuth } from './contexts/AuthContext';

// Placeholder for other pages
function Placeholder({ title }) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      <p>This module is scheduled for a future phase.</p>
    </div>
  );
}

export default function App() {
  const { user } = useAuth();

  if (!user) {
    return <Login />;
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="capture" element={<LiveCapture />} />
          <Route path="packets" element={<PacketLog />} />
          <Route path="threats" element={<Threats />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="map" element={<NetworkMap />} />
          <Route path="timeline" element={<AttackTimeline />} />
          <Route path="pcap" element={<PcapAnalysis />} />
          <Route path="rules" element={<Rules />} />
          <Route path="mitre" element={<MitreNavigator />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
