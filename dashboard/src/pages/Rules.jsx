import React from 'react';
import { Shield, Database, Code, List, Plus } from 'lucide-react';

export default function Rules() {
  const idsRules = [
    { id: 'IDS-001', name: 'SSH Brute Force Attempt', type: 'Flow', mitre: 'T1110', cvss: 7.5, status: 'Active' },
    { id: 'IDS-002', name: 'Cleartext Authentication Protocol', type: 'Flow', mitre: 'T1040', cvss: 7.5, status: 'Active' },
    { id: 'IDS-003', name: 'Network Port Scan', type: 'Flow', mitre: 'T1046', cvss: 5.3, status: 'Active' },
    { id: 'IDS-004', name: 'Suspicious DNS Traffic', type: 'Packet', mitre: 'T1071', cvss: 7.2, status: 'Active' },
    { id: 'IDS-005', name: 'HTTP Directory Traversal', type: 'Packet', mitre: 'T1190', cvss: 7.5, status: 'Active' },
    { id: 'IDS-006', name: 'Potential Reverse Shell', type: 'Packet', mitre: 'T1059', cvss: 10.0, status: 'Active' },
    { id: 'IDS-007', name: 'ICMP Flood DoS', type: 'Packet', mitre: 'T1498', cvss: 7.5, status: 'Active' },
    { id: 'IDS-008', name: 'Massive Data Transfer', type: 'Flow', mitre: 'T1048', cvss: 6.5, status: 'Active' },
  ];

  const yaraRules = [
    { id: 'YARA-001', name: 'Suspicious Executable Download', target: 'Payload', mitre: 'T1105', status: 'Active' },
    { id: 'YARA-002', name: 'Log4j JNDI Lookup (Log4Shell)', target: 'Payload', mitre: 'T1190', status: 'Active' },
    { id: 'YARA-003', name: 'SQL Injection Payload', target: 'Payload', mitre: 'T1190', status: 'Active' },
  ];

  const sigmaRules = [
    { id: 'SIGMA-001', name: 'Suspicious DNS TXT Query', source: 'DNS Layer', status: 'Active' },
    { id: 'SIGMA-002', name: 'Suspicious User-Agent (Nmap)', source: 'HTTP Layer', status: 'Active' },
  ];

  return (
    <div className="fade-in">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 600 }}>Detection Rules Engine</h2>
        <button className="btn btn-primary" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Plus size={16} /> New Rule
        </button>
      </div>

      <div className="card mb-4">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Shield color="var(--primary)" />
          <h3 className="card-title">IDS Behavioral Signatures</h3>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Name</th>
                <th>Evaluation Type</th>
                <th>MITRE ATT&CK</th>
                <th>CVSS Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {idsRules.map(rule => (
                <tr key={rule.id}>
                  <td className="font-mono text-sm">{rule.id}</td>
                  <td className="font-medium">{rule.name}</td>
                  <td><span className="badge" style={{ backgroundColor: 'var(--bg-secondary)' }}>{rule.type}</span></td>
                  <td><span className="badge" style={{ backgroundColor: 'var(--bg-secondary)' }}>{rule.mitre}</span></td>
                  <td style={{ color: rule.cvss >= 9 ? 'var(--critical)' : rule.cvss >= 7 ? 'var(--high)' : 'var(--medium)' }}>
                    {rule.cvss.toFixed(1)}
                  </td>
                  <td><span className="badge" style={{ backgroundColor: 'var(--success-bg)', color: 'var(--success)' }}>{rule.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Code color="var(--warning)" />
            <h3 className="card-title">YARA Payload Signatures</h3>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Name</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {yaraRules.map(rule => (
                  <tr key={rule.id}>
                    <td className="font-mono text-sm">{rule.id}</td>
                    <td className="font-medium">{rule.name}</td>
                    <td><span className="badge" style={{ backgroundColor: 'var(--success-bg)', color: 'var(--success)' }}>{rule.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-header" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Database color="var(--info)" />
            <h3 className="card-title">Sigma Log Signatures</h3>
          </div>
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Name</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {sigmaRules.map(rule => (
                  <tr key={rule.id}>
                    <td className="font-mono text-sm">{rule.id}</td>
                    <td className="font-medium">{rule.name}</td>
                    <td><span className="badge" style={{ backgroundColor: 'var(--success-bg)', color: 'var(--success)' }}>{rule.status}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
