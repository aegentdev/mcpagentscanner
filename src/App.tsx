import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import ComingSoon from './pages/ComingSoon';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/system-schema" element={<ComingSoon title="System Schema" description="Visual representation of your multi-agent system architecture and connections." />} />
        <Route path="/vulnerability-scan" element={<ComingSoon title="Vulnerability Scan" description="Comprehensive security scanning and vulnerability assessment tools." />} />
        <Route path="/attack-monitoring" element={<ComingSoon title="Attack Monitoring" description="Real-time monitoring and detection of potential attacks and security threats." />} />
        <Route path="/threat-intelligence" element={<ComingSoon title="Threat Intelligence" description="Advanced threat intelligence and security analytics." />} />
        <Route path="/data-poisoning" element={<ComingSoon title="Data Poisoning" description="Detection and prevention of data poisoning attacks." />} />
        <Route path="/jailbreaks" element={<ComingSoon title="Jailbreaks" description="Monitoring and prevention of AI model jailbreak attempts." />} />
        <Route path="/hardening-tools" element={<ComingSoon title="Hardening Tools" description="Security hardening and configuration management tools." />} />
        <Route path="/prompt-hardening" element={<ComingSoon title="Prompt Hardening" description="Advanced prompt security and validation tools." />} />
        <Route path="/risk-reports" element={<ComingSoon title="Risk Reports" description="Comprehensive risk assessment and reporting tools." />} />
        <Route path="/system-monitor" element={<ComingSoon title="System Monitor" description="Real-time system monitoring and performance analytics." />} />
      </Routes>
    </Router>
  );
}

export default App; 