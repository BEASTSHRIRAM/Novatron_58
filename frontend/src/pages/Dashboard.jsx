import React, { useState } from 'react';
import axios from 'axios';
import ThreatScoreGauge from '../components/ThreatScoreGauge';
import ThreatCard from '../components/ThreatCard';
import Map3D from '../components/Map3D';
import EvidenceTabs from '../components/EvidenceTabs';
import AiReportPanel from '../components/AiReportPanel';
import JsonDrawer from '../components/JsonDrawer';
import DnsChecker from '../components/DnsChecker';
import { Loader2, Shield, Search, AlertTriangle, FileText } from 'lucide-react';
import jsPDF from 'jspdf';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ABUSE_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
  6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP', 9: 'Open Proxy', 10: 'Web Spam',
  11: 'Email Spam', 12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking',
  16: 'SQL Injection', 17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH Attack', 23: 'IoT Targeted'
};

const Dashboard = () => {
  const [ipAddress, setIpAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [threatData, setThreatData] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const fetchHistory = async (ip) => {
    setLoadingHistory(true);
    try {
      const res = await axios.get(`${API}/history/${ip}`);
      setHistory(res.data.history || []);
    } catch (e) {
      console.error('fetchHistory failed', e);
      setHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleAnalyze = async () => {
    if (!ipAddress.trim()) return setError('Please enter a valid IP address');
    setLoading(true); setError(null); setThreatData(null);
    try {
      const res = await axios.post(`${API}/analyze`, { ip: ipAddress.trim() });
      setThreatData(res.data);
      fetchHistory(ipAddress.trim());
    } catch (err) {
      let msg = 'Failed to analyze IP address';
      import React, { useState } from 'react';
      import axios from 'axios';
      import ThreatScoreGauge from '../components/ThreatScoreGauge';
      import ThreatCard from '../components/ThreatCard';
      import Map3D from '../components/Map3D';
      import EvidenceTabs from '../components/EvidenceTabs';
      import AiReportPanel from '../components/AiReportPanel';
      import JsonDrawer from '../components/JsonDrawer';
      import DnsChecker from '../components/DnsChecker';
      import { Loader2, Shield, Search, AlertTriangle, FileText } from 'lucide-react';
      import jsPDF from 'jspdf';

      const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
      const API = `${BACKEND_URL}/api`;

      const ABUSE_CATEGORIES = {
        1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
        6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP', 9: 'Open Proxy', 10: 'Web Spam',
        11: 'Email Spam', 12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking',
        16: 'SQL Injection', 17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
        21: 'Web App Attack', 22: 'SSH Attack', 23: 'IoT Targeted'
      };

      const Dashboard = () => {
        const [ipAddress, setIpAddress] = useState('');
        const [loading, setLoading] = useState(false);
        const [threatData, setThreatData] = useState(null);
        const [error, setError] = useState(null);
        const [history, setHistory] = useState([]);
        const [loadingHistory, setLoadingHistory] = useState(false);

        const fetchHistory = async (ip) => {
          setLoadingHistory(true);
          try {
            const res = await axios.get(`${API}/history/${ip}`);
            setHistory(res.data.history || []);
          } catch (e) {
            console.error('fetchHistory failed', e);
            setHistory([]);
          } finally {
            setLoadingHistory(false);
          }
        };

        const handleAnalyze = async () => {
          if (!ipAddress.trim()) return setError('Please enter a valid IP address');
          setLoading(true); setError(null); setThreatData(null);
          try {
            const res = await axios.post(`${API}/analyze`, { ip: ipAddress.trim() });
            setThreatData(res.data);
            fetchHistory(ipAddress.trim());
          } catch (err) {
            let msg = 'Failed to analyze IP address';
            if (err.response?.data?.detail) {
              const d = err.response.data.detail;
              msg = Array.isArray(d) ? d.map(x => x.msg || JSON.stringify(x)).join(', ') : String(d);
            }
            setError(msg);
          } finally {
            setLoading(false);
          }
        };

        const handleDownloadReport = async () => {
          if (!threatData) return setError('No threat data to generate report for. Run an analysis first.');
          try {
            const pdf = new jsPDF('p', 'mm', 'a4');
            const w = pdf.internal.pageSize.getWidth();
            const margin = 15;

            pdf.setFontSize(18);
            pdf.setTextColor(0, 180, 70);
            pdf.text('TICE - Threat Report', margin, 25);

            pdf.setFontSize(10);
            pdf.setTextColor(120, 120, 120);
            pdf.text(`IP: ${threatData.ip}`, margin, 35);
            pdf.text(`Risk: ${threatData.risk.score}/100`, w - margin - 50, 35);

            pdf.setFontSize(12);
            const content = threatData.ai_report || 'No AI report available.';
            const lines = pdf.splitTextToSize(content, w - margin * 2);
            pdf.text(lines, margin, 50);

            pdf.save(`TICE-Threat-Report-${threatData.ip}-${Date.now()}.pdf`);
          } catch (e) {
            console.error(e);
            setError('Failed to generate PDF report');
          }
        };

        const handleKeyPress = (e) => { if (e.key === 'Enter') handleAnalyze(); };

        return (
          <div className="min-h-screen p-6 lg:p-8" style={{ background: 'linear-gradient(135deg,#0a0a0f 0%,#1a0f2e 100%)' }}>
            <div className="max-w-7xl mx-auto mb-8 animate-slide-up">
              <div className="flex items-center gap-4 mb-2">
                <Shield className="w-10 h-10 text-green-400" />
                <h1 className="text-5xl font-bold" style={{ fontFamily: 'Space Grotesk, sans-serif', background: 'linear-gradient(135deg,#00ff41 0%,#a855f7 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>TICE</h1>
              </div>
              <p className="text-gray-400">Threat Intelligence Correlation Engine - Advanced IP Analysis & Attribution</p>
            </div>

            <div className="max-w-7xl mx-auto mb-8 animate-slide-up">
              <div className="glass p-6 rounded-2xl">
                <div className="flex flex-col md:flex-row gap-4">
                  <div className="flex-1">
                    <input data-testid="ip-input" type="text" value={ipAddress} onChange={(e)=>setIpAddress(e.target.value)} onKeyPress={handleKeyPress} placeholder="Enter IP address (e.g., 1.2.3.4)" className="w-full px-6 py-4 rounded-xl text-lg bg-black/40 border-2 border-gray-700 text-white" disabled={loading} />
                  </div>
                  <button data-testid="analyze-button" onClick={handleAnalyze} disabled={loading} className="px-8 py-4 rounded-xl font-semibold text-lg flex items-center gap-3" style={{ background: loading ? '#374151' : 'linear-gradient(135deg,#00ff41 0%,#00cc33 100%)' }}>
                    {loading ? (<><Loader2 className="w-6 h-6 animate-spin"/>Analyzing...</>) : (<><Search className="w-6 h-6"/>Analyze Threat</>)}
                  </button>
                </div>

                <div className="mt-4">
                  <button data-testid="report-button" onClick={handleDownloadReport} disabled={!threatData} className="px-6 py-3 rounded-lg font-semibold text-md flex items-center gap-2 bg-gray-800 text-gray-100">
                    <FileText className="w-5 h-5" /> {threatData ? 'Download Report (PDF)' : 'Run analysis to enable report'}
                  </button>
                </div>

                {error && <div className="mt-4 p-4 rounded-xl bg-red-900/20 border border-red-500/30 flex items-center gap-3"><AlertTriangle className="w-5 h-5 text-red-400"/><p className="text-red-400">{error}</p></div>}

                {threatData && <div className="mt-4 p-3 rounded-xl bg-green-900/10 border border-green-500/20 flex items-center gap-3"><Shield className="w-4 h-4 text-green-400"/><p className="text-green-400 text-sm">Analysis from {new Date(threatData.timestamp).toLocaleString()} <span className="text-gray-500 ml-2">(cached for 24 hours)</span></p></div>}
              </div>
            </div>

            {threatData && (
              <div className="max-w-7xl mx-auto space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <ThreatScoreGauge risk={threatData.risk} />
                  <ThreatCard threatData={threatData} />
                  <Map3D location={threatData.context.location} country={threatData.context.country} />
                </div>

                <div><DnsChecker ip={threatData.ip} /></div>
                <EvidenceTabs evidence={threatData.evidence} />
                <AiReportPanel report={threatData.ai_report} threatData={threatData} />

                {history.length > 0 && (
                  <div className="glass p-6 rounded-2xl">
                    <h2 className="text-2xl font-bold text-white">Analysis History ({history.length})</h2>
                    {loadingHistory ? (<Loader2 className="w-8 h-8 animate-spin text-green-400"/>) : (
                      <div className="space-y-3">
                        {history.map((item, i) => (
                          <div key={i} className="p-4 rounded-xl bg-black/30 border border-gray-700/50">
                            <div className="flex justify-between"><div><strong>{item.risk.label} Risk</strong> • Score: {item.risk.score}</div><div className="text-sm text-gray-400">{new Date(item.timestamp).toLocaleString()}</div></div>
                            <div className="mt-2 text-sm text-gray-300">Country: {item.context.country} • ISP: {item.context.org}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div className="animate-slide-up"><JsonDrawer data={threatData} /></div>
              </div>
            )}

            {!threatData && !loading && (
              <div className="max-w-4xl mx-auto text-center py-20">
                <Shield className="w-24 h-24 mx-auto mb-6 text-gray-600" />
                <h2 className="text-3xl font-bold text-gray-500 mb-4">Enter an IP address to begin threat analysis</h2>
                <p className="text-gray-600 text-lg">TICE correlates data from multiple OSINT sources to provide comprehensive threat intelligence</p>
              </div>
            )}
          </div>
        );
      };

      export default Dashboard;