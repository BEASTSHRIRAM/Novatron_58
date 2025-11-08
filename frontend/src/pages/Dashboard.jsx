import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import ThreatScoreGauge from '../components/ThreatScoreGauge';
import ThreatCard from '../components/ThreatCard';
import Map3D from '../components/Map3D';
import EvidenceTabs from '../components/EvidenceTabs';
import AiReportPanel from '../components/AiReportPanel';
import JsonDrawer from '../components/JsonDrawer';
import DnsChecker from '../components/DnsChecker';
import { Loader2, Shield, Search, AlertTriangle, Home } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// AbuseIPDB Category Mapping
const ABUSE_CATEGORIES = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  13: "VPN IP",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH Attack",
  23: "IoT Targeted"
};

const Dashboard = () => {
  const navigate = useNavigate();
  const [userRole, setUserRole] = useState(localStorage.getItem('userRole') || 'investigator');
  const [ipAddress, setIpAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [threatData, setThreatData] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const handleAnalyze = async () => {
    if (!ipAddress.trim()) {
      setError('Please enter a valid IP address');
      return;
    }

    setLoading(true);
    setError(null);
    setThreatData(null);

    try {
      const response = await axios.post(`${API}/analyze`, {
        ip: ipAddress.trim()
      });
      setThreatData(response.data);
      
      // Fetch history after successful analysis
      fetchHistory(ipAddress.trim());
    } catch (err) {
      // Handle different error response formats
      let errorMessage = 'Failed to analyze IP address';
      
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        
        // Check if detail is an array (Pydantic validation errors)
        if (Array.isArray(detail)) {
          errorMessage = detail.map(e => e.msg || JSON.stringify(e)).join(', ');
        } else if (typeof detail === 'string') {
          errorMessage = detail;
        } else {
          errorMessage = JSON.stringify(detail);
        }
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const fetchHistory = async (ip) => {
    setLoadingHistory(true);
    try {
      const response = await axios.get(`${API}/history/${ip}`);
      setHistory(response.data.history || []);
    } catch (err) {
      console.error('Failed to fetch history:', err);
      setHistory([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleAnalyze();
    }
  };

  return (
    <div className="min-h-screen p-6 lg:p-8" style={{ background: 'linear-gradient(135deg, #0a0a0f 0%, #1a0f2e 100%)' }}>
      {/* Header */}
      <div className="max-w-7xl mx-auto mb-8 animate-slide-up">
        <div className="flex items-center justify-between gap-4 mb-2">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="p-2 hover:bg-gray-800 rounded-lg transition-all"
              title="Back to Home"
            >
              <Home className="w-6 h-6 text-gray-400 hover:text-green-400" />
            </button>
            <h1 className="text-5xl lg:text-6xl font-bold" style={{ 
              fontFamily: 'Space Grotesk, sans-serif',
              background: 'linear-gradient(135deg, #00ff41 0%, #a855f7 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              textShadow: '0 0 30px rgba(0,255,65,0.3)'
            }}>
              PredwinAI
            </h1>
          </div>
          <div className="text-right">
            <span className="inline-block px-3 py-1 rounded-full bg-gradient-to-r from-green-400/20 to-purple-500/20 border border-green-400/30 text-green-400 text-sm font-semibold">
              {userRole === 'investigator' ? 'Investigator' : '🛡️ SOC Analyst'}
            </span>
          </div>
        </div>
        <p className="text-gray-400 text-lg" style={{ fontFamily: 'Inter, sans-serif' }}>
          Threat Intelligence Correlation Engine - Advanced IP Analysis & Attribution
        </p>
      </div>

      {/* IP Input Section */}
      <div className="max-w-7xl mx-auto mb-8 animate-slide-up" style={{ animationDelay: '0.1s' }}>
        <div className="glass p-6 rounded-2xl">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1">
              <input
                data-testid="ip-input"
                type="text"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Enter IP address (e.g., 1.2.3.4)"
                className="w-full px-6 py-4 rounded-xl text-lg bg-black/40 border-2 border-gray-700 text-white focus:border-green-400 focus:outline-none transition-all"
                style={{ fontFamily: 'Space Grotesk, sans-serif' }}
                disabled={loading}
              />
            </div>
            <button
              data-testid="analyze-button"
              onClick={handleAnalyze}
              disabled={loading}
              className="px-8 py-4 rounded-xl font-semibold text-lg flex items-center justify-center gap-3 transition-all transform hover:scale-105"
              style={{
                background: loading ? '#374151' : 'linear-gradient(135deg, #00ff41 0%, #00cc33 100%)',
                color: '#000',
                boxShadow: loading ? 'none' : '0 0 30px rgba(0,255,65,0.4)',
                fontFamily: 'Space Grotesk, sans-serif'
              }}
            >
              {loading ? (
                <>
                  <Loader2 className="w-6 h-6 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-6 h-6" />
                  Analyze Threat
                </>
              )}
            </button>
          </div>

          {error && (
            <div data-testid="error-message" className="mt-4 p-4 rounded-xl bg-red-900/20 border border-red-500/30 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <p className="text-red-400">{error}</p>
            </div>
          )}
          
          {threatData && (
            <div className="mt-4 p-3 rounded-xl bg-green-900/10 border border-green-500/20 flex items-center gap-3">
              <Shield className="w-4 h-4 text-green-400" />
              <p className="text-green-400 text-sm">
                Analysis from {new Date(threatData.timestamp).toLocaleString()} 
                <span className="text-gray-500 ml-2">
                  (cached for 24 hours)
                </span>
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Results Section */}
      {threatData && (
        <div className="max-w-7xl mx-auto space-y-6">
          {/* Top Row: Score, Card, Globe */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-slide-up" style={{ animationDelay: '0.2s' }}>
            <ThreatScoreGauge risk={threatData.risk} />
            <ThreatCard threatData={threatData} />
            <Map3D location={threatData.context.location} country={threatData.context.country} />
          </div>

          {/* DNS & Domain Checker */}
          <div className="animate-slide-up" style={{ animationDelay: '0.25s' }}>
            <DnsChecker ip={threatData.ip} />
          </div>

          {/* Evidence Tabs */}
          <div className="animate-slide-up" style={{ animationDelay: '0.3s' }}>
            <EvidenceTabs evidence={threatData.evidence} />
          </div>

          {/* AI Report */}
          <div className="animate-slide-up" style={{ animationDelay: '0.4s' }}>
            <AiReportPanel report={threatData.ai_report} threatData={threatData} />
          </div>

          {/* Analysis History */}
          {history.length > 0 && (
            <div className="animate-slide-up" style={{ animationDelay: '0.45s' }}>
              <div className="glass p-6 rounded-2xl">
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-3" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Analysis History
                  <span className="text-sm text-gray-500 font-normal">({history.length} past analyses)</span>
                </h2>
                
                {loadingHistory ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-8 h-8 animate-spin text-green-400" />
                  </div>
                ) : (
                  <div className="space-y-3">
                    {history.map((item, index) => (
                      <div 
                        key={index}
                        className="p-4 rounded-xl bg-black/30 border border-gray-700/50 hover:border-green-400/30 transition-all cursor-pointer"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <div 
                              className="w-3 h-3 rounded-full"
                              style={{
                                backgroundColor: 
                                  item.risk?.label === 'Critical' ? '#ef4444' :
                                  item.risk?.label === 'High' ? '#f59e0b' :
                                  item.risk?.label === 'Medium' ? '#eab308' :
                                  item.risk?.label === 'Low' ? '#10b981' : '#6b7280'
                              }}
                            />
                            <span className="font-semibold text-white">{item.risk?.label || 'Unknown'} Risk</span>
                            <span className="text-gray-400">•</span>
                            <span className="text-gray-400">Score: {item.risk?.score || 0}</span>
                          </div>
                          <span className="text-sm text-gray-500">
                            {new Date(item.timestamp).toLocaleString()}
                          </span>
                        </div>
                        
                        <div className="flex flex-wrap gap-2 mb-2">
                          {item.categories && item.categories.map((cat, idx) => (
                            <span 
                              key={idx}
                              className="px-3 py-1 text-xs rounded-full bg-purple-900/30 text-purple-300 border border-purple-500/30"
                            >
                              {cat}
                            </span>
                          ))}
                        </div>
                        
                        <div className="text-sm text-gray-400">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-2">
                            <div>
                              <span className="text-gray-500">Country:</span> {item.context.country}
                            </div>
                            <div>
                              <span className="text-gray-500">ISP:</span> {item.context.org?.substring(0, 30)}...
                            </div>
                            <div>
                              <span className="text-gray-500">Abuse Reports:</span> {item.evidence.abuseipdb?.total_reports || 0}
                            </div>
                            <div>
                              <span className="text-gray-500">OTX Detections:</span> {item.evidence.otx?.analysis_stats?.malicious || 0}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Attack History from AbuseIPDB */}
          {threatData.evidence?.abuseipdb?.reports && threatData.evidence.abuseipdb.reports.length > 0 && (
            <div className="animate-slide-up" style={{ animationDelay: '0.46s' }}>
              <div className="glass p-6 rounded-2xl border-2 border-red-500/20">
                <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-3" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                  Previous Attack Reports
                  <span className="text-sm text-gray-500 font-normal">
                    ({threatData.evidence.abuseipdb.reports.length} incidents reported)
                  </span>
                </h2>
                
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {threatData.evidence.abuseipdb.reports.map((report, index) => {
                    // Convert category numbers to names
                    const categoryNames = report.categories.map(catId => 
                      ABUSE_CATEGORIES[catId] || `Category ${catId}`
                    );
                    
                    // Try to parse JSON or structured data from comments
                    let displayComment = report.comment;
                    let parsedEvents = [];
                    
                    if (displayComment) {
                      // Try to extract JSON objects
                      try {
                        const jsonMatches = displayComment.match(/\{"event":\{[^}]+\}[^}]*\}/g);
                        if (jsonMatches) {
                          parsedEvents = jsonMatches.map(json => JSON.parse(json));
                          displayComment = null;
                        }
                      } catch (e) {
                        console.log('JSON parse failed, trying alternate format');
                      }
                      
                      // If no JSON, try to parse SSH log format
                      if (!parsedEvents.length && displayComment.includes('sshd[')) {
                        const lines = displayComment.split(/(?=\d{4}-\d{2}-\d{2}T)/);
                        parsedEvents = lines.filter(line => line.trim()).map(line => {
                          const timeMatch = line.match(/(\d{4}-\d{2}-\d{2}T[\d:+]+)/);
                          const userMatch = line.match(/(?:user|invalid user)\s+(\w+)/i);
                          const ipMatch = line.match(/from\s+([\d.]+)/);
                          const portMatch = line.match(/port\s+(\d+)/);
                          const actionMatch = line.match(/sshd\[\d+\]:\s*([^:]+)/);
                          
                          return {
                            parsed: true,
                            time: timeMatch ? timeMatch[1] : null,
                            user: userMatch ? userMatch[1] : 'unknown',
                            ip: ipMatch ? ipMatch[1] : null,
                            port: portMatch ? portMatch[1] : null,
                            action: actionMatch ? actionMatch[1].trim() : 'SSH authentication failure',
                            rawLine: line.substring(0, 200)
                          };
                        });
                        displayComment = null;
                      }
                    }
                    
                    return (
                      <div 
                        key={index}
                        className="p-4 rounded-xl bg-red-900/10 border border-red-500/20 hover:border-red-400/40 transition-all"
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2 flex-wrap">
                              {categoryNames.map((catName, idx) => (
                                <span key={idx} className="px-2 py-1 text-xs rounded bg-red-500/20 text-red-300 font-semibold">
                                  {catName}
                                </span>
                              ))}
                              <span className="text-xs text-gray-500">
                                • Reported by {report.reporterCountryName || 'Unknown'}
                              </span>
                            </div>
                            
                            {parsedEvents.length > 0 ? (
                              <div className="space-y-2 text-sm">
                                {parsedEvents.map((data, idx) => {
                                  if (data.parsed) {
                                    // SSH log format
                                    return (
                                      <div key={idx} className="bg-black/40 rounded p-3 font-mono text-xs border border-gray-700">
                                        <div className="grid grid-cols-2 gap-2">
                                          {data.action && (
                                            <div className="col-span-2"><span className="text-gray-500">Action:</span> <span className="text-orange-400">{data.action}</span></div>
                                          )}
                                          {data.user && (
                                            <div><span className="text-gray-500">Username:</span> <span className="text-red-400">{data.user}</span></div>
                                          )}
                                          {data.ip && (
                                            <div><span className="text-gray-500">From IP:</span> <span className="text-yellow-400">{data.ip}</span></div>
                                          )}
                                          {data.port && (
                                            <div><span className="text-gray-500">Port:</span> <span className="text-cyan-400">{data.port}</span></div>
                                          )}
                                          {data.time && (
                                            <div><span className="text-gray-500">Time:</span> <span className="text-gray-300">{new Date(data.time).toLocaleString()}</span></div>
                                          )}
                                        </div>
                                      </div>
                                    );
                                  }
                                  
                                  // JSON event format
                                  const event = data.event || {};
                                  return (
                                    <div key={idx} className="bg-black/40 rounded p-3 font-mono text-xs border border-gray-700">
                                      <div className="grid grid-cols-2 gap-2">
                                        {event.Protocol && (
                                          <div><span className="text-gray-500">Protocol:</span> <span className="text-cyan-400">{event.Protocol}</span></div>
                                        )}
                                        {event.RemoteAddr && (
                                          <div><span className="text-gray-500">Source:</span> <span className="text-yellow-400">{event.RemoteAddr}</span></div>
                                        )}
                                        {event.User && (
                                          <div><span className="text-gray-500">Username:</span> <span className="text-red-400">{event.User}</span></div>
                                        )}
                                        {event.Password && (
                                          <div><span className="text-gray-500">Password:</span> <span className="text-red-400">{event.Password}</span></div>
                                        )}
                                        {event.Client && (
                                          <div><span className="text-gray-500">Client:</span> <span className="text-blue-400">{event.Client}</span></div>
                                        )}
                                        {event.DateTime && (
                                          <div><span className="text-gray-500">Time:</span> <span className="text-gray-300">{new Date(event.DateTime).toLocaleString()}</span></div>
                                        )}
                                        {event.Description && (
                                          <div className="col-span-2"><span className="text-gray-500">Action:</span> <span className="text-orange-400">{event.Description}</span></div>
                                        )}
                                        {event.Msg && (
                                          <div className="col-span-2"><span className="text-gray-500">Message:</span> <span className="text-purple-400">{event.Msg}</span></div>
                                        )}
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            ) : displayComment ? (
                              <p className="text-sm text-gray-300 mb-2 break-words">
                                {displayComment}
                              </p>
                            ) : null}
                          </div>
                          
                          <span className="text-xs text-gray-500 whitespace-nowrap ml-4">
                            {new Date(report.reportedAt).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* No Attack History Message */}
          {threatData.evidence?.abuseipdb?.total_reports === 0 && (
            <div className="animate-slide-up" style={{ animationDelay: '0.46s' }}>
              <div className="glass p-6 rounded-2xl border-2 border-green-500/20">
                <div className="flex items-center gap-3 text-green-400">
                  <Shield className="w-6 h-6" />
                  <div>
                    <h3 className="font-semibold text-lg">No Attack History Found</h3>
                    <p className="text-sm text-gray-400">This IP has no reported malicious activities in the AbuseIPDB database</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* JSON Drawer */}
          <div className="animate-slide-up" style={{ animationDelay: '0.5s' }}>
            <JsonDrawer data={threatData} />
          </div>
        </div>
      )}

      {/* Empty State */}
      {!threatData && !loading && (
        <div className="max-w-4xl mx-auto text-center py-20">
          <Shield className="w-24 h-24 mx-auto mb-6 text-gray-600" />
          <h2 className="text-3xl font-bold text-gray-500 mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Enter an IP address to begin threat analysis
          </h2>
          <p className="text-gray-600 text-lg">
            TICE correlates data from multiple OSINT sources to provide comprehensive threat intelligence
          </p>
        </div>
      )}
    </div>
  );
};

export default Dashboard;