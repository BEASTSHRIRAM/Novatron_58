import React, { useState } from 'react';
import axios from 'axios';
import ThreatScoreGauge from '../components/ThreatScoreGauge';
import ThreatCard from '../components/ThreatCard';
import Map3D from '../components/Map3D';
import EvidenceTabs from '../components/EvidenceTabs';
import AiReportPanel from '../components/AiReportPanel';
import JsonDrawer from '../components/JsonDrawer';
import { Loader2, Shield, Search, AlertTriangle } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const [ipAddress, setIpAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [threatData, setThreatData] = useState(null);
  const [error, setError] = useState(null);

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
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze IP address');
    } finally {
      setLoading(false);
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
        <div className="flex items-center gap-4 mb-2">
          <Shield className="w-10 h-10 text-green-400" style={{ filter: 'drop-shadow(0 0 10px rgba(0,255,65,0.5))' }} />
          <h1 className="text-5xl lg:text-6xl font-bold" style={{ 
            fontFamily: 'Space Grotesk, sans-serif',
            background: 'linear-gradient(135deg, #00ff41 0%, #a855f7 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            textShadow: '0 0 30px rgba(0,255,65,0.3)'
          }}>
            TICE
          </h1>
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

          {/* Evidence Tabs */}
          <div className="animate-slide-up" style={{ animationDelay: '0.3s' }}>
            <EvidenceTabs evidence={threatData.evidence} />
          </div>

          {/* AI Report */}
          <div className="animate-slide-up" style={{ animationDelay: '0.4s' }}>
            <AiReportPanel report={threatData.ai_report} />
          </div>

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