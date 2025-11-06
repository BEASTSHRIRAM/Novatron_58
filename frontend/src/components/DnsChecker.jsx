import React, { useState, useEffect } from 'react';
import { Globe, Server, Link2, AlertCircle, Loader2, Copy, Check } from 'lucide-react';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const DnsChecker = ({ ip }) => {
  const [dnsData, setDnsData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (ip) {
      fetchDnsData();
    }
  }, [ip]);

  const fetchDnsData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${API}/dns-check`, { ip });
      console.log('DNS Response:', response.data); // Debug log
      setDnsData(response.data.dns_data);
      setError(null);
    } catch (err) {
      console.error('DNS check error:', err);
      const errorMessage = err.response?.data?.detail || err.message || 'Failed to fetch DNS data';
      setError(errorMessage);
      setDnsData(null);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="glass p-6 rounded-2xl">
        <div className="flex items-center gap-2 mb-4">
          <Globe className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-bold" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ffff' }}>
            DNS & Domain Checker
          </h3>
        </div>
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-6 h-6 text-blue-400 animate-spin" />
          <span className="ml-2 text-gray-400">Checking DNS information...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass p-6 rounded-2xl">
        <div className="flex items-center gap-2 mb-4">
          <Globe className="w-5 h-5 text-blue-400" />
          <h3 className="text-lg font-bold" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ffff' }}>
            DNS & Domain Checker
          </h3>
        </div>
        <div className="flex items-center gap-3 p-4 bg-red-900/20 rounded-lg border border-red-500/30">
          <AlertCircle className="w-5 h-5 text-red-400" />
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="glass p-6 rounded-2xl">
      <div className="flex items-center gap-2 mb-6">
        <Globe className="w-5 h-5 text-blue-400" />
        <h3 className="text-lg font-bold" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ffff' }}>
          DNS & Domain Information
        </h3>
      </div>

      {dnsData && (
        <div className="space-y-4">
          {/* Hostname / Reverse DNS */}
          <div className="p-4 bg-black/30 rounded-lg border border-blue-500/20">
            <p className="text-sm text-gray-400 mb-2 flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-400" />
              Hostname / Reverse DNS
            </p>
            <div className="flex items-center justify-between">
              <p className="text-white font-mono text-sm break-all">
                {dnsData.hostname ? (
                  <span className="text-green-400">{dnsData.hostname}</span>
                ) : (
                  <span className="text-gray-500 italic">No reverse DNS record found</span>
                )}
              </p>
              {dnsData.hostname && (
                <button
                  onClick={() => copyToClipboard(dnsData.hostname)}
                  className="ml-2 p-1 hover:bg-blue-500/20 rounded transition-all"
                >
                  {copied ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4 text-blue-400" />
                  )}
                </button>
              )}
            </div>
          </div>

          {/* WHOIS Information */}
          {dnsData.whois_info && Object.keys(dnsData.whois_info).length > 0 && (
            <div className="p-4 bg-black/30 rounded-lg border border-purple-500/20">
              <p className="text-sm text-gray-400 mb-3 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-purple-400" />
                WHOIS / Organization Information
              </p>
              <div className="space-y-2 text-sm">
                {Object.entries(dnsData.whois_info).map(([key, value]) => (
                  <div key={key} className="flex justify-between items-start">
                    <span className="text-gray-500 capitalize font-semibold min-w-fit">{key}:</span>
                    <span className="text-white font-mono text-right break-all max-w-xs">
                      {String(value).substring(0, 100)}
                      {String(value).length > 100 ? '...' : ''}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Related Domains */}
          {dnsData.related_domains && dnsData.related_domains.length > 0 && (
            <div className="p-4 bg-black/30 rounded-lg border border-green-500/20">
              <p className="text-sm text-gray-400 mb-3 flex items-center gap-2">
                <Link2 className="w-4 h-4 text-green-400" />
                Related Domains / Organizations
              </p>
              <div className="flex flex-wrap gap-2">
                {dnsData.related_domains.map((domain, idx) => (
                  <a
                    key={idx}
                    href={`https://${domain}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1 rounded-full text-sm font-semibold hover:scale-105 transition-transform"
                    style={{
                      background: 'rgba(34, 197, 94, 0.2)',
                      border: '1px solid rgba(34, 197, 94, 0.3)',
                      color: '#22c55e'
                    }}
                  >
                    {domain}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* No Data Message */}
          {!dnsData.hostname &&
            (!dnsData.whois_info || Object.keys(dnsData.whois_info).length === 0) &&
            (!dnsData.related_domains || dnsData.related_domains.length === 0) && (
              <div className="p-4 bg-black/30 rounded-lg border border-gray-500/20">
                <p className="text-gray-400 text-sm">
                  ℹ️ Limited DNS information available for this IP. This is normal for many IPs without public reverse DNS records.
                </p>
              </div>
            )}

          {/* Error Message */}
          {dnsData.error && (
            <div className="p-4 bg-yellow-900/20 rounded-lg border border-yellow-500/20">
              <p className="text-yellow-400 text-sm">{dnsData.error}</p>
            </div>
          )}

          {/* Refresh Button */}
          <button
            onClick={fetchDnsData}
            className="w-full mt-4 px-4 py-2 rounded-lg bg-blue-500/20 text-blue-400 border border-blue-500/30 hover:bg-blue-500/30 transition-all"
            style={{ fontFamily: 'Space Grotesk, sans-serif' }}
          >
            🔄 Refresh DNS Data
          </button>
        </div>
      )}
    </div>
  );
};

export default DnsChecker;
