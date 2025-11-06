import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Bug, MapPin, AlertCircle, CheckCircle2 } from 'lucide-react';

const EvidenceTabs = ({ evidence }) => {
  const { abuseipdb, virustotal, ipinfo } = evidence;
  
  // Debug logging
  console.log('Evidence data:', evidence);
  console.log('VirusTotal data:', virustotal);
  
  // Extract VirusTotal stats - check both nested and flat structure
  const vtStats = virustotal?.analysis_stats || virustotal || {};
  console.log('VT Stats:', vtStats);
  
  const vtMalicious = vtStats.malicious || 0;
  const vtSuspicious = vtStats.suspicious || 0;
  const vtHarmless = vtStats.harmless || 0;
  const vtUndetected = vtStats.undetected || 0;
  const vtReputation = virustotal?.reputation || 0;
  const vtTags = virustotal?.tags || [];
  const vtCves = virustotal?.cves || [];
  
  // Handle total_votes - it can be a number or an object
  let vtTotalVotes = virustotal?.total_votes || 0;
  if (typeof vtTotalVotes === 'object') {
    // If it's an object, sum the values
    vtTotalVotes = Object.values(vtTotalVotes).reduce((a, b) => a + b, 0);
  }
  
  const totalEngines = vtTotalVotes || (vtMalicious + vtSuspicious + vtHarmless + vtUndetected);

  return (
    <div data-testid="evidence-tabs" className="glass p-6 rounded-2xl">
      <h3 className="text-xl font-bold mb-6" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#a855f7' }}>
        Evidence Analysis
      </h3>

      <Tabs defaultValue="abuseipdb" className="w-full">
        <TabsList className="grid w-full grid-cols-3 bg-black/40 p-1 rounded-lg">
          <TabsTrigger
            data-testid="tab-abuseipdb"
            value="abuseipdb"
            className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400 text-gray-400 rounded-md transition-all"
          >
            <Shield className="w-4 h-4 mr-2" />
            AbuseIPDB
          </TabsTrigger>
          <TabsTrigger
            data-testid="tab-virustotal"
            value="virustotal"
            className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400 text-gray-400 rounded-md transition-all"
          >
            <Bug className="w-4 h-4 mr-2" />
            VirusTotal
          </TabsTrigger>
          <TabsTrigger
            data-testid="tab-ipdata"
            value="ipinfo"
            className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400 text-gray-400 rounded-md transition-all"
          >
            <MapPin className="w-4 h-4 mr-2" />
            IPData.co
          </TabsTrigger>
        </TabsList>

        <TabsContent value="abuseipdb" className="mt-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Confidence Score</p>
              <p className="text-2xl font-bold" style={{
                color: abuseipdb.confidence_score > 50 ? '#ef4444' : '#00ff41',
                fontFamily: 'Space Grotesk, sans-serif'
              }}>
                {abuseipdb.confidence_score}%
              </p>
            </div>
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Total Reports</p>
              <p className="text-2xl font-bold text-white" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                {abuseipdb.total_reports}
              </p>
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Usage Type</p>
            <p className="text-white font-medium">{abuseipdb.usage_type}</p>
          </div>

          <div className="flex items-center gap-2 p-4 bg-black/30 rounded-lg">
            {abuseipdb.is_whitelisted ? (
              <CheckCircle2 className="w-5 h-5 text-green-400" />
            ) : (
              <AlertCircle className="w-5 h-5 text-yellow-400" />
            )}
            <p className="text-white">
              {abuseipdb.is_whitelisted ? 'Whitelisted' : 'Not Whitelisted'}
            </p>
          </div>
        </TabsContent>

        <TabsContent value="virustotal" className="mt-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Malicious Detections</p>
              <p className="text-2xl font-bold" style={{
                color: vtMalicious > 5 ? '#ef4444' : vtMalicious > 0 ? '#f59e0b' : '#00ff41',
                fontFamily: 'Space Grotesk, sans-serif'
              }}>
                {vtMalicious}
              </p>
            </div>
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Suspicious Detections</p>
              <p className="text-2xl font-bold" style={{
                color: vtSuspicious > 3 ? '#f59e0b' : '#00ff41',
                fontFamily: 'Space Grotesk, sans-serif'
              }}>
                {vtSuspicious}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Harmless</p>
              <p className="text-2xl font-bold text-green-400" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                {vtHarmless}
              </p>
            </div>
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Reputation Score</p>
              <p className="text-2xl font-bold" style={{
                color: vtReputation < 0 ? '#ef4444' : '#00ff41',
                fontFamily: 'Space Grotesk, sans-serif'
              }}>
                {vtReputation}
              </p>
            </div>
          </div>

          <div className={`p-4 bg-black/30 rounded-lg ${vtCves.length > 0 ? 'border-2 border-red-500/30' : ''}`}>
            <p className="text-sm text-gray-400 mb-2 flex items-center gap-2">
              <AlertCircle className={`w-4 h-4 ${vtCves.length > 0 ? 'text-red-400' : 'text-gray-500'}`} />
              Known CVEs
            </p>
            <div className="flex flex-wrap gap-2">
              {vtCves.length > 0 ? (
                vtCves.map((cve, idx) => (
                  <a
                    key={idx}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1 rounded-full text-sm font-semibold hover:scale-105 transition-transform"
                    style={{
                      background: 'rgba(220, 38, 38, 0.2)',
                      border: '1px solid rgba(220, 38, 38, 0.4)',
                      color: '#dc2626'
                    }}
                  >
                    {cve}
                  </a>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No CVEs detected</p>
              )}
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Threat Tags</p>
            <div className="flex flex-wrap gap-2">
              {vtTags && vtTags.length > 0 ? (
                vtTags.map((tag, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 rounded-full text-sm font-semibold"
                    style={{
                      background: 'rgba(239, 68, 68, 0.2)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      color: '#ef4444'
                    }}
                  >
                    {tag}
                  </span>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No threat tags</p>
              )}
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Total Votes</p>
            <p className="text-white font-medium">{totalEngines} engines analyzed</p>
          </div>
        </TabsContent>

        <TabsContent value="ipinfo" className="mt-6 space-y-4">
          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Geolocation</p>
            <p className="text-white font-medium">{ipinfo.geolocation || 'Unknown'}</p>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Organization</p>
            <p className="text-white font-medium">{ipinfo.organization}</p>
          </div>

          {ipinfo.hostname && (
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-2">Hostname</p>
              <p className="text-white font-medium break-all">{ipinfo.hostname}</p>
            </div>
          )}

          {ipinfo.postal_code && (
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-2">Postal Code</p>
              <p className="text-white font-medium">{ipinfo.postal_code}</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default EvidenceTabs;