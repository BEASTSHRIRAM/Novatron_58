import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Bug, MapPin, AlertCircle, CheckCircle2 } from 'lucide-react';

const EvidenceTabs = ({ evidence }) => {
  const { abuseipdb, otx, ipinfo } = evidence;
  
  // Debug logging
  console.log('Evidence data:', evidence);
  console.log('OTX data:', otx);
  
  // Extract OTX stats - check both nested and flat structure
  const otxStats = otx?.analysis_stats || otx || {};
  console.log('OTX Stats:', otxStats);
  
  const otxMalicious = otxStats.malicious || 0;
  const otxSuspicious = otxStats.suspicious || 0;
  const otxHarmless = otxStats.harmless || 0;
  const otxUndetected = otxStats.undetected || 0;
  const otxReputation = otx?.reputation || 0;
  const otxReputationScore = otx?.reputation_score || 0;  // 0-10 scale
  const otxPulseCount = otx?.pulse_count || 0;
  const otxThreatGroups = otx?.threat_groups || [];
  const otxMalwareFamilies = otx?.malware_families || [];
  const otxIndustries = otx?.industries || [];
  const otxCves = otx?.cves || [];
  
  // Total vendors analyzed
  const totalEngines = otxMalicious + otxSuspicious + otxHarmless + otxUndetected;

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
            data-testid="tab-otx"
            value="otx"
            className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400 text-gray-400 rounded-md transition-all"
          >
            <Bug className="w-4 h-4 mr-2" />
            OTX (AlienVault)
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

        <TabsContent value="otx" className="mt-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">OTX Reputation Score</p>
              <p className="text-2xl font-bold" style={{
                color: otxReputationScore >= 7 ? '#ef4444' : otxReputationScore >= 4 ? '#f59e0b' : '#00ff41',
                fontFamily: 'Space Grotesk, sans-serif'
              }}>
                {otxReputationScore}/10
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {otxReputationScore >= 7 ? 'Very Bad' : otxReputationScore >= 4 ? 'Suspicious' : 'Good'}
              </p>
            </div>
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Raw OTX Reputation</p>
              <p className="text-2xl font-bold text-purple-400" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                {otxReputation === null || otxReputation === undefined ? 'N/A' : otxReputation}
              </p>
              <p className="text-xs text-gray-500 mt-1">From OTX API</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Threat Pulses</p>
              <p className="text-2xl font-bold" style={{
                color: otxPulseCount > 10 ? '#ef4444' : otxPulseCount > 0 ? '#f59e0b' : '#00ff41',
                fontFamily: 'Space Grotesk, sans-serif'
              }}>
                {otxPulseCount}
              </p>
              <p className="text-xs text-gray-500 mt-1">
                {otxPulseCount > 10 ? 'High Activity' : otxPulseCount > 0 ? 'Some Reports' : 'No Reports'}
              </p>
            </div>
            <div className="p-4 bg-black/30 rounded-lg">
              <p className="text-sm text-gray-400 mb-1">Malware Families</p>
              <p className="text-2xl font-bold text-red-400" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                {otxMalwareFamilies?.length || 0}
              </p>
              <p className="text-xs text-gray-500 mt-1">Identified</p>
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Threat Groups</p>
            <div className="flex flex-wrap gap-2">
              {otxThreatGroups && otxThreatGroups.length > 0 ? (
                otxThreatGroups.slice(0, 5).map((group, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 rounded-full text-sm font-semibold"
                    style={{
                      background: 'rgba(168, 85, 247, 0.2)',
                      border: '1px solid rgba(168, 85, 247, 0.4)',
                      color: '#a855f7'
                    }}
                  >
                    {group}
                  </span>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No threat groups identified</p>
              )}
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Malware Families</p>
            <div className="flex flex-wrap gap-2">
              {otxMalwareFamilies && otxMalwareFamilies.length > 0 ? (
                otxMalwareFamilies.slice(0, 5).map((malware, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 rounded-full text-sm font-semibold"
                    style={{
                      background: 'rgba(239, 68, 68, 0.2)',
                      border: '1px solid rgba(239, 68, 68, 0.4)',
                      color: '#ef4444'
                    }}
                  >
                    {malware}
                  </span>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No malware families identified</p>
              )}
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Targeted Industries</p>
            <div className="flex flex-wrap gap-2">
              {otxIndustries && otxIndustries.length > 0 ? (
                otxIndustries.slice(0, 8).map((industry, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 rounded-full text-sm font-semibold"
                    style={{
                      background: 'rgba(245, 158, 11, 0.2)',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                      color: '#f59e0b'
                    }}
                  >
                    {industry}
                  </span>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No specific industries targeted</p>
              )}
            </div>
          </div>

          <div className={`p-4 bg-black/30 rounded-lg ${otxCves.length > 0 ? 'border-2 border-red-500/30' : ''}`}>
            <p className="text-sm text-gray-400 mb-2 flex items-center gap-2">
              <AlertCircle className={`w-4 h-4 ${otxCves.length > 0 ? 'text-red-400' : 'text-gray-500'}`} />
              Known CVEs
            </p>
            <div className="flex flex-wrap gap-2">
              {otxCves.length > 0 ? (
                otxCves.map((cve, idx) => (
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
            <p className="text-sm text-gray-400 mb-2">Detection Summary</p>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div>
                <p className="text-sm text-red-400 font-semibold">{otxMalicious}</p>
                <p className="text-xs text-gray-500">Malicious</p>
              </div>
              <div>
                <p className="text-sm text-yellow-400 font-semibold">{otxSuspicious}</p>
                <p className="text-xs text-gray-500">Suspicious</p>
              </div>
              <div>
                <p className="text-sm text-green-400 font-semibold">{otxHarmless}</p>
                <p className="text-xs text-gray-500">Harmless</p>
              </div>
            </div>
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