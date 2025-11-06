import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Server, MapPin, AlertCircle, CheckCircle2 } from 'lucide-react';

const EvidenceTabs = ({ evidence }) => {
  const { abuseipdb, shodan, ipinfo } = evidence;

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
            data-testid="tab-shodan"
            value="shodan"
            className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400 text-gray-400 rounded-md transition-all"
          >
            <Server className="w-4 h-4 mr-2" />
            Shodan
          </TabsTrigger>
          <TabsTrigger
            data-testid="tab-ipinfo"
            value="ipinfo"
            className="data-[state=active]:bg-green-500/20 data-[state=active]:text-green-400 text-gray-400 rounded-md transition-all"
          >
            <MapPin className="w-4 h-4 mr-2" />
            IPInfo
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

        <TabsContent value="shodan" className="mt-6 space-y-4">
          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Open Ports</p>
            <div className="flex flex-wrap gap-2">
              {shodan.open_ports && shodan.open_ports.length > 0 ? (
                shodan.open_ports.map((port, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1 rounded-full text-sm font-semibold"
                    style={{
                      background: 'rgba(0, 255, 65, 0.2)',
                      border: '1px solid rgba(0, 255, 65, 0.3)',
                      color: '#00ff41'
                    }}
                  >
                    {port}
                  </span>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No open ports detected</p>
              )}
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Vulnerabilities</p>
            <div className="space-y-2">
              {shodan.vulnerabilities && shodan.vulnerabilities.length > 0 ? (
                shodan.vulnerabilities.map((vuln, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-red-400" />
                    <span className="text-red-400 font-mono text-sm">{vuln}</span>
                  </div>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No known vulnerabilities</p>
              )}
            </div>
          </div>

          <div className="p-4 bg-black/30 rounded-lg">
            <p className="text-sm text-gray-400 mb-2">Operating System</p>
            <p className="text-white font-medium">{shodan.os}</p>
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