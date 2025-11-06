import React from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity, Database } from 'lucide-react';

const EvidenceTabs = ({ evidence }) => {
  // Create unified evidence structure
  const unified = {
    threatScore: {
      abuseConfidence: evidence?.abuseipdb?.confidence_score || 0,
      vtReputation: evidence?.virustotal?.reputation || 0,
      totalDetections: evidence?.virustotal?.analysis_stats?.malicious || 0
    },
    abuseHistory: {
      totalReports: evidence?.abuseipdb?.total_reports || 0,
      lastReported: evidence?.abuseipdb?.last_reported,
      isWhitelisted: evidence?.abuseipdb?.is_whitelisted || false,
      usageType: evidence?.abuseipdb?.usage_type || 'Unknown',
      reports: evidence?.abuseipdb?.reports || []
    },
    malwareAnalysis: {
      malicious: evidence?.virustotal?.analysis_stats?.malicious || 0,
      suspicious: evidence?.virustotal?.analysis_stats?.suspicious || 0,
      harmless: evidence?.virustotal?.analysis_stats?.harmless || 0,
      undetected: evidence?.virustotal?.analysis_stats?.undetected || 0,
      reputation: evidence?.virustotal?.reputation || 0,
      tags: evidence?.virustotal?.tags || [],
      cves: evidence?.virustotal?.cves || []
    },
    geolocation: {
      location: evidence?.ipinfo?.geolocation || 'Unknown',
      organization: evidence?.ipinfo?.organization || 'Unknown',
      hostname: evidence?.ipinfo?.hostname || 'N/A',
      postalCode: evidence?.ipinfo?.postal_code || ''
    },
    threatClassification: {
      greynoise: evidence?.greynoise?.classification || 'unknown',
      actor: evidence?.greynoise?.actor || 'Unknown',
      tags: evidence?.greynoise?.tags || [],
      firstSeen: evidence?.greynoise?.first_seen,
      lastSeen: evidence?.greynoise?.last_seen,
      riot: evidence?.greynoise?.riot || false
    },
    infrastructure: {
      ports: evidence?.shodan?.ports || [],
      services: evidence?.shodan?.services || [],
      vulns: evidence?.shodan?.vulns || [],
      hostnames: evidence?.shodan?.hostnames || []
    }
  };

  const totalVotes = unified.malwareAnalysis.malicious + 
                     unified.malwareAnalysis.suspicious + 
                     unified.malwareAnalysis.harmless + 
                     unified.malwareAnalysis.undetected;

  return (
    <div className="glass p-6 rounded-2xl">
      <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
        <Database className="w-6 h-6 text-purple-400" />
        Unified Threat Intelligence Analysis
      </h2>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Threat Scoring */}
        <div className="bg-black/30 rounded-xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-green-400" />
            <h3 className="text-lg font-semibold text-white">Threat Scoring</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Abuse Confidence</span>
              <div className="flex items-center gap-2">
                <div className="w-32 h-2 bg-gray-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-green-500 to-red-500"
                    style={{ width: `${unified.threatScore.abuseConfidence}%` }}
                  />
                </div>
                <span className={`font-bold ${unified.threatScore.abuseConfidence > 75 ? 'text-red-400' : unified.threatScore.abuseConfidence > 50 ? 'text-orange-400' : 'text-green-400'}`}>
                  {unified.threatScore.abuseConfidence}%
                </span>
              </div>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-gray-400">VirusTotal Reputation</span>
              <span className={`font-bold ${unified.threatScore.vtReputation < -10 ? 'text-red-400' : unified.threatScore.vtReputation < 0 ? 'text-orange-400' : 'text-green-400'}`}>
                {unified.threatScore.vtReputation}
              </span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Malicious Detections</span>
              <span className={`font-bold ${unified.threatScore.totalDetections > 5 ? 'text-red-400' : unified.threatScore.totalDetections > 0 ? 'text-orange-400' : 'text-green-400'}`}>
                {unified.threatScore.totalDetections}/{totalVotes}
              </span>
            </div>
          </div>
        </div>

        {/* Abuse History */}
        <div className="bg-black/30 rounded-xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h3 className="text-lg font-semibold text-white">Abuse History</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Total Reports</span>
              <span className="font-bold text-white">{unified.abuseHistory.totalReports}</span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Usage Type</span>
              <span className="font-bold text-purple-400">{unified.abuseHistory.usageType}</span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Whitelisted</span>
              {unified.abuseHistory.isWhitelisted ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : (
                <span className="text-gray-500">No</span>
              )}
            </div>
            
            {unified.abuseHistory.lastReported && (
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Last Reported</span>
                <span className="text-sm text-gray-500">{new Date(unified.abuseHistory.lastReported).toLocaleDateString()}</span>
              </div>
            )}
          </div>
        </div>

        {/* Malware Analysis */}
        <div className="bg-black/30 rounded-xl p-5 border border-gray-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-purple-400" />
            <h3 className="text-lg font-semibold text-white">Security Analysis</h3>
          </div>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-red-900/20 rounded-lg p-3 border border-red-500/30">
                <div className="text-xs text-red-400 mb-1">Malicious</div>
                <div className="text-2xl font-bold text-red-400">{unified.malwareAnalysis.malicious}</div>
              </div>
              
              <div className="bg-orange-900/20 rounded-lg p-3 border border-orange-500/30">
                <div className="text-xs text-orange-400 mb-1">Suspicious</div>
                <div className="text-2xl font-bold text-orange-400">{unified.malwareAnalysis.suspicious}</div>
              </div>
              
              <div className="bg-green-900/20 rounded-lg p-3 border border-green-500/30">
                <div className="text-xs text-green-400 mb-1">Harmless</div>
                <div className="text-2xl font-bold text-green-400">{unified.malwareAnalysis.harmless}</div>
              </div>
              
              <div className="bg-gray-900/20 rounded-lg p-3 border border-gray-500/30">
                <div className="text-xs text-gray-400 mb-1">Undetected</div>
                <div className="text-2xl font-bold text-gray-400">{unified.malwareAnalysis.undetected}</div>
              </div>
            </div>
            
            {unified.malwareAnalysis.tags.length > 0 && (
              <div>
                <div className="text-xs text-gray-500 mb-2">Threat Tags</div>
                <div className="flex flex-wrap gap-2">
                  {unified.malwareAnalysis.tags.slice(0, 6).map((tag, idx) => (
                    <span key={idx} className="px-2 py-1 text-xs rounded bg-purple-900/30 text-purple-300 border border-purple-500/30">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Threat Classification */}
        {unified.threatClassification.greynoise !== 'unknown' && (
          <div className="bg-black/30 rounded-xl p-5 border border-gray-700/50">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-yellow-400" />
              <h3 className="text-lg font-semibold text-white">Threat Intelligence</h3>
            </div>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-gray-400">Classification</span>
                <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                  unified.threatClassification.greynoise === 'malicious' ? 'bg-red-900/30 text-red-400 border border-red-500/30' :
                  unified.threatClassification.greynoise === 'benign' ? 'bg-green-900/30 text-green-400 border border-green-500/30' :
                  'bg-gray-900/30 text-gray-400 border border-gray-500/30'
                }`}>
                  {unified.threatClassification.greynoise.toUpperCase()}
                </span>
              </div>
              
              {unified.threatClassification.actor && unified.threatClassification.actor !== 'Unknown' && (
                <div className="flex justify-between items-center">
                  <span className="text-gray-400">Actor</span>
                  <span className="font-bold text-yellow-400">{unified.threatClassification.actor}</span>
                </div>
              )}
              
              {unified.threatClassification.riot && (
                <div className="flex items-center gap-2 text-green-400 text-sm">
                  <CheckCircle className="w-4 h-4" />
                  <span>Known legitimate service (RIOT)</span>
                </div>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  );
};

export default EvidenceTabs;