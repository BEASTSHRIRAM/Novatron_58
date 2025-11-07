import React from 'react';
import { AlertTriangle, Users, Target, AlertCircle } from 'lucide-react';

const ThreatGroupsCard = ({ evidence, related }) => {
  const threatGroups = related?.threat_groups || [];
  const otxData = evidence?.otx || {};
  const malwareFamilies = otxData?.malware_families || [];
  const targetIndustries = otxData?.target_industries || [];
  const pulseCount = otxData?.pulse_count || 0;

  if (!threatGroups.length && !malwareFamilies.length && !targetIndustries.length && pulseCount === 0) {
    return null;
  }

  return (
    <div className="bg-black/30 rounded-xl p-5 border border-gray-700/50">
      <div className="flex items-center gap-2 mb-4">
        <AlertTriangle className="w-5 h-5 text-red-400" />
        <h3 className="text-lg font-semibold text-white">Threat Groups & Campaigns</h3>
      </div>

      <div className="space-y-4">
        {/* Threat Groups */}
        {threatGroups.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-4 h-4 text-red-400" />
              <h4 className="text-sm font-semibold text-red-400">Associated Threat Actors</h4>
            </div>
            <div className="space-y-2">
              {threatGroups.map((group, idx) => (
                <div key={idx} className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                  <p className="text-sm text-red-300 font-medium">{group}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Malware Families */}
        {malwareFamilies.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <AlertCircle className="w-4 h-4 text-orange-400" />
              <h4 className="text-sm font-semibold text-orange-400">Associated Malware Families</h4>
            </div>
            <div className="flex flex-wrap gap-2">
              {malwareFamilies.map((family, idx) => (
                <span key={idx} className="px-3 py-1 bg-orange-900/20 border border-orange-500/30 rounded-full text-xs text-orange-300 font-medium">
                  {family}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Target Industries */}
        {targetIndustries.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Target className="w-4 h-4 text-purple-400" />
              <h4 className="text-sm font-semibold text-purple-400">Targeted Industries</h4>
            </div>
            <div className="flex flex-wrap gap-2">
              {targetIndustries.map((industry, idx) => (
                <span key={idx} className="px-3 py-1 bg-purple-900/20 border border-purple-500/30 rounded-full text-xs text-purple-300 font-medium">
                  {industry}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* OTX Pulse Count */}
        {pulseCount > 0 && (
          <div className="bg-blue-900/20 border border-blue-500/30 rounded-lg p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-blue-300">AlienVault OTX Pulses</span>
              <span className="px-3 py-1 bg-blue-500/20 rounded-full text-xs font-bold text-blue-300">
                {pulseCount}
              </span>
            </div>
            <p className="text-xs text-blue-400 mt-2">
              {pulseCount === 1 ? 'This IP is associated with 1 threat intelligence pulse.' : `This IP is associated with ${pulseCount} threat intelligence pulses.`}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatGroupsCard;
