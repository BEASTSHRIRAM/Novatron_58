import React from 'react';
import { MapPin, Building2, Network, Globe, Tag } from 'lucide-react';

const ThreatCard = ({ threatData }) => {
  const { context, categories } = threatData;

  const getCategoryColor = (category) => {
    if (category.includes('Malicious') || category.includes('Vulnerabilities')) {
      return { bg: 'rgba(239, 68, 68, 0.2)', border: 'rgba(239, 68, 68, 0.4)', text: '#ef4444' };
    }
    if (category.includes('High') || category.includes('SSH') || category.includes('Abuse')) {
      return { bg: 'rgba(251, 146, 60, 0.2)', border: 'rgba(251, 146, 60, 0.4)', text: '#fb923c' };
    }
    return { bg: 'rgba(0, 255, 65, 0.2)', border: 'rgba(0, 255, 65, 0.3)', text: '#00ff41' };
  };

  return (
    <div data-testid="threat-card" className="glass p-6 rounded-2xl">
      <h3 className="text-xl font-bold mb-6" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#a855f7' }}>
        Threat Profile
      </h3>

      <div className="space-y-4">
        {/* Location */}
        <div className="flex items-start gap-3">
          <MapPin className="w-5 h-5 text-green-400 mt-1" />
          <div>
            <p className="text-sm text-gray-400">Location</p>
            <p className="text-white font-medium">
              {context.city}, {context.country}
              {context.region && ` (${context.region})`}
            </p>
          </div>
        </div>

        {/* Organization */}
        <div className="flex items-start gap-3">
          <Building2 className="w-5 h-5 text-green-400 mt-1" />
          <div>
            <p className="text-sm text-gray-400">Organization</p>
            <p className="text-white font-medium">{context.org || 'Unknown'}</p>
          </div>
        </div>

        {/* ASN */}
        <div className="flex items-start gap-3">
          <Network className="w-5 h-5 text-green-400 mt-1" />
          <div>
            <p className="text-sm text-gray-400">ASN</p>
            <p className="text-white font-medium">{context.asn || 'Unknown'}</p>
          </div>
        </div>

        {/* Hostname */}
        {context.hostname && (
          <div className="flex items-start gap-3">
            <Globe className="w-5 h-5 text-green-400 mt-1" />
            <div>
              <p className="text-sm text-gray-400">Hostname</p>
              <p className="text-white font-medium break-all">{context.hostname}</p>
            </div>
          </div>
        )}

        {/* Categories */}
        <div className="pt-4 border-t border-gray-700">
          <div className="flex items-center gap-2 mb-3">
            <Tag className="w-5 h-5 text-purple-400" />
            <p className="text-sm text-gray-400 font-medium">Threat Categories</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {categories.map((cat, idx) => {
              const colors = getCategoryColor(cat);
              return (
                <span
                  key={idx}
                  data-testid={`category-badge-${idx}`}
                  className="px-3 py-1 rounded-full text-xs font-semibold"
                  style={{
                    background: colors.bg,
                    border: `1px solid ${colors.border}`,
                    color: colors.text
                  }}
                >
                  {cat}
                </span>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatCard;