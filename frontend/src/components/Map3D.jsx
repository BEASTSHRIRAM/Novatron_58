import React from 'react';
import { MapPin } from 'lucide-react';

const Map3D = ({ location, country }) => {
  // Parse location coordinates
  const [lat, lng] = location ? location.split(',').map(parseFloat) : [0, 0];
  
  // Construct OpenStreetMap embed URL (free, no API key needed)
  const mapUrl = `https://www.openstreetmap.org/export/embed.html?bbox=${lng-5},${lat-5},${lng+5},${lat+5}&layer=mapnik&marker=${lat},${lng}`;

  return (
    <div data-testid="map-3d" className="glass p-6 rounded-2xl h-full">
      <h3 className="text-xl font-bold mb-4 flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ff41' }}>
        <MapPin className="w-5 h-5" />
        Geolocation
      </h3>
      
      <div className="relative rounded-xl overflow-hidden" style={{ height: '300px', border: '2px solid rgba(0, 255, 65, 0.2)' }}>
        {location ? (
          <iframe
            title="Location Map"
            width="100%"
            height="100%"
            frameBorder="0"
            scrolling="no"
            marginHeight="0"
            marginWidth="0"
            src={mapUrl}
            style={{ border: 0 }}
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center bg-black/40">
            <p className="text-gray-500">Location data unavailable</p>
          </div>
        )}
      </div>

      <div className="mt-4 text-center">
        <p className="text-sm text-gray-400">Target Location</p>
        <p className="text-lg font-semibold text-white mt-1" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
          {country || 'Unknown'}
        </p>
        {location && (
          <p className="text-xs text-gray-500 mt-1">
            {lat.toFixed(4)}°, {lng.toFixed(4)}°
          </p>
        )}
      </div>
    </div>
  );
};

export default Map3D;