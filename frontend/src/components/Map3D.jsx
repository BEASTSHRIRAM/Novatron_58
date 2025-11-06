import React, { useRef, useEffect } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Sphere } from '@react-three/drei';
import * as THREE from 'three';

function Globe({ location }) {
  const globeRef = useRef();

  useFrame(() => {
    if (globeRef.current) {
      globeRef.current.rotation.y += 0.001;
    }
  });

  // Parse location coordinates
  const [lat, lng] = location ? location.split(',').map(parseFloat) : [37.7749, -122.4194];

  // Convert lat/lng to 3D coordinates
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lng + 180) * (Math.PI / 180);
  const radius = 2.1;

  const markerX = -(radius * Math.sin(phi) * Math.cos(theta));
  const markerY = radius * Math.cos(phi);
  const markerZ = radius * Math.sin(phi) * Math.sin(theta);

  return (
    <group ref={globeRef}>
      {/* Globe */}
      <Sphere args={[2, 64, 64]}>
        <meshStandardMaterial
          color="#1a1a2e"
          emissive="#0f0f1e"
          roughness={0.8}
          metalness={0.2}
        />
      </Sphere>

      {/* Grid lines */}
      <Sphere args={[2.01, 32, 32]}>
        <meshBasicMaterial
          color="#00ff41"
          wireframe
          transparent
          opacity={0.15}
        />
      </Sphere>

      {/* Location marker */}
      <mesh position={[markerX, markerY, markerZ]}>
        <sphereGeometry args={[0.08, 16, 16]} />
        <meshBasicMaterial color="#ef4444" />
      </mesh>

      {/* Marker glow */}
      <mesh position={[markerX, markerY, markerZ]}>
        <sphereGeometry args={[0.15, 16, 16]} />
        <meshBasicMaterial color="#ef4444" transparent opacity={0.3} />
      </mesh>
    </group>
  );
}

const Map3D = ({ location, country }) => {
  return (
    <div data-testid="map-3d" className="glass p-6 rounded-2xl h-full">
      <h3 className="text-xl font-bold mb-4" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ff41' }}>
        Geolocation
      </h3>
      
      <div className="relative" style={{ height: '300px' }}>
        <Canvas camera={{ position: [0, 0, 5], fov: 50 }}>
          <ambientLight intensity={0.5} />
          <pointLight position={[10, 10, 10]} intensity={1} />
          <Globe location={location} />
          <OrbitControls
            enableZoom={true}
            enablePan={false}
            minDistance={3}
            maxDistance={8}
            autoRotate
            autoRotateSpeed={0.5}
          />
        </Canvas>
      </div>

      <div className="mt-4 text-center">
        <p className="text-sm text-gray-400">Target Location</p>
        <p className="text-lg font-semibold text-white mt-1" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
          {country || 'Unknown'}
        </p>
      </div>
    </div>
  );
};

export default Map3D;