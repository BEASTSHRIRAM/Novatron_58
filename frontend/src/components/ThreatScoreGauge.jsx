import React from 'react';
import { CircularProgressbar, buildStyles } from 'react-circular-progressbar';
import 'react-circular-progressbar/dist/styles.css';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

const ThreatScoreGauge = ({ risk }) => {
  const { score, label, confidence } = risk;

  const getColor = () => {
    if (score >= 80) return '#ef4444'; // red
    if (score >= 60) return '#f97316'; // orange
    if (score >= 40) return '#eab308'; // yellow
    if (score >= 20) return '#22c55e'; // green
    return '#00ff41'; // neon green
  };

  const getIcon = () => {
    if (score >= 60) return <AlertTriangle className="w-8 h-8" />;
    return <CheckCircle className="w-8 h-8" />;
  };

  return (
    <div data-testid="threat-score-gauge" className="glass p-6 rounded-2xl">
      <h3 className="text-xl font-bold mb-6 flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ff41' }}>
        <Shield className="w-6 h-6" />
        Risk Score
      </h3>
      
      <div className="flex flex-col items-center">
        <div className="w-48 h-48 mb-6">
          <CircularProgressbar
            value={score}
            text={`${score}`}
            styles={buildStyles({
              textSize: '24px',
              pathColor: getColor(),
              textColor: getColor(),
              trailColor: 'rgba(255, 255, 255, 0.1)',
              pathTransitionDuration: 1.5
            })}
          />
        </div>

        <div className="flex items-center gap-3 mb-4">
          <div style={{ color: getColor() }}>
            {getIcon()}
          </div>
          <span className="text-3xl font-bold" style={{ color: getColor(), fontFamily: 'Space Grotesk, sans-serif' }}>
            {label}
          </span>
        </div>

        <div className="text-center">
          <p className="text-sm text-gray-400 mb-2">Confidence Level</p>
          <span className="px-4 py-2 rounded-full text-sm font-semibold" style={{
            background: confidence === 'High' ? 'rgba(0,255,65,0.2)' : 'rgba(168,85,247,0.2)',
            color: confidence === 'High' ? '#00ff41' : '#a855f7',
            border: `1px solid ${confidence === 'High' ? 'rgba(0,255,65,0.3)' : 'rgba(168,85,247,0.3)'}`
          }}>
            {confidence}
          </span>
        </div>
      </div>
    </div>
  );
};

export default ThreatScoreGauge;