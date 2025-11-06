import React, { useState } from 'react';
import { Code, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';

const JsonDrawer = ({ data }) => {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div data-testid="json-drawer" className="glass p-6 rounded-2xl">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-bold flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#00ff41' }}>
          <Code className="w-6 h-6" />
          Raw JSON Response
        </h3>
        <div className="flex gap-2">
          <button
            data-testid="copy-json-button"
            onClick={handleCopy}
            className="px-4 py-2 rounded-lg bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30 transition-all flex items-center gap-2"
            style={{ fontFamily: 'Space Grotesk, sans-serif' }}
          >
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button
            data-testid="toggle-json-button"
            onClick={() => setExpanded(!expanded)}
            className="px-4 py-2 rounded-lg bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30 transition-all"
          >
            {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 p-4 bg-black/50 rounded-lg overflow-auto max-h-96">
          <pre className="text-sm text-gray-300" style={{ fontFamily: 'monospace' }}>
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export default JsonDrawer;