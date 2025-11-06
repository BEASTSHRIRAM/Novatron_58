import React, { useState } from 'react';
import { Brain, ChevronDown, ChevronUp, Download } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

const AiReportPanel = ({ report }) => {
  const [expanded, setExpanded] = useState(true);

  const handleExport = () => {
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div data-testid="ai-report-panel" className="glass p-6 rounded-2xl">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-bold flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif', color: '#a855f7' }}>
          <Brain className="w-6 h-6" />
          AI Threat Attribution Report
        </h3>
        <div className="flex gap-2">
          <button
            data-testid="export-report-button"
            onClick={handleExport}
            className="px-4 py-2 rounded-lg bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30 transition-all flex items-center gap-2"
            style={{ fontFamily: 'Space Grotesk, sans-serif' }}
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <button
            data-testid="toggle-report-button"
            onClick={() => setExpanded(!expanded)}
            className="px-4 py-2 rounded-lg bg-purple-500/20 text-purple-400 border border-purple-500/30 hover:bg-purple-500/30 transition-all"
          >
            {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="prose prose-invert max-w-none">
          <div
            className="p-6 bg-black/30 rounded-lg text-gray-300 leading-relaxed"
            style={{ fontFamily: 'Inter, sans-serif' }}
          >
            <ReactMarkdown
              components={{
                h2: ({ node, ...props }) => <h2 className="text-2xl font-bold text-green-400 mb-4 mt-6" {...props} />,
                h3: ({ node, ...props }) => <h3 className="text-xl font-semibold text-purple-400 mb-3 mt-4" {...props} />,
                ul: ({ node, ...props }) => <ul className="list-none space-y-2 my-4" {...props} />,
                li: ({ node, ...props }) => <li className="text-gray-300" {...props} />,
                p: ({ node, ...props }) => <p className="mb-3" {...props} />,
                strong: ({ node, ...props }) => <strong className="text-white font-semibold" {...props} />,
                hr: ({ node, ...props }) => <hr className="border-gray-700 my-4" {...props} />
              }}
            >
              {report}
            </ReactMarkdown>
          </div>
        </div>
      )}
    </div>
  );
};

export default AiReportPanel;