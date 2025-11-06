import React, { useState } from 'react';
import { Brain, ChevronDown, ChevronUp, Download, FileText } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import jsPDF from 'jspdf';

const AiReportPanel = ({ report, threatData }) => {
  const [expanded, setExpanded] = useState(true);
  const [exporting, setExporting] = useState(false);

  const handleExportMarkdown = () => {
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPDF = async () => {
    setExporting(true);
    try {
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 15;
      const contentWidth = pageWidth - (margin * 2);
      let yPosition = margin;

      // Helper function to check if we need a new page
      const checkPageBreak = (heightNeeded) => {
        if (yPosition + heightNeeded > pageHeight - margin) {
          pdf.addPage();
          yPosition = margin;
          return true;
        }
        return false;
      };

      // Helper to add text with word wrap
      const addText = (text, fontSize, color = [0, 0, 0], isBold = false, maxWidth = contentWidth) => {
        pdf.setFontSize(fontSize);
        pdf.setFont('helvetica', isBold ? 'bold' : 'normal');
        pdf.setTextColor(...color);
        
        const lines = pdf.splitTextToSize(text, maxWidth);
        const lineHeight = fontSize * 0.4;
        
        lines.forEach((line) => {
          checkPageBreak(lineHeight);
          pdf.text(line, margin, yPosition);
          yPosition += lineHeight;
        });
        
        return yPosition;
      };

      // Header with gradient background simulation
      pdf.setFillColor(240, 240, 245);
      pdf.rect(0, 0, pageWidth, 50, 'F');
      
      pdf.setFillColor(168, 85, 247);
      pdf.rect(0, 48, pageWidth, 2, 'F');

      // TICE Logo/Title
      pdf.setFontSize(32);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(0, 200, 50);
      pdf.text('TICE', margin, 25);
      
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(168, 85, 247);
      pdf.text('Threat Intelligence Correlation Engine', margin, 35);

      // Timestamp
      pdf.setFontSize(9);
      pdf.setTextColor(80, 80, 80);
      const timestamp = new Date(threatData.timestamp).toLocaleString();
      pdf.text(`Generated: ${timestamp}`, margin, 43);

      yPosition = 60;

      // IP Address and Risk Score Section
      checkPageBreak(25);
      pdf.setFillColor(245, 245, 250);
      pdf.roundedRect(margin, yPosition, contentWidth, 22, 3, 3, 'F');
      
      pdf.setFontSize(14);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(0, 150, 40);
      pdf.text('IP ADDRESS ANALYSIS', margin + 5, yPosition + 8);
      
      pdf.setFontSize(16);
      pdf.setTextColor(0, 0, 0);
      pdf.text(threatData.ip, margin + 5, yPosition + 16);

      // Risk Score Badge
      const riskScore = threatData.risk.score;
      const riskColor = riskScore >= 60 ? [239, 68, 68] : riskScore >= 40 ? [245, 158, 11] : [0, 255, 65];
      const riskLabel = riskScore >= 60 ? 'HIGH RISK' : riskScore >= 40 ? 'MEDIUM RISK' : 'LOW RISK';
      
      pdf.setFillColor(...riskColor);
      pdf.roundedRect(pageWidth - margin - 40, yPosition + 5, 38, 12, 2, 2, 'F');
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(255, 255, 255);
      pdf.text(`${riskScore}/100`, pageWidth - margin - 35, yPosition + 12, { align: 'left' });
      
      yPosition += 30;

      // Threat Classification
      checkPageBreak(15);
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(168, 85, 247);
      pdf.text('THREAT CLASSIFICATION', margin, yPosition);
      yPosition += 8;
      
      pdf.setFillColor(250, 250, 252);
      const categoriesHeight = Math.max(15, threatData.categories.length * 6 + 8);
      pdf.roundedRect(margin, yPosition, contentWidth, categoriesHeight, 2, 2, 'F');
      
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(0, 0, 0);
      
      if (threatData.categories.length > 0) {
        threatData.categories.forEach((cat, idx) => {
          pdf.text(`• ${cat}`, margin + 5, yPosition + 7 + (idx * 6));
        });
      } else {
        pdf.text('• No significant threats identified', margin + 5, yPosition + 10);
      }
      
      yPosition += categoriesHeight + 10;

      // Attribution & Context
      checkPageBreak(35);
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(168, 85, 247);
      pdf.text('ATTRIBUTION & CONTEXT', margin, yPosition);
      yPosition += 8;
      
      pdf.setFillColor(250, 250, 252);
      pdf.roundedRect(margin, yPosition, contentWidth, 28, 2, 2, 'F');
      
      pdf.setFontSize(9);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(0, 0, 0);
      
      const context = threatData.context;
      pdf.text(`Location: ${context.city || 'Unknown'}, ${context.country || 'Unknown'}`, margin + 5, yPosition + 7);
      pdf.text(`Organization: ${context.org || 'Unknown'}`, margin + 5, yPosition + 13);
      pdf.text(`ASN: ${context.asn || 'Unknown'}`, margin + 5, yPosition + 19);
      if (context.hostname) {
        pdf.text(`Hostname: ${context.hostname}`, margin + 5, yPosition + 25);
      }
      
      yPosition += 35;

      // Evidence Summary
      checkPageBreak(50);
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(168, 85, 247);
      pdf.text('EVIDENCE SUMMARY', margin, yPosition);
      yPosition += 8;

      const evidence = threatData.evidence;
      
      // AbuseIPDB
      pdf.setFillColor(250, 250, 252);
      pdf.roundedRect(margin, yPosition, contentWidth, 20, 2, 2, 'F');
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(0, 150, 40);
      pdf.text('AbuseIPDB', margin + 5, yPosition + 7);
      
      pdf.setFontSize(9);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(0, 0, 0);
      pdf.text(`Confidence: ${evidence.abuseipdb.confidence_score}% | Reports: ${evidence.abuseipdb.total_reports}`, margin + 5, yPosition + 14);
      
      yPosition += 25;

      // VirusTotal
      checkPageBreak(20);
      pdf.setFillColor(250, 250, 252);
      pdf.roundedRect(margin, yPosition, contentWidth, 20, 2, 2, 'F');
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(0, 150, 40);
      pdf.text('VirusTotal', margin + 5, yPosition + 7);
      
      pdf.setFontSize(9);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(0, 0, 0);
      const vtMal = evidence.virustotal.malicious || 0;
      const vtSus = evidence.virustotal.suspicious || 0;
      pdf.text(`Malicious: ${vtMal} | Suspicious: ${vtSus} | Reputation: ${evidence.virustotal.reputation || 0}`, margin + 5, yPosition + 14);
      
      yPosition += 25;

      // CVEs if present
      if (evidence.virustotal.cves && evidence.virustotal.cves.length > 0) {
        checkPageBreak(20);
        pdf.setFillColor(255, 245, 245);
        const cveHeight = Math.min(20, evidence.virustotal.cves.length * 5 + 12);
        pdf.roundedRect(margin, yPosition, contentWidth, cveHeight, 2, 2, 'F');
        
        pdf.setFontSize(10);
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(239, 68, 68);
        pdf.text('⚠ Known CVEs', margin + 5, yPosition + 7);
        
        pdf.setFontSize(8);
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor(0, 0, 0);
        const cveText = evidence.virustotal.cves.join(', ');
        const cveLines = pdf.splitTextToSize(cveText, contentWidth - 10);
        pdf.text(cveLines, margin + 5, yPosition + 13);
        
        yPosition += cveHeight + 5;
      }

      yPosition += 5;

      // AI Report Section
      checkPageBreak(15);
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(168, 85, 247);
      pdf.text('AI THREAT ANALYSIS', margin, yPosition);
      yPosition += 8;

      // Parse and format the markdown report
      pdf.setFontSize(9);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(0, 0, 0);
      
      const reportLines = report.split('\n');
      reportLines.forEach((line) => {
        if (!line.trim()) {
          yPosition += 3;
          return;
        }
        
        // Headers
        if (line.startsWith('##')) {
          checkPageBreak(10);
          pdf.setFontSize(11);
          pdf.setFont('helvetica', 'bold');
          pdf.setTextColor(0, 150, 40);
          addText(line.replace(/^##\s*/, ''), 11, [0, 150, 40], true);
          yPosition += 2;
        } else if (line.startsWith('###')) {
          checkPageBreak(8);
          pdf.setFontSize(10);
          pdf.setFont('helvetica', 'bold');
          pdf.setTextColor(168, 85, 247);
          addText(line.replace(/^###\s*/, ''), 10, [168, 85, 247], true);
          yPosition += 1;
        } else if (line.startsWith('•') || line.startsWith('-') || line.startsWith('*')) {
          checkPageBreak(6);
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor(0, 0, 0);
          addText(line, 9, [0, 0, 0], false);
        } else if (line.includes('**')) {
          checkPageBreak(6);
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'bold');
          pdf.setTextColor(0, 0, 0);
          addText(line.replace(/\*\*/g, ''), 9, [0, 0, 0], true);
        } else if (line.trim() === '---') {
          checkPageBreak(5);
          pdf.setDrawColor(180, 180, 180);
          pdf.line(margin, yPosition, pageWidth - margin, yPosition);
          yPosition += 5;
        } else {
          checkPageBreak(6);
          pdf.setFontSize(9);
          pdf.setFont('helvetica', 'normal');
          pdf.setTextColor(0, 0, 0);
          addText(line, 9, [0, 0, 0], false);
        }
      });

      // Footer on last page
      pdf.setFontSize(8);
      pdf.setTextColor(100, 100, 100);
      pdf.text('Generated by TICE - Threat Intelligence Correlation Engine', pageWidth / 2, pageHeight - 10, { align: 'center' });

      // Save PDF
      pdf.save(`TICE-Threat-Report-${threatData.ip}-${Date.now()}.pdf`);
      
    } catch (error) {
      console.error('Error generating PDF:', error);
      alert('Failed to generate PDF. Please try again.');
    } finally {
      setExporting(false);
    }
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
            data-testid="export-pdf-button"
            onClick={handleExportPDF}
            disabled={exporting}
            className="px-4 py-2 rounded-lg bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            style={{ fontFamily: 'Space Grotesk, sans-serif' }}
          >
            <FileText className="w-4 h-4" />
            {exporting ? 'Generating...' : 'Export PDF'}
          </button>

          <button
            data-testid="export-markdown-button"
            onClick={handleExportMarkdown}
            className="px-4 py-2 rounded-lg bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30 transition-all flex items-center gap-2"
            style={{ fontFamily: 'Space Grotesk, sans-serif' }}
          >
            <Download className="w-4 h-4" />
            Export MD
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