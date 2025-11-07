import React, { useState, useEffect } from "react";
import axios from "axios";
import { Mail, AlertCircle, CheckCircle2, Loader2, RefreshCw, Copy, Download } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export default function AttackerEmails({ ip, threatData, isOpen, onClose }) {
  const [emailData, setEmailData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(null);

  const fetchEmails = async () => {
    if (!ip) return;

    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(`${API}/attacker-emails`, { ip });
      setEmailData(response.data);
    } catch (err) {
      setError(
        err.response?.data?.detail ||
        err.message ||
        "Failed to fetch attacker emails"
      );
      console.error("Error fetching emails:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && ip && !emailData) {
      fetchEmails();
    }
  }, [isOpen, ip]);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const downloadEmails = () => {
    if (!emailData?.emails) return;

    const emails = emailData.emails.map(e => e.value).join("\n");
    const csvContent = "Email,Confidence,Position,Company\n" +
      emailData.emails
        .map(e => `"${e.value}","${e.confidence}%","${e.position || 'N/A'}","${e.company || 'N/A'}"`)
        .join("\n");

    const element = document.createElement("a");
    element.setAttribute("href", "data:text/csv;charset=utf-8," + encodeURIComponent(csvContent));
    element.setAttribute("download", `attacker-emails-${ip}-${new Date().toISOString().split('T')[0]}.csv`);
    element.style.display = "none";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const getConfidenceBadgeColor = (confidence) => {
    if (confidence >= 85) return "bg-red-500";
    if (confidence >= 70) return "bg-orange-500";
    return "bg-yellow-500";
  };

  const getSourceBadge = (source) => {
    if (source === "PTR_RECORD") return { label: "PTR Record", color: "bg-blue-500" };
    if (source === "PASSIVE_DNS") return { label: "Passive DNS", color: "bg-purple-500" };
    return { label: "Unknown", color: "bg-gray-500" };
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <Card className="w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-gradient-to-br from-gray-900 to-black border-red-500/30">
        {/* Header */}
        <div className="sticky top-0 bg-gradient-to-r from-red-900/20 to-orange-900/20 border-b border-red-500/20 p-6 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <Mail className="w-6 h-6 text-red-500" />
            <div>
              <h2 className="text-2xl font-bold text-white">Attacker Email Discovery</h2>
              <p className="text-gray-400 text-sm">IP: {ip}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white text-2xl"
          >
            ✕
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Loading State */}
          {loading && (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <Loader2 className="w-8 h-8 text-red-500 animate-spin" />
              <p className="text-gray-400">Discovering attacker emails using OSINT chain...</p>
              <div className="text-xs text-gray-500 max-w-md text-center">
                🔍 Step 1: Reverse DNS lookup (PTR) • Step 2: Passive DNS (PDNS) • Step 3: Hunter.io emails
              </div>
            </div>
          )}

          {/* Error State */}
          {error && (
            <Alert className="bg-red-500/10 border-red-500/30">
              <AlertCircle className="w-4 h-4 text-red-500" />
              <AlertDescription className="text-red-400">{error}</AlertDescription>
            </Alert>
          )}

          {/* No Data */}
          {!loading && !emailData && !error && (
            <div className="text-center py-12">
              <p className="text-gray-400">Click "Discover Emails" to start the OSINT chain</p>
              <Button
                onClick={fetchEmails}
                className="mt-4 bg-red-600 hover:bg-red-700 text-white"
              >
                <Mail className="w-4 h-4 mr-2" />
                Discover Emails
              </Button>
            </div>
          )}

          {/* OSINT Chain Status */}
          {emailData && (
            <div className="space-y-4">
              {/* Chain Steps */}
              <div className="bg-black/30 border border-gray-700 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-300 mb-3">🔗 OSINT Chain Steps</h3>
                <div className="space-y-2">
                  {emailData.chain_steps && emailData.chain_steps.length > 0 ? (
                    emailData.chain_steps.map((step, idx) => (
                      <div
                        key={idx}
                        className="text-sm text-gray-400 flex items-center gap-2"
                      >
                        {step.includes("success") || step.includes("complete") ? (
                          <CheckCircle2 className="w-4 h-4 text-green-500" />
                        ) : step.includes("failed") ? (
                          <AlertCircle className="w-4 h-4 text-red-500" />
                        ) : (
                          <div className="w-4 h-4 rounded-full bg-blue-500/30" />
                        )}
                        <span className="capitalize">{step.replace(/_/g, " ")}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-gray-500">No chain data available</p>
                  )}
                </div>
              </div>

              {/* Domain Source & Confidence */}
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-black/30 border border-gray-700 rounded-lg p-4">
                  <div className="text-xs text-gray-500 uppercase tracking-wider">Domain Source</div>
                  <div className="mt-2">
                    <Badge className={getSourceBadge(emailData.domain_source).color + " text-white"}>
                      {getSourceBadge(emailData.domain_source).label}
                    </Badge>
                  </div>
                </div>

                <div className="bg-black/30 border border-gray-700 rounded-lg p-4">
                  <div className="text-xs text-gray-500 uppercase tracking-wider">Confidence</div>
                  <div className="mt-2 text-2xl font-bold text-white">{emailData.confidence}%</div>
                </div>

                <div className="bg-black/30 border border-gray-700 rounded-lg p-4">
                  <div className="text-xs text-gray-500 uppercase tracking-wider">Emails Found</div>
                  <div className="mt-2 text-2xl font-bold text-white">{emailData.emails.length}</div>
                </div>
              </div>

              {/* Domains Checked */}
              {emailData.domains_checked && emailData.domains_checked.length > 0 && (
                <div className="bg-black/30 border border-gray-700 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-gray-300 mb-3">🌐 Domains Checked</h3>
                  <div className="flex flex-wrap gap-2">
                    {emailData.domains_checked.map((domain, idx) => (
                      <Badge
                        key={idx}
                        className="bg-blue-500/20 text-blue-400 border border-blue-500/30 text-xs"
                      >
                        {domain}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* High Confidence Emails */}
              {emailData.high_confidence_emails && emailData.high_confidence_emails.length > 0 && (
                <div className="bg-black/30 border border-red-500/30 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-red-400 mb-3">
                    ⚠️ High Confidence Emails ({emailData.high_confidence_emails.length})
                  </h3>
                  <div className="space-y-2">
                    {emailData.high_confidence_emails.map((email, idx) => (
                      <div
                        key={idx}
                        className="bg-red-500/10 border border-red-500/20 rounded p-3 flex justify-between items-center group hover:bg-red-500/15 transition"
                      >
                        <div>
                          <div className="font-mono text-sm text-red-300">{email.value}</div>
                          <div className="text-xs text-gray-400 mt-1">
                            {email.first_name} {email.last_name} • {email.position}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getConfidenceBadgeColor(email.confidence) + " text-white text-xs"}>
                            {email.confidence}%
                          </Badge>
                          <button
                            onClick={() => copyToClipboard(email.value, `email-${idx}`)}
                            className="p-2 hover:bg-red-500/20 rounded opacity-0 group-hover:opacity-100 transition"
                            title="Copy email"
                          >
                            {copied === `email-${idx}` ? (
                              <CheckCircle2 className="w-4 h-4 text-green-500" />
                            ) : (
                              <Copy className="w-4 h-4 text-red-400" />
                            )}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* All Discovered Emails */}
              {emailData.emails && emailData.emails.length > 0 && (
                <div className="bg-black/30 border border-gray-700 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-gray-300 mb-3">
                    📧 All Discovered Emails ({emailData.emails.length})
                  </h3>
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {emailData.emails.map((email, idx) => (
                      <div
                        key={idx}
                        className="bg-gray-900/50 border border-gray-700 rounded p-3 flex justify-between items-center group hover:bg-gray-800 transition"
                      >
                        <div className="flex-1">
                          <div className="font-mono text-sm text-gray-300">{email.value}</div>
                          <div className="text-xs text-gray-500 mt-1">
                            {email.first_name} {email.last_name} • {email.position || "Unknown Position"}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge className={getConfidenceBadgeColor(email.confidence) + " text-white text-xs"}>
                            {email.confidence}%
                          </Badge>
                          <button
                            onClick={() => copyToClipboard(email.value, `email-${idx}`)}
                            className="p-2 hover:bg-gray-700 rounded opacity-0 group-hover:opacity-100 transition"
                            title="Copy email"
                          >
                            {copied === `email-${idx}` ? (
                              <CheckCircle2 className="w-4 h-4 text-green-500" />
                            ) : (
                              <Copy className="w-4 h-4 text-gray-400" />
                            )}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* No Emails Found */}
              {(!emailData.emails || emailData.emails.length === 0) && emailData.domain_source && (
                <Alert className="bg-yellow-500/10 border-yellow-500/30">
                  <AlertCircle className="w-4 h-4 text-yellow-600" />
                  <AlertDescription className="text-yellow-600">
                    Domain found ({emailData.domain_source}) but no email addresses discovered in Hunter.io
                  </AlertDescription>
                </Alert>
              )}
            </div>
          )}

          {/* Error Message */}
          {emailData && emailData.error && (
            <Alert className="bg-yellow-500/10 border-yellow-500/30">
              <AlertCircle className="w-4 h-4 text-yellow-600" />
              <AlertDescription className="text-yellow-600">{emailData.error}</AlertDescription>
            </Alert>
          )}
        </div>

        {/* Footer */}
        {emailData && (
          <div className="sticky bottom-0 bg-gray-900 border-t border-gray-700 p-4 flex justify-between items-center">
            <div className="text-xs text-gray-500">
              Last updated: {new Date(emailData.timestamp).toLocaleString()}
            </div>
            <div className="flex gap-2">
              {emailData.emails && emailData.emails.length > 0 && (
                <Button
                  onClick={downloadEmails}
                  className="bg-green-600 hover:bg-green-700 text-white text-sm"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export CSV
                </Button>
              )}
              <Button
                onClick={fetchEmails}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 text-white text-sm"
              >
                <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
                Refresh
              </Button>
              <Button
                onClick={onClose}
                className="bg-gray-700 hover:bg-gray-600 text-white text-sm"
              >
                Close
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
