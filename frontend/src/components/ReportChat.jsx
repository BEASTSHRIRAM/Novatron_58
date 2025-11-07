import React, { useState, useRef, useEffect } from 'react';
import { MessageCircle, Send, X, Sparkles, Loader, Volume2 } from 'lucide-react';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const ReportChat = ({ threatData, report, isOpen, onClose }) => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: 'bot',
      text: '🤖 Hi! I\'m your threat intelligence assistant. Ask me anything about this IP analysis, the risk score, threat categories, or the report findings. I can explain technical terms, help you understand the evidence, and suggest next steps.',
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const messagesEndRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const scrollToBottom = () => {
    if (autoScroll && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, autoScroll]);

  const handleSendMessage = async () => {
    if (!input.trim()) return;

    // Add user message
    const userMessage = {
      id: messages.length + 1,
      type: 'user',
      text: input,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(`${API}/chat-about-report`, {
        question: input,
        threat_data: {
          ip: threatData.ip,
          risk: threatData.risk,
          context: threatData.context,
          categories: threatData.categories,
          related: threatData.related,
          evidence: threatData.evidence
        },
        report: report,
        conversation_history: messages.map(m => ({
          type: m.type,
          text: m.text
        }))
      });

      const botMessage = {
        id: messages.length + 2,
        type: 'bot',
        text: response.data.answer,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, botMessage]);
    } catch (err) {
      console.error('Error sending message:', err);
      const errorMessage = {
        id: messages.length + 2,
        type: 'bot',
        text: '❌ Sorry, I encountered an error while processing your question. Please try again.',
        isError: true,
        timestamp: new Date()
      };
      setMessages(prev => [...prev, errorMessage]);
      setError(err.response?.data?.detail || 'Failed to get response');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        id: 1,
        type: 'bot',
        text: '🤖 Hi! I\'m your threat intelligence assistant. Ask me anything about this IP analysis, the risk score, threat categories, or the report findings. I can explain technical terms, help you understand the evidence, and suggest next steps.',
        timestamp: new Date()
      }
    ]);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="bg-gradient-to-b from-slate-900 to-slate-950 rounded-2xl shadow-2xl flex flex-col h-[80vh] w-[90%] max-w-2xl border border-purple-500/30">
        
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-purple-500/20">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <MessageCircle className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                Report Assistant
              </h2>
              <p className="text-xs text-gray-400">Ask about this threat analysis</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-red-500/20 rounded-lg transition-colors text-red-400"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Messages Container */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-purple-500/30 scrollbar-track-transparent"
          onScroll={(e) => {
            const scrollTop = e.target.scrollTop;
            const scrollHeight = e.target.scrollHeight;
            const clientHeight = e.target.clientHeight;
            setAutoScroll(scrollHeight - (scrollTop + clientHeight) < 100);
          }}
        >
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'} animate-in fade-in slide-in-from-bottom-2`}
            >
              <div
                className={`max-w-xs lg:max-w-md px-4 py-3 rounded-xl ${
                  message.type === 'user'
                    ? 'bg-gradient-to-r from-purple-600 to-purple-500 text-white rounded-br-none'
                    : message.isError
                    ? 'bg-red-500/20 border border-red-500/30 text-red-300 rounded-bl-none'
                    : 'bg-slate-800/50 border border-purple-500/20 text-gray-200 rounded-bl-none'
                }`}
              >
                <p className="text-sm leading-relaxed whitespace-pre-wrap break-words" style={{ fontFamily: 'Inter, sans-serif' }}>
                  {message.text}
                </p>
                <p className={`text-xs mt-1 ${
                  message.type === 'user' 
                    ? 'text-purple-200/60'
                    : 'text-gray-400'
                }`}>
                  {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </p>
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-slate-800/50 border border-purple-500/20 px-4 py-3 rounded-xl rounded-bl-none flex items-center gap-2">
                <Loader className="w-4 h-4 animate-spin text-purple-400" />
                <span className="text-sm text-gray-300">Analyzing...</span>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="border-t border-purple-500/20 p-4 bg-slate-900/50 rounded-b-2xl">
          {error && (
            <div className="mb-3 p-2 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-xs">
              {error}
            </div>
          )}
          
          <div className="flex gap-3 mb-3">
            <button
              onClick={clearChat}
              className="text-xs px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-gray-300 transition-colors"
            >
              Clear
            </button>
            <div className="flex-1 text-xs text-gray-500 flex items-center gap-2">
              <span>💡 Try asking:</span>
              <div className="flex gap-2 flex-wrap">
                <button onClick={() => setInput("What does this risk score mean?")} className="hover:text-purple-400 underline">
                  "Risk score"
                </button>
                <span>•</span>
                <button onClick={() => setInput("What is CVE?")} className="hover:text-purple-400 underline">
                  "CVEs"
                </button>
                <span>•</span>
                <button onClick={() => setInput("What should I do?")} className="hover:text-purple-400 underline">
                  "Action plan"
                </button>
              </div>
            </div>
          </div>

          <div className="flex gap-2">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Ask anything about this threat analysis... (Shift+Enter for new line)"
              className="flex-1 bg-slate-800/50 border border-purple-500/30 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-purple-500/60 focus:ring-2 focus:ring-purple-500/20 resize-none"
              rows="3"
              style={{ fontFamily: 'Inter, sans-serif' }}
              disabled={loading}
            />
            <button
              onClick={handleSendMessage}
              disabled={loading || !input.trim()}
              className="px-4 py-3 bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 rounded-lg text-white font-semibold transition-all flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:from-purple-600 disabled:hover:to-purple-500"
              style={{ fontFamily: 'Space Grotesk, sans-serif' }}
            >
              {loading ? (
                <Loader className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportChat;
