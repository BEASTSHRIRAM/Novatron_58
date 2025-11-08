import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Zap, Brain, ArrowRight, Lock, TrendingUp } from 'lucide-react';
import '../styles/LandingPage.css';

export default function LandingPage() {
  const navigate = useNavigate();
  const [hoveredCard, setHoveredCard] = useState(null);

  const handleRoleSelect = (role) => {
    // Store selected role in localStorage for dashboard context
    localStorage.setItem('userRole', role);
    localStorage.setItem('roleSelectedAt', new Date().toISOString());
    navigate('/dashboard');
  };

  return (
    <div className="landing-page">
      {/* Animated Background */}
      <div className="animated-bg">
        <div className="blur-blob blob-1"></div>
        <div className="blur-blob blob-2"></div>
        <div className="blur-blob blob-3"></div>
      </div>

      {/* Header */}
      <header className="landing-header">
        <div className="header-content">
          <div className="logo-section">
            <h1 className="logo-text">PredwinAI</h1>
            <span className="logo-subtitle">Threat Intelligence Correlation Engine</span>
          </div>
          <nav className="header-nav">
            <a href="#features" className="nav-link">Features</a>
            <a href="#about" className="nav-link">About</a>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="landing-main">
        {/* Hero Section */}
        <section className="hero-section">
          <div className="hero-content">
            <h2 className="hero-title">
              Threat Intelligence at Your Fingertips
            </h2>
            <p className="hero-description">
              Analyze, correlate, and investigate IP addresses with OSINT sources in seconds.
              Get actionable insights powered by AI and threat research.
            </p>
          </div>
        </section>

        {/* Role Selection Section */}
        <section className="role-section">
          <h3 className="section-title">Who are you?</h3>
          <p className="section-subtitle">Select your role to get started with TICE</p>

          <div className="role-cards-container">
            {/* Investigator Card */}
            <div
              className={`role-card investigator-card ${hoveredCard === 'investigator' ? 'hovered' : ''}`}
              onMouseEnter={() => setHoveredCard('investigator')}
              onMouseLeave={() => setHoveredCard(null)}
              onClick={() => handleRoleSelect('investigator')}
            >
              <div className="card-background"></div>
              <div className="card-content">
                <div className="card-icon-wrapper">
                  <Brain size={48} className="card-icon" />
                </div>
                <h4 className="card-title">Security Investigator</h4>
                <p className="card-description">
                  Deep dive into suspicious IPs with comprehensive threat analysis
                </p>
                <ul className="card-features">
                  <li>Detailed threat profiles</li>
                  <li>Geolocation mapping</li>
                  <li>Risk scoring & breakdown</li>
                  <li>AI-powered analysis</li>
                </ul>
                <button className="card-button">
                  Start Investigating
                  <ArrowRight size={18} className="button-icon" />
                </button>
              </div>
              <div className="card-border"></div>
            </div>

            {/* SOC Analyst Card */}
            <div
              className={`role-card soc-card ${hoveredCard === 'soc' ? 'hovered' : ''}`}
              onMouseEnter={() => setHoveredCard('soc')}
              onMouseLeave={() => setHoveredCard(null)}
              onClick={() => handleRoleSelect('soc')}
            >
              <div className="card-background"></div>
              <div className="card-content">
                <div className="card-icon-wrapper">
                  <Zap size={48} className="card-icon" />
                </div>
                <h4 className="card-title">SOC Analyst</h4>
                <p className="card-description">
                  Fast incident response with prioritized threat intelligence
                </p>
                <ul className="card-features">
                  <li>Quick risk assessment</li>
                  <li>Threat prioritization</li>
                  <li>Attacker email discovery</li>
                  <li>AI chat assistance</li>
                </ul>
                <button className="card-button">
                  Start Analyzing
                  <ArrowRight size={18} className="button-icon" />
                </button>
              </div>
              <div className="card-border"></div>
            </div>

            {/* Threat Researcher Card */}
            <div
              className={`role-card researcher-card ${hoveredCard === 'researcher' ? 'hovered' : ''}`}
              onMouseEnter={() => setHoveredCard('researcher')}
              onMouseLeave={() => setHoveredCard(null)}
              onClick={() => handleRoleSelect('researcher')}
            >
              <div className="card-background"></div>
              <div className="card-content">
                <div className="card-icon-wrapper">
                  <TrendingUp size={48} className="card-icon" />
                </div>
                <h4 className="card-title">Threat Researcher</h4>
                <p className="card-description">
                  Track malware campaigns and APT attribution
                </p>
                <ul className="card-features">
                  <li>Malware correlation</li>
                  <li>APT attribution</li>
                  <li>Campaign tracking</li>
                  <li>IoC pivoting</li>
                </ul>
                <button className="card-button">
                  Start Researching
                  <ArrowRight size={18} className="button-icon" />
                </button>
              </div>
              <div className="card-border"></div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="features-section" id="features">
          <h3 className="section-title">Powered by OSINT Sources</h3>
          <div className="features-grid">
            <FeatureCard
              icon={<Shield size={32} />}
              title="AbuseIPDB"
              description="Community-verified IP reputation with confidence scores"
            />
            <FeatureCard
              icon={<Lock size={32} />}
              title="OTX (AlienVault)"
              description="Threat group attribution and malware family identification"
            />
            <FeatureCard
              icon={<TrendingUp size={32} />}
              title="IPInfo"
              description="Geolocation and network context"
            />
            <FeatureCard
              icon={<Shield size={32} />}
              title="Passive DNS"
              description="Historical domain associations and flux detection"
            />
            <FeatureCard
              icon={<Brain size={32} />}
              title="Hunter"
              description="Attacker email discovery and OSINT chaining"
            />
          </div>
        </section>

        {/* Stats Section */}
        <section className="stats-section">
          <StatCard number="8" label="OSINT Sources" />
          <StatCard number="<5s" label="Analysis Time" />
          <StatCard number="100+" label="Risk Metrics" />
          <StatCard number="AI" label="Powered Analysis" />
        </section>

        {/* About Section */}
        <section className="about-section" id="about">
          <h3 className="section-title">About TICE</h3>
          <p className="about-text">
            PredwinAI(Threat Intelligence Correlation Engine) is a modern threat intelligence platform
            that correlates data from 8 different OSINT sources to provide comprehensive IP analysis.
            Whether you're investigating suspicious activity, responding to incidents, or researching
            threat campaigns, TICE gives you the actionable intelligence you need in seconds.
          </p>
          <div className="about-highlights">
            <div className="highlight">
              <h4>Security First</h4>
              <p>No API keys stored. All analysis happens in real-time.</p>
            </div>
            <div className="highlight">
              <h4>Lightning Fast</h4>
              <p>Parallel queries across all sources complete in 3-5 seconds.</p>
            </div>
            <div className="highlight">
              <h4>AI Powered</h4>
              <p>Google Gemini integration for human-readable threat reports.</p>
            </div>
            <div className="highlight">
              <h4>Comprehensive</h4>
              <p>40+ different threat signals combined into one risk score.</p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="landing-footer">
        <p>&copy; 2025 PredwinAI- Threat Intelligence Correlation Engine</p>
        <p className="footer-tagline">Built for security professionals, by security professionals</p>
      </footer>
    </div>
  );
}

// Feature Card Component
function FeatureCard({ icon, title, description }) {
  return (
    <div className="feature-card">
      <div className="feature-icon">{icon}</div>
      <h4 className="feature-title">{title}</h4>
      <p className="feature-description">{description}</p>
    </div>
  );
}

// Stat Card Component
function StatCard({ number, label }) {
  return (
    <div className="stat-card">
      <div className="stat-number">{number}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
