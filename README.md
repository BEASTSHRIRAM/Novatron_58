# TICE - Threat Intelligence Correlation Engine

> **Advanced IP Analysis & Threat Attribution Platform**

TICE is a full-stack cybersecurity threat intelligence platform that correlates data from multiple OSINT sources to provide comprehensive IP address analysis, risk scoring, and AI-powered threat attribution reports.

![TICE Dashboard](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![React](https://img.shields.io/badge/React-19-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green)

## 🚀 Features

### Core Capabilities
- ✅ **Multi-Source OSINT Integration**: AbuseIPDB, Shodan, IPInfo
- ✅ **Risk Scoring Engine**: Intelligent 0-100 risk calculation with rationale
- ✅ **Threat Correlation**: Unified threat profile from multiple sources
- ✅ **AI Attribution Reports**: Comprehensive threat analysis with recommendations
- ✅ **3D Geolocation Visualization**: Interactive Three.js globe with IP location markers
- ✅ **Professional SOC Dashboard**: Dark cyber-themed UI with glassmorphism design
- ✅ **Evidence Analysis**: Tabbed view of all OSINT data sources
- ✅ **Export Capabilities**: Download threat reports in markdown format

### Architecture Highlights
- **Backend**: FastAPI with async/await for high-performance API handling
- **Frontend**: React 19 with Three.js, Tailwind CSS, and Shadcn UI components
- **Database**: MongoDB for storing analysis history
- **Design**: Cybersecurity SOC theme with neon green/purple accents

## 📁 Project Structure

```
tice/
├── backend/
│   ├── server.py              # Main FastAPI application
│   ├── core/
│   │   ├── correlate.py       # Multi-source data correlation engine
│   │   ├── risk.py            # Risk scoring algorithms
│   │   └── report.py          # AI report generation
│   ├── sources/
│   │   ├── abuseipdb.py       # AbuseIPDB API integration
│   │   ├── shodan_api.py      # Shodan API integration
│   │   └── ipinfo_api.py      # IPInfo API integration
│   ├── models/                # Placeholder for future ML models
│   ├── requirements.txt       # Python dependencies
│   └── .env                   # API keys and configuration
│
├── frontend/
│   ├── src/
│   │   ├── App.js            # Main React app
│   │   ├── pages/
│   │   │   └── Dashboard.jsx  # Main dashboard page
│   │   └── components/
│   │       ├── ThreatScoreGauge.jsx    # Risk score visualization
│   │       ├── ThreatCard.jsx          # Threat profile card
│   │       ├── Map3D.jsx               # Three.js globe
│   │       ├── EvidenceTabs.jsx        # OSINT data tabs
│   │       ├── AiReportPanel.jsx       # AI report display
│   │       └── JsonDrawer.jsx          # Raw JSON viewer
│   └── package.json
│
└── README.md
```

## 🔧 Installation & Setup

### Prerequisites
- Node.js 20+ / Python 3.11+
- MongoDB
- Optional: API keys for AbuseIPDB, Shodan, IPInfo

### Backend Setup

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env and add your API keys (optional for demo mode)

# Run the server
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
yarn install

# Run the development server
yarn start
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8001
- API Docs: http://localhost:8001/docs

## 🔑 API Keys Configuration

Edit `/app/backend/.env` and add your API keys:

```env
# OSINT API Keys (optional - works in mock mode without keys)
ABUSEIPDB_API_KEY=""
SHODAN_API_KEY=""
IPINFO_API_KEY=""

# AI API Key (optional - for enhanced threat reports)
GEMINI_API_KEY=""
```

**Note**: The system works in demo/mock mode without API keys, using realistic sample data.

## 📊 API Endpoints

### Health Check
```
GET /api/health
```

### Analyze IP Address
```
POST /api/analyze
Content-Type: application/json

{
  "ip": "1.2.3.4"
}
```

**Response**: Complete threat intelligence profile including:
- Risk score (0-100) with label and confidence
- Context (location, organization, ASN)
- Threat categories
- Related artifacts
- Evidence from all sources
- AI-generated threat report
- Timestamp

## 🎨 Design System

### Color Palette
- **Primary Background**: Dark gradient (#0a0a0f → #1a0f2e)
- **Accent Green**: Neon green (#00ff41) for success/safe indicators
- **Accent Purple**: #a855f7 for important highlights
- **Danger**: #ef4444 for critical threats
- **Warning**: #f97316 for medium threats

### Typography
- **Headers**: Space Grotesk (cybersecurity tech aesthetic)
- **Body**: Inter (clean readability)

### UI Components
- **Glassmorphism cards** with backdrop blur
- **Neon glow effects** on interactive elements
- **Smooth animations** for state transitions
- **Responsive grid layout** for all screen sizes

## 🧪 Testing

### Test Backend API
```bash
curl -X POST http://localhost:8001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"ip":"8.8.8.8"}'
```

### Test Frontend
1. Open http://localhost:3000
2. Enter an IP address (e.g., 8.8.8.8)
3. Click "Analyze Threat"
4. Verify all components render:
   - Risk Score Gauge
   - Threat Profile Card
   - 3D Globe with location marker
   - Evidence Tabs (AbuseIPDB, Shodan, IPInfo)
   - AI Threat Report
   - JSON Drawer

## 🔮 Future Enhancements

### Planned Features
- [ ] **ML Anomaly Detection**: Internal signals from ML models
- [ ] **LangChain AI Agent**: Enhanced attribution with WatsonX/OpenAI integration
- [ ] **Bulk IP Scanning**: Analyze multiple IPs in batch
- [ ] **Historical Analysis**: Trend analysis and time-series data
- [ ] **Automated Alerting**: Email/Slack notifications for critical threats
- [ ] **PDF Report Export**: Professional report generation
- [ ] **Real-time Monitoring**: WebSocket-based live updates
- [ ] **User Authentication**: Multi-tenant support

### Integration Points
- `/app/backend/models/`: Add ML model files
- `/app/backend/core/report.py`: Integrate Gemini 2.5 Pro for AI reports
- Database queries for historical analysis

## 🏆 Hackathon Ready

This project is specifically designed for cybersecurity hackathons:

✅ **Professional Architecture**: Clean separation of concerns, modular design  
✅ **Impressive Visuals**: 3D globe, animated UI, SOC dashboard aesthetic  
✅ **Real-world Application**: Solves actual threat intelligence problems  
✅ **Scalable Foundation**: Easy to add ML models, new data sources, AI agents  
✅ **Demo-ready**: Works with mock data, no API keys required  
✅ **Well-documented**: Clear code structure, comments, README  

## 📝 License

MIT License - feel free to use for hackathons, educational purposes, or commercial projects.

## 🤝 Contributing

Contributions welcome! Please open issues or submit pull requests.

---

**Built with ❤️ for the cybersecurity community**

*TICE - Threat Intelligence Correlation Engine*
