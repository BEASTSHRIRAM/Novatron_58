from dotenv import load_dotenv
from pathlib import Path

# Load environment variables FIRST, before any other imports
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pydantic import BaseModel, validator
from datetime import datetime, timezone
import ipaddress
from typing import Dict, List, Any, Optional

from core.correlate import correlate_threat_data
from core.risk import calculate_risk_score
from core.report import generate_threat_report
from core.timeline import generate_event_timeline
from sources.abuseipdb import get_abuseipdb_data
from sources.otx_api import get_otx_data
from sources.ipinfo_api import get_ipinfo_data
from sources.greynoise_api import get_greynoise_data
from sources.shodan_api import get_shodan_data
from sources.censys_api import get_censys_data
from sources.passive_dns_api import get_passive_dns_data
from sources.dns_checker import get_dns_data
from sources.hunter_api import get_attacker_emails

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(
    mongo_url,
    serverSelectionTimeoutMS=5000,  # 5 second timeout
    connectTimeoutMS=5000,
    socketTimeoutMS=5000
)
db = client[os.environ['DB_NAME']]

app = FastAPI(title="TICE - Threat Intelligence Correlation Engine")
api_router = APIRouter(prefix="/api")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IPAnalysisRequest(BaseModel):
    ip: str
    
    @validator('ip')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')


class IPAnalysisResponse(BaseModel):
    ip: str
    risk: Dict[str, Any]
    context: Dict[str, Any]
    categories: List[str]
    related: Dict[str, List[str]]
    evidence: Dict[str, Any]
    ai_report: str
    timestamp: str


@api_router.get("/health")
async def health_check():
    return {"status": "ok", "service": "TICE"}


@api_router.get("/history/{ip}")
async def get_ip_history(ip: str):
    """
    Get analysis history for a specific IP address
    Returns all past analyses sorted by timestamp (newest first)
    """
    try:
        # Validate IP format
        ipaddress.ip_address(ip)
        
        # Fetch all analyses for this IP, sorted by newest first
        cursor = db.analyses.find(
            {"ip": ip},
            {"_id": 0}  # Exclude MongoDB _id field
        ).sort("timestamp", -1).limit(50)  # Limit to last 50 analyses
        
        history = await cursor.to_list(length=50)
        
        return {
            "ip": ip,
            "total_analyses": len(history),
            "history": history
        }
        
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    except Exception as e:
        logger.error(f"Error fetching history for IP {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch history: {str(e)}")


@api_router.post("/analyze", response_model=IPAnalysisResponse)
async def analyze_ip(request: IPAnalysisRequest):
    try:
        ip = request.ip
        logger.info(f"Analyzing IP: {ip} - Fetching fresh data (caching disabled)")
        
        # Fetch data from ACTIVE sources only (disabled: greynoise, shodan, censys, passive_dns for speed)
        import asyncio
        abuseipdb_data, otx_data, ipinfo_data = await asyncio.gather(
            get_abuseipdb_data(ip),
            get_otx_data(ip),
            get_ipinfo_data(ip),
            return_exceptions=True
        )
        
        # Handle exceptions from parallel execution
        def safe_data(data, source_name):
            if isinstance(data, Exception):
                logger.error(f"{source_name} failed: {str(data)}")
                return {"data": {}, "error": str(data)}
            return data
        
        abuseipdb_data = safe_data(abuseipdb_data, "AbuseIPDB")
        otx_data = safe_data(otx_data, "OTX")
        ipinfo_data = safe_data(ipinfo_data, "IPInfo")
        
        # Use empty data for disabled sources (for speed)
        greynoise_data = {"data": {}, "source": "disabled"}
        shodan_data = {"data": {}, "source": "disabled"}
        censys_data = {"data": {}, "source": "disabled"}
        passive_dns_data = {"data": {}, "source": "disabled"}
        
        correlated = correlate_threat_data(
            ip=ip,
            abuseipdb=abuseipdb_data,
            otx=otx_data,
            ipinfo=ipinfo_data,
            greynoise=greynoise_data,
            shodan=shodan_data,
            censys=censys_data,
            passive_dns=passive_dns_data
        )
        
        risk = calculate_risk_score(
            abuseipdb=abuseipdb_data,
            otx=otx_data,
            ipinfo=ipinfo_data,
            greynoise=greynoise_data,
            shodan=shodan_data,
            censys=censys_data,
            passive_dns=passive_dns_data
        )
        
        # Calculate OTX Reputation Score (0-10) from aggregated risk score
        # Map risk score (0-100) to reputation rating (0-10) where 0=good, 10=very bad
        otx_reputation_rating = min(10, int(risk["score"] / 10))
        
        # Add reputation rating to evidence (override any previous calculation)
        if "otx" in correlated["evidence"]:
            correlated["evidence"]["otx"]["reputation_score"] = otx_reputation_rating
        
        # Do NOT generate an AI report during analyze — keep analyze fast and non-blocking.
        # AI report generation is handled by the /generate-report endpoint on demand.
        ai_report = ""
        
        # Generate event timeline
        timeline = generate_event_timeline(
            abuseipdb=abuseipdb_data,
            otx=otx_data,
            greynoise=greynoise_data,
            shodan=shodan_data,
            passive_dns=passive_dns_data
        )
        
        response = {
            "ip": ip,
            "risk": risk,
            "context": correlated["context"],
            "categories": correlated["categories"],
            "related": correlated["related"],
            "evidence": correlated["evidence"],
            "ai_report": ai_report,
            "timeline": timeline,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        await db.analyses.insert_one({
            **response,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        return response
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error analyzing IP {request.ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@api_router.post("/dns-check")
async def dns_check(request: IPAnalysisRequest):
    """Check DNS and domain information for an IP address"""
    try:
        ip = request.ip
        logger.info(f"Checking DNS info for IP: {ip}")
        
        dns_data = await get_dns_data(ip)
        
        return {
            "ip": ip,
            "dns_data": dns_data,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error checking DNS for IP {request.ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"DNS check failed: {str(e)}")


class GenerateReportRequest(BaseModel):
    ip: str
    correlated: Dict[str, Any]
    risk: Dict[str, Any]


@api_router.post("/generate-report")
async def generate_report(request: GenerateReportRequest):
    """Generate AI threat report using Gemini API"""
    try:
        ip = request.ip
        logger.info(f"Generating AI report for IP: {ip}")
        
        # Generate the threat report using Gemini
        ai_report = generate_threat_report(
            ip=ip,
            correlated=request.correlated,
            risk=request.risk
        )
        
        return {
            "ip": ip,
            "report": ai_report,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating report for IP {request.ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


class ChatRequest(BaseModel):
    question: str
    threat_data: Dict[str, Any]
    report: str
    conversation_history: Optional[List[Dict[str, str]]] = None


@api_router.post("/chat-about-report")
async def chat_about_report(request: ChatRequest):
    """Chat interface to ask questions about the threat report"""
    try:
        from groq import Groq
        import os
        
        GROQ_API_KEY = os.getenv("GROQ_API_KEY")
        if not GROQ_API_KEY:
            # Fallback response if no AI available
            return {
                "answer": "I'm currently offline. Here's what I know about your question:\n\n"
                         "🔍 **Analysis Context:**\n"
                         f"• IP: {request.threat_data.get('ip', 'N/A')}\n"
                         f"• Risk Score: {request.threat_data.get('risk', {}).get('score', 'N/A')}/100\n"
                         f"• Threat Categories: {', '.join(request.threat_data.get('categories', []))}\n\n"
                         "Please try again in a moment or check the full report above."
            }
        
        client = Groq(api_key=GROQ_API_KEY)
        
        # Build conversation context
        threat_summary = f"""
## Current Threat Analysis

**IP Address:** {request.threat_data['ip']}
**Risk Score:** {request.threat_data['risk']['score']}/100
**Risk Level:** {request.threat_data['risk']['label']}
**Risk Rationale:** {', '.join(request.threat_data['risk'].get('rationale', []))}

**Threat Categories:** {', '.join(request.threat_data.get('categories', []))}

**Location:** {request.threat_data['context'].get('city', 'Unknown')}, {request.threat_data['context'].get('country', 'Unknown')}
**Organization:** {request.threat_data['context'].get('org', 'Unknown')}
**ASN:** {request.threat_data['context'].get('asn', 'Unknown')}

**Related Indicators:**
- Domains: {', '.join(request.threat_data['related'].get('domains', [])[:5]) if request.threat_data['related'].get('domains') else 'None'}
- CVEs: {', '.join(request.threat_data['related'].get('cves', [])[:5]) if request.threat_data['related'].get('cves') else 'None'}
- Threat Groups: {', '.join(request.threat_data['related'].get('threat_groups', [])[:3]) if request.threat_data['related'].get('threat_groups') else 'None'}

**AI Report:**
{request.report}
"""
        
        # Build conversation history if provided
        conversation_context = ""
        if request.conversation_history and len(request.conversation_history) > 0:
            conversation_context = "**Previous Questions & Answers:**\n"
            for i, msg in enumerate(request.conversation_history[-4:]):  # Last 4 messages for context
                if msg['type'] == 'user':
                    conversation_context += f"\n**Q:** {msg['text']}\n"
                else:
                    conversation_context += f"**A:** {msg['text'][:500]}...\n"  # Truncate for context
        
        # Build the prompt
        prompt = f"""You are a cybersecurity threat intelligence expert and assistant. Your role is to help security analysts 
understand threat reports and IP analysis data. You explain technical concepts clearly, provide actionable insights, 
and help users understand what they should do about the threats.

{threat_summary}

{conversation_context}

**User's Question:** {request.question}

Provide a helpful, clear answer that:
1. Directly answers the user's question
2. Uses plain language but maintains technical accuracy
3. Provides context when helpful (e.g., explain what CVE means, not just list CVE numbers)
4. Suggests actionable next steps if relevant
5. Uses emoji indicators (🔴 for critical, 🟡 for medium, 🟢 for low) when appropriate

Keep your response concise but thorough (2-4 paragraphs max). Use markdown formatting for readability."""

        message = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=1024
        )
        answer = message.choices[0].message.content
        
        return {
            "answer": answer,
            "ip": request.threat_data['ip'],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error in chat endpoint: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to process your question: {str(e)}"
        )


@api_router.post("/attacker-emails")
async def get_attacker_emails_endpoint(request: IPAnalysisRequest):
    """
    Find email addresses associated with an attacker's IP address.
    
    Uses professional OSINT chain:
    1. Reverse DNS lookup (PTR record)
    2. Passive DNS fallback (CIRCL)
    3. Hunter.io email discovery
    
    Returns:
        - emails: List of discovered email addresses with confidence scores
        - domain_source: How the domain was identified (PTR, PDNS, or Not Found)
        - domains_checked: Domains that were queried
        - confidence: Overall confidence score (0-100)
        - chain_steps: Detailed steps taken during discovery
    """
    try:
        ip = request.ip
        logger.info(f"Starting email discovery for attacker IP: {ip}")
        
        # Call the professional OSINT chain
        result = await get_attacker_emails(ip)
        
        # Store result in database
        await db.email_discoveries.insert_one({
            **result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        logger.info(f"Email discovery complete for {ip}: Found {len(result['emails'])} emails")
        
        return result
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error discovering emails for IP {request.ip}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Email discovery failed: {str(e)}"
        )


app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()