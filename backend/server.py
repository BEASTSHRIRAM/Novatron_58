from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, validator
from datetime import datetime, timezone
import ipaddress
from typing import Dict, List, Any, Optional

# Import our custom modules
from core.correlate import correlate_threat_data
from core.risk import calculate_risk_score
from core.report import generate_threat_report
from sources.abuseipdb import get_abuseipdb_data
from sources.shodan_api import get_shodan_data
from sources.ipinfo_api import get_ipinfo_data

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="TICE - Threat Intelligence Correlation Engine")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Pydantic Models
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


# Routes
@api_router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "TICE"}


@api_router.post("/analyze", response_model=IPAnalysisResponse)
async def analyze_ip(request: IPAnalysisRequest):
    """
    Analyze an IP address using multiple OSINT sources
    """
    try:
        ip = request.ip
        logger.info(f"Analyzing IP: {ip}")
        
        # Fetch data from all OSINT sources in parallel
        abuseipdb_data = await get_abuseipdb_data(ip)
        shodan_data = await get_shodan_data(ip)
        ipinfo_data = await get_ipinfo_data(ip)
        
        # Correlate all threat data
        correlated = correlate_threat_data(
            ip=ip,
            abuseipdb=abuseipdb_data,
            shodan=shodan_data,
            ipinfo=ipinfo_data
        )
        
        # Calculate risk score
        risk = calculate_risk_score(
            abuseipdb=abuseipdb_data,
            shodan=shodan_data,
            ipinfo=ipinfo_data
        )
        
        # Generate AI threat report (placeholder)
        ai_report = generate_threat_report(
            ip=ip,
            correlated=correlated,
            risk=risk
        )
        
        # Build response
        response = {
            "ip": ip,
            "risk": risk,
            "context": correlated["context"],
            "categories": correlated["categories"],
            "related": correlated["related"],
            "evidence": correlated["evidence"],
            "ai_report": ai_report,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Store in database for history
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


# Include the router in the main app
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