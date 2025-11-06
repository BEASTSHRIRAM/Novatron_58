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
from sources.abuseipdb import get_abuseipdb_data
from sources.shodan_api import get_shodan_data
from sources.ipinfo_api import get_ipinfo_data

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
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


@api_router.post("/analyze", response_model=IPAnalysisResponse)
async def analyze_ip(request: IPAnalysisRequest):
    try:
        ip = request.ip
        logger.info(f"Analyzing IP: {ip}")
        
        abuseipdb_data = await get_abuseipdb_data(ip)
        shodan_data = await get_shodan_data(ip)
        ipinfo_data = await get_ipinfo_data(ip)
        
        correlated = correlate_threat_data(
            ip=ip,
            abuseipdb=abuseipdb_data,
            shodan=shodan_data,
            ipinfo=ipinfo_data
        )
        
        risk = calculate_risk_score(
            abuseipdb=abuseipdb_data,
            shodan=shodan_data,
            ipinfo=ipinfo_data
        )
        ai_report = generate_threat_report(
            ip=ip,
            correlated=correlated,
            risk=risk
        )
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