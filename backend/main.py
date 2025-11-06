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
from sources.virustotal_api import get_virustotal_data
from sources.ipinfo_api import get_ipinfo_data
from sources.greynoise_api import get_greynoise_data
from sources.shodan_api import get_shodan_data
from sources.censys_api import get_censys_api
from sources.passive_dns_api import get_passive_dns_data
from sources.dns_checker import get_dns_data

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
        logger.info(f"Analyzing IP: {ip}")
        
        # TEMPORARILY DISABLED CACHING FOR TESTING
        # Check if we have recent analysis (within last 24 hours)
        # cached_analysis = await db.analyses.find_one(
        #     {"ip": ip},
        #     sort=[("timestamp", -1)]
        # )
        
        # if cached_analysis:
        #     # Parse timestamp
        #     from dateutil import parser
        #     cached_time = parser.isoparse(cached_analysis["timestamp"])
        #     time_diff = datetime.now(timezone.utc) - cached_time
            
        #     # If analysis is less than 24 hours old, return cached result
        #     if time_diff.total_seconds() < 86400:  # 24 hours in seconds
        #         logger.info(f"Returning cached analysis for IP: {ip} (age: {time_diff.total_seconds()/3600:.1f} hours)")
        #         # Remove MongoDB _id field
        #         cached_analysis.pop("_id", None)
        #         return cached_analysis
        
        logger.info(f"Fetching fresh data for IP: {ip}")
        
        # Fetch data from all sources in parallel
        import asyncio
        abuseipdb_data, virustotal_data, ipinfo_data, greynoise_data, shodan_data, censys_data, passive_dns_data = await asyncio.gather(
            get_abuseipdb_data(ip),
            get_virustotal_data(ip),
            get_ipinfo_data(ip),
            get_greynoise_data(ip),
            get_shodan_data(ip),
            get_censys_data(ip),
            get_passive_dns_data(ip),
            return_exceptions=True
        )
        
        # Handle exceptions from parallel execution
        def safe_data(data, source_name):
            if isinstance(data, Exception):
                logger.error(f"{source_name} failed: {str(data)}")
                return {"data": {}, "error": str(data)}
            return data
        
        abuseipdb_data = safe_data(abuseipdb_data, "AbuseIPDB")
        virustotal_data = safe_data(virustotal_data, "VirusTotal")
        ipinfo_data = safe_data(ipinfo_data, "IPInfo")
        greynoise_data = safe_data(greynoise_data, "GreyNoise")
        shodan_data = safe_data(shodan_data, "Shodan")
        censys_data = safe_data(censys_data, "Censys")
        passive_dns_data = safe_data(passive_dns_data, "Passive DNS")
        
        correlated = correlate_threat_data(
            ip=ip,
            abuseipdb=abuseipdb_data,
            virustotal=virustotal_data,
            ipinfo=ipinfo_data,
            greynoise=greynoise_data,
            shodan=shodan_data,
            censys=censys_data,
            passive_dns=passive_dns_data
        )
        
        risk = calculate_risk_score(
            abuseipdb=abuseipdb_data,
            virustotal=virustotal_data,
            ipinfo=ipinfo_data,
            greynoise=greynoise_data,
            shodan=shodan_data,
            censys=censys_data,
            passive_dns=passive_dns_data
        )
        
        ai_report = generate_threat_report(
            ip=ip,
            correlated=correlated,
            risk=risk
        )
        
        # Generate event timeline
        timeline = generate_event_timeline(
            abuseipdb=abuseipdb_data,
            virustotal=virustotal_data,
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