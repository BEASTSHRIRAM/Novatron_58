import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
async def get_abuseipdb_data(ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        logger.warning("AbuseIPDB API key not configured, using mock data")
        return {
            "data": {
                "abuseConfidenceScore": 75,
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "DigitalOcean LLC",
                "domain": "digitalocean.com",
                "totalReports": 42,
                "numDistinctUsers": 15,
                "lastReportedAt": "2025-01-15T10:30:00+00:00",
                "isWhitelisted": False,
                "countryCode": "US"
            },
            "mock": True
        }
    
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(ABUSEIPDB_URL, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        logger.error(f"AbuseIPDB API error: {str(e)}")
        return {"data": {}, "error": str(e)}