import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

IPINFO_API_KEY = os.environ.get("IPINFO_API_KEY", "")
IPINFO_URL = "https://ipinfo.io/{ip}/json"


async def get_ipinfo_data(ip: str) -> Dict[str, Any]:
    """
    Query IPInfo for geolocation and organization data
    Returns normalized dict with context intelligence
    """
    if not IPINFO_API_KEY:
        logger.warning("IPInfo API key not configured, using mock data")
        return {
            "data": {
                "ip": ip,
                "hostname": "server.example.com",
                "city": "San Francisco",
                "region": "California",
                "country": "US",
                "loc": "37.7749,-122.4194",
                "org": "AS14061 DigitalOcean, LLC",
                "postal": "94103",
                "timezone": "America/Los_Angeles"
            },
            "mock": True
        }
    
    try:
        url = IPINFO_URL.format(ip=ip)
        params = {"token": IPINFO_API_KEY}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            return {"data": response.json()}
            
    except Exception as e:
        logger.error(f"IPInfo API error: {str(e)}")
        return {"data": {}, "error": str(e)}