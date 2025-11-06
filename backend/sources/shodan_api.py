import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"


async def get_shodan_data(ip: str) -> Dict[str, Any]:
    """
    Query Shodan for IP exposure and service data
    Returns normalized dict with infrastructure intelligence
    """
    if not SHODAN_API_KEY:
        logger.warning("Shodan API key not configured, using mock data")
        return {
            "data": {
                "ports": [22, 80, 443, 3306],
                "vulns": ["CVE-2021-44228", "CVE-2022-26134"],
                "tags": ["cloud", "database"],
                "os": "Linux 4.15",
                "org": "DigitalOcean, LLC",
                "asn": "AS14061",
                "hostnames": ["server.example.com"],
                "domains": ["example.com"],
                "country_code": "US",
                "city": "San Francisco",
                "last_update": "2025-01-15T08:20:00+00:00"
            },
            "mock": True
        }
    
    try:
        url = SHODAN_URL.format(ip=ip)
        params = {"key": SHODAN_API_KEY}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            return {"data": response.json()}
            
    except Exception as e:
        logger.error(f"Shodan API error: {str(e)}")
        return {"data": {}, "error": str(e)}