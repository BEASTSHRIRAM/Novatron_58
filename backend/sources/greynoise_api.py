import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY", "")
GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"
GREYNOISE_RIOT_URL = "https://api.greynoise.io/v2/riot/{ip}"


async def get_greynoise_data(ip: str) -> Dict[str, Any]:
    """
    Query GreyNoise for IP classification and activity data
    Returns normalized dict with threat intelligence
    """
    if not GREYNOISE_API_KEY:
        logger.warning("GreyNoise API key not configured, using mock data")
        return {
            "data": {
                "classification": "malicious",
                "name": "Unknown Scanner",
                "first_seen": "2024-01-15",
                "last_seen": "2025-01-05",
                "actor": "unknown",
                "tags": ["web scanner", "ssh bruteforce"],
                "metadata": {
                    "country": "CN",
                    "country_code": "CN",
                    "city": "Beijing",
                    "organization": "China Telecom",
                    "asn": "AS4134"
                },
                "raw_data": {
                    "scan": True,
                    "web": {
                        "paths": ["/admin", "/wp-admin", "/.env"]
                    }
                },
                "riot": False,
                "message": "Mock data - GreyNoise API not configured"
            },
            "mock": True
        }
    
    try:
        headers = {
            "key": GREYNOISE_API_KEY,
            "Accept": "application/json"
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get community/quick check data
            response = await client.get(
                GREYNOISE_URL.format(ip=ip),
                headers=headers
            )
            response.raise_for_status()
            data = response.json()
            
            # Check if IP is in RIOT (known good IPs)
            riot_response = await client.get(
                GREYNOISE_RIOT_URL.format(ip=ip),
                headers=headers
            )
            riot_data = riot_response.json() if riot_response.status_code == 200 else {}
            
            # Normalize GreyNoise response
            normalized = {
                "classification": data.get("classification", "unknown"),
                "name": data.get("name", "Unknown"),
                "first_seen": data.get("first_seen", ""),
                "last_seen": data.get("last_seen", ""),
                "actor": data.get("actor", "unknown"),
                "tags": data.get("tags", []),
                "metadata": data.get("metadata", {}),
                "raw_data": data.get("raw_data", {}),
                "riot": riot_data.get("riot", False),
                "riot_category": riot_data.get("category", ""),
                "riot_name": riot_data.get("name", ""),
                "message": data.get("message", "")
            }
            
            return {"data": normalized}
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"IP {ip} not found in GreyNoise database")
            return {
                "data": {
                    "classification": "unknown",
                    "message": "IP not found in GreyNoise",
                    "riot": False
                }
            }
        elif e.response.status_code == 429:
            logger.warning("GreyNoise API rate limit exceeded")
            return {"data": {}, "error": "Rate limit exceeded"}
        else:
            logger.error(f"GreyNoise API HTTP error: {e.response.status_code}")
            return {"data": {}, "error": str(e)}
    except Exception as e:
        logger.error(f"GreyNoise API error: {str(e)}")
        return {"data": {}, "error": str(e)}
