import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


async def get_virustotal_data(ip: str) -> Dict[str, Any]:
    """
    Query VirusTotal for IP reputation and threat data
    Returns normalized dict with threat intelligence
    """
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured, using mock data")
        return {
            "data": {
                "malicious": 5,
                "suspicious": 2,
                "harmless": 60,
                "undetected": 15,
                "total_votes": 82,
                "reputation": -15,
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 60,
                    "undetected": 15
                },
                "tags": ["malware", "bruteforce"],
                "country": "US",
                "as_owner": "DigitalOcean LLC",
                "network": "45.33.32.0/24"
            },
            "mock": True
        }
    
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }
        
        url = VIRUSTOTAL_URL.format(ip=ip)
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            data = result.get("data", {})
            attributes = data.get("attributes", {})
            
            # Normalize VirusTotal data
            last_analysis = attributes.get("last_analysis_stats", {})
            
            return {
                "data": {
                    "malicious": last_analysis.get("malicious", 0),
                    "suspicious": last_analysis.get("suspicious", 0),
                    "harmless": last_analysis.get("harmless", 0),
                    "undetected": last_analysis.get("undetected", 0),
                    "total_votes": sum(last_analysis.values()) if last_analysis else 0,
                    "reputation": attributes.get("reputation", 0),
                    "last_analysis_stats": last_analysis,
                    "tags": attributes.get("tags", []),
                    "country": attributes.get("country", "Unknown"),
                    "as_owner": attributes.get("as_owner", "Unknown"),
                    "network": attributes.get("network", "")
                }
            }
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logger.warning("VirusTotal API access forbidden (invalid/expired key), using mock data")
        elif e.response.status_code == 404:
            logger.info(f"IP {ip} not found in VirusTotal database")
        elif e.response.status_code == 429:
            logger.warning("VirusTotal API rate limit exceeded, using mock data")
            return {
                "data": {
                    "malicious": 3,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 10,
                    "total_votes": 64,
                    "reputation": -8,
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 50,
                        "undetected": 10
                    },
                    "tags": ["rate-limited"],
                    "country": "Unknown",
                    "as_owner": "Unknown",
                    "network": ""
                },
                "mock": True
            }
        else:
            logger.error(f"VirusTotal API HTTP error: {e.response.status_code}")
        return {"data": {}, "error": str(e)}
    except Exception as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return {"data": {}, "error": str(e)}
