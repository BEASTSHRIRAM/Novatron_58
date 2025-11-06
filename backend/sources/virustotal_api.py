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
    def _mock_for_ip(ip_addr: str) -> Dict[str, Any]:
        seed = sum([int(x) for x in ip_addr.split('.') if x.isdigit()]) if '.' in ip_addr else sum(ord(c) for c in ip_addr)
        malicious = seed % 7  # 0-6
        suspicious = (seed // 3) % 5
        harmless = max(0, 100 - (malicious * 8 + suspicious * 4))
        undetected = max(0, 20 - (malicious + suspicious))
        reputation = ((seed * 13) % 61) - 30  # -30 .. +30
        tags = [] if malicious == 0 else (['malware'] if malicious > 3 else ['suspicious'])
        as_owner = "DigitalOcean LLC" if (seed % 5) != 0 else "Example ISP"
        return {
            "source": "mock",
            "data": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_votes": malicious + suspicious + harmless + undetected,
                "reputation": reputation,
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected
                },
                "tags": tags,
                "country": "US",
                "as_owner": as_owner,
                "network": f"{ip_addr}/24"
            },
            "mock": True
        }

    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured, using mock data")
        return _mock_for_ip(ip)
    
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
            logger.debug("VirusTotal raw response for %s: %s", ip, result)
            data = result.get("data", {})
            attributes = data.get("attributes", {})
            
            # Normalize VirusTotal data
            last_analysis = attributes.get("last_analysis_stats", {})
            
            return {
                "source": "live",
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
        status = e.response.status_code
        if status == 403:
            logger.warning("VirusTotal API access forbidden (invalid/expired key), using mock data")
            return _mock_for_ip(ip)
        elif status == 404:
            logger.info(f"IP {ip} not found in VirusTotal database")
            return _mock_for_ip(ip)
        elif status == 429:
            logger.warning("VirusTotal API rate limit exceeded, using mock data")
            # Use deterministic mock rather than fixed static values
            mock = _mock_for_ip(ip)
            # mark as rate-limited in tags
            mock['data']['tags'] = mock['data'].get('tags', []) + ['rate-limited']
            return mock
        else:
            logger.error(f"VirusTotal API HTTP error: {status}")
            return _mock_for_ip(ip)
    except Exception as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return _mock_for_ip(ip)
