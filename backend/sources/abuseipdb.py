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
        # Create deterministic but variable mock data based on IP string so different IPs get different scores
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        abuse_conf = max(0, min(95, (seed * 7) % 100))
        total_reports = (seed * 3) % 120
        usage = "Data Center/Web Hosting/Transit" if (seed % 3) != 0 else "ISP"
        isp_name = "DigitalOcean LLC" if (seed % 5) != 0 else "Example ISP"
        return {
            "data": {
                "abuseConfidenceScore": abuse_conf,
                "usageType": usage,
                "isp": isp_name,
                "domain": isp_name.lower().replace(' ', '') + ".com",
                "totalReports": total_reports,
                "numDistinctUsers": max(0, (seed * 2) % 40),
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
        # Fall back to deterministic mock so different IPs produce different mock results
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        abuse_conf = max(0, min(95, (seed * 7) % 100))
        total_reports = (seed * 3) % 120
        usage = "Data Center/Web Hosting/Transit" if (seed % 3) != 0 else "ISP"
        isp_name = "DigitalOcean LLC" if (seed % 5) != 0 else "Example ISP"
        return {
            "data": {
                "abuseConfidenceScore": abuse_conf,
                "usageType": usage,
                "isp": isp_name,
                "domain": isp_name.lower().replace(' ', '') + ".com",
                "totalReports": total_reports,
                "numDistinctUsers": max(0, (seed * 2) % 40),
                "lastReportedAt": "2025-01-15T10:30:00+00:00",
                "isWhitelisted": False,
                "countryCode": "US"
            },
            "mock": True,
            "error": str(e)
        }