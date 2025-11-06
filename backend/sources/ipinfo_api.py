import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

IPDATA_API_KEY = os.environ.get("IPDATA_API_KEY", "")
IPDATA_URL = "https://api.ipdata.co/{ip}"


async def get_ipinfo_data(ip: str) -> Dict[str, Any]:
    """
    Query IPData.co for geolocation and organization data
    Returns normalized dict with context intelligence
    """
    if not IPDATA_API_KEY:
        logger.warning("IPData API key not configured, using mock data")
        # Deterministic mock per IP
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        cities = [
            ("San Francisco", "California"),
            ("New York", "New York"),
            ("London", "England"),
            ("Berlin", "Berlin"),
            ("Mumbai", "Maharashtra"),
            ("Tokyo", "Tokyo")
        ]
        city, region = cities[seed % len(cities)]
        country_map = {"San Francisco": ("United States", "US"), "New York": ("United States", "US"), "London": ("United Kingdom", "GB"), "Berlin": ("Germany", "DE"), "Mumbai": ("India", "IN"), "Tokyo": ("Japan", "JP")}
        country_name, country_code = country_map.get(city, ("Unknown", "UN"))
        asn_val = f"AS{14000 + (seed % 1000)}"
        orgs = ["DigitalOcean, LLC", "Amazon AWS", "Example ISP", "Cloudflare, Inc."]
        org = orgs[seed % len(orgs)]
        latitude = 37.7749 + ((seed % 10) * 0.01)
        longitude = -122.4194 + ((seed % 10) * 0.01)

        return {
            "data": {
                "ip": ip,
                "hostname": f"host-{seed % 100}.example.com",
                "city": city,
                "region": region,
                "country_name": country_name,
                "country_code": country_code,
                "latitude": latitude,
                "longitude": longitude,
                "asn": {"name": org, "asn": asn_val},
                "postal": str(90000 + (seed % 999)),
                "time_zone": {"name": "UTC"}
            },
            "mock": True
        }
    
    try:
        url = IPDATA_URL.format(ip=ip)
        params = {"api-key": IPDATA_API_KEY}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Normalize IPData response to match expected format
            normalized = {
                "ip": data.get("ip", ip),
                "hostname": data.get("hostname", ""),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", ""),
                "country": data.get("country_code", "Unknown"),
                "country_name": data.get("country_name", "Unknown"),
                "loc": f"{data.get('latitude', 0)},{data.get('longitude', 0)}",
                "org": data.get("asn", {}).get("name", "Unknown"),
                "asn": data.get("asn", {}).get("asn", "Unknown"),
                "postal": data.get("postal", ""),
                "timezone": data.get("time_zone", {}).get("name", "")
            }
            
            return {"data": normalized}
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logger.warning(f"IPData API access forbidden (invalid/expired key), using mock data")
        else:
            logger.error(f"IPData API error: {str(e)}")
        return {
            "data": {
                "ip": ip,
                "hostname": "server.example.com",
                "city": "San Francisco",
                "region": "California",
                "country": "US",
                "country_name": "United States",
                "loc": "37.7749,-122.4194",
                "org": "DigitalOcean, LLC",
                "asn": "AS14061",
                "postal": "94103",
                "timezone": "America/Los_Angeles"
            },
            "mock": True
        }
    except Exception as e:
        logger.error(f"IPData API error: {str(e)}")
        return {"data": {}, "error": str(e)}