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
        # Deterministic mock based on IP
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        base_ports = [22, 80, 443]
        extra_ports = [(seed % 5) + 1]
        ports = base_ports + [1000 + (seed % 100)] * extra_ports[0]
        vuln_pool = ["CVE-2021-44228", "CVE-2022-26134", "CVE-2020-1472", "CVE-2019-0708"]
        vulns = [vuln_pool[i % len(vuln_pool)] for i in range(seed % 3)]
        orgs = ["DigitalOcean, LLC", "Amazon AWS", "Example ISP", "Cloudflare, Inc."]
        org = orgs[seed % len(orgs)]
        city_list = ["San Francisco", "New York", "London", "Berlin"]
        city = city_list[seed % len(city_list)]
        return {
            "data": {
                "ports": ports,
                "vulns": vulns,
                "tags": ["cloud"] if seed % 2 == 0 else ["database"],
                "os": "Linux 4.15",
                "org": org,
                "asn": f"AS{14000 + (seed % 1000)}",
                "hostnames": [f"host-{seed % 100}.example.com"],
                "domains": [f"example{seed % 10}.com"],
                "country_code": "US",
                "city": city,
                "last_update": "2025-01-15T08:20:00+00:00"
            },
            "mock": True
        }
    
    try:
        url = SHODAN_URL.format(ip=ip)
        params = {"key": SHODAN_API_KEY}
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract and normalize service data
            services = []
            for item in data.get("data", []):
                services.append({
                    "port": item.get("port"),
                    "protocol": item.get("transport", "tcp"),
                    "service": item.get("product", ""),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": item.get("data", "")[:200]  # Truncate banner
                })
            
            # Add services to response
            normalized_data = data.copy()
            normalized_data["services"] = services
            
            return {"data": normalized_data}
            
    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        logger.warning(f"Shodan HTTP error {status} - returning deterministic mock")
        # return a deterministic mock for this IP so results vary across IPs
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        base_ports = [22, 80, 443]
        extra_ports = [(seed % 5) + 1]
        ports = base_ports + [1000 + (seed % 100)] * extra_ports[0]
        vuln_pool = ["CVE-2021-44228", "CVE-2022-26134", "CVE-2020-1472", "CVE-2019-0708"]
        vulns = [vuln_pool[i % len(vuln_pool)] for i in range(seed % 3)]
        orgs = ["DigitalOcean, LLC", "Amazon AWS", "Example ISP", "Cloudflare, Inc."]
        org = orgs[seed % len(orgs)]
        city_list = ["San Francisco", "New York", "London", "Berlin"]
        city = city_list[seed % len(city_list)]
        return {
            "data": {
                "ports": ports,
                "vulns": vulns,
                "tags": ["cloud"] if seed % 2 == 0 else ["database"],
                "os": "Linux 4.15",
                "org": org,
                "asn": f"AS{14000 + (seed % 1000)}",
                "hostnames": [f"host-{seed % 100}.example.com"],
                "domains": [f"example{seed % 10}.com"],
                "country_code": "US",
                "city": city,
                "last_update": "2025-01-15T08:20:00+00:00"
            },
            "mock": True
        }
    except Exception as e:
        logger.error(f"Shodan API error: {str(e)}")
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        return {
            "data": {
                "ports": [22, 80, 443] + ([1000 + (seed % 100)] * ((seed % 5) + 1)),
                "vulns": ["CVE-2021-44228"] if seed % 3 == 0 else [],
                "tags": ["cloud"] if seed % 2 == 0 else ["database"],
                "os": "Linux 4.15",
                "org": ["DigitalOcean, LLC"][(seed % 1)],
                "asn": f"AS{14000 + (seed % 1000)}",
                "hostnames": [f"host-{seed % 100}.example.com"],
                "domains": [f"example{seed % 10}.com"],
                "country_code": "US",
                "city": ["San Francisco", "New York", "London", "Berlin"][seed % 4],
                "last_update": "2025-01-15T08:20:00+00:00"
            },
            "mock": True
        }