import os
import httpx
import logging
from typing import Dict, Any
import base64

logger = logging.getLogger(__name__)

CENSYS_API_ID = os.environ.get("CENSYS_API_ID", "")
CENSYS_API_SECRET = os.environ.get("CENSYS_API_SECRET", "")
CENSYS_URL = "https://search.censys.io/api/v2/hosts/{ip}"


async def get_censys_data(ip: str) -> Dict[str, Any]:
    """
    Query Censys for IP exposure, certificates, and historical data
    Returns normalized dict with infrastructure intelligence
    """
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        logger.warning("Censys API credentials not configured, using mock data")
        # Deterministic mock per IP
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        ports = [443]
        if seed % 3 == 0:
            ports += [22, 80]
        certificates = [
            {
                "issuer": "Let's Encrypt",
                "subject": f"example{seed % 10}.com",
                "valid_from": "2024-01-01",
                "valid_to": "2025-04-01"
            }
        ]
        asn = f"{14000 + (seed % 1000)}"
        names = ["DigitalOcean, LLC", "Amazon AWS", "Example ISP"]
        name = names[seed % len(names)]
        cities = ["San Francisco", "New York", "Berlin"]
        city = cities[seed % len(cities)]

        return {
            "data": {
                "services": [{"port": p, "service_name": "HTTPS"} for p in ports],
                "certificates": certificates,
                "autonomous_system": {
                    "asn": asn,
                    "description": f"{name}-ASN",
                    "bgp_prefix": f"104.{seed % 255}.0.0/16",
                    "name": name,
                    "country_code": "US"
                },
                "location": {
                    "country": "United States",
                    "city": city,
                    "coordinates": {"latitude": 37.7749 + (seed % 10) * 0.01, "longitude": -122.4194 + (seed % 10) * 0.01}
                },
                "last_updated_at": "2025-01-15T10:30:00Z",
                "operating_system": {
                    "product": "Linux",
                    "vendor": "Ubuntu"
                }
            },
            "mock": True
        }
    
    try:
        # Censys uses Basic Auth
        auth_string = f"{CENSYS_API_ID}:{CENSYS_API_SECRET}"
        auth_bytes = auth_string.encode('ascii')
        base64_auth = base64.b64encode(auth_bytes).decode('ascii')
        
        headers = {
            "Authorization": f"Basic {base64_auth}",
            "Accept": "application/json"
        }
        
        url = CENSYS_URL.format(ip=ip)
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            result = data.get("result", {})
            
            # Extract certificates from services
            certificates = []
            services = result.get("services", [])
            for service in services:
                if "tls" in service and "certificates" in service["tls"]:
                    for cert in service["tls"]["certificates"]:
                        certificates.append({
                            "issuer": cert.get("issuer", ""),
                            "subject": cert.get("subject", ""),
                            "valid_from": cert.get("valid_from", ""),
                            "valid_to": cert.get("valid_to", ""),
                            "fingerprint": cert.get("fingerprint_sha256", "")
                        })
            
            normalized = {
                "services": services,
                "certificates": certificates,
                "autonomous_system": result.get("autonomous_system", {}),
                "location": result.get("location", {}),
                "last_updated_at": result.get("last_updated_at", ""),
                "operating_system": result.get("operating_system", {}),
                "dns": result.get("dns", {})
            }
            
            return {"data": normalized}
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"IP {ip} not found in Censys database")
            return {"data": {"message": "IP not found in Censys"}}
        elif e.response.status_code == 403:
            logger.warning("Censys API access forbidden (invalid credentials)")
            return {"data": {"message": "Invalid API credentials"}, "mock": True}
        elif e.response.status_code == 429:
            logger.warning("Censys API rate limit exceeded")
            return {"data": {}, "error": "Rate limit exceeded"}
        else:
            logger.error(f"Censys API HTTP error: {e.response.status_code}")
            return {"data": {}, "error": str(e)}
    except Exception as e:
        logger.error(f"Censys API error: {str(e)}")
        return {"data": {}, "error": str(e)}
