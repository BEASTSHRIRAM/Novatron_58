import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Using SecurityTrails as the Passive DNS provider
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")
SECURITYTRAILS_URL = "https://api.securitytrails.com/v1/ips/nearby/{ip}"


async def get_passive_dns_data(ip: str) -> Dict[str, Any]:
    """
    Query Passive DNS for historical domain associations
    Returns normalized dict with DNS history intelligence
    """
    if not SECURITYTRAILS_API_KEY:
        logger.warning("SecurityTrails API key not configured, using mock data")
        # Deterministic mock per IP
        seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
        domains = []
        suspicious_keywords = []
        domain_examples = ["malicious-example.com", "phishing-site.net", "tracker.example", "cdn.example"]
        count = 1 + (seed % 4)
        for i in range(count):
            d = domain_examples[(seed + i) % len(domain_examples)]
            domains.append({
                "domain": d,
                "first_seen": "2024-01-15",
                "last_seen": "2025-01-15",
                "record_type": "A"
            })
            if "phish" in d or "malicious" in d:
                suspicious_keywords.append(d.split('-')[0])

        return {
            "data": {
                "associated_domains": domains,
                "total_domains": len(domains),
                "suspicious_keywords": suspicious_keywords
            },
            "mock": True
        }
    
    try:
        headers = {
            "APIKEY": SECURITYTRAILS_API_KEY,
            "Accept": "application/json"
        }
        
        url = SECURITYTRAILS_URL.format(ip=ip)
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            blocks = data.get("blocks", [])
            
            associated_domains = []
            suspicious_keywords = []
            
            for block in blocks:
                hostnames = block.get("hostnames", [])
                for hostname_info in hostnames:
                    domain = hostname_info.get("hostname", "")
                    
                    # Check for suspicious keywords
                    suspicious_terms = ["phishing", "malware", "spam", "scam", "fake", "suspicious", "malicious", "hack"]
                    for term in suspicious_terms:
                        if term in domain.lower() and term not in suspicious_keywords:
                            suspicious_keywords.append(term)
                    
                    associated_domains.append({
                        "domain": domain,
                        "first_seen": hostname_info.get("first_seen", ""),
                        "last_seen": hostname_info.get("last_seen", ""),
                        "record_type": "A"
                    })
            
            normalized = {
                "associated_domains": associated_domains,
                "total_domains": len(associated_domains),
                "suspicious_keywords": suspicious_keywords
            }
            
            return {"data": normalized}
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"IP {ip} not found in SecurityTrails database")
            return {"data": {"message": "IP not found in DNS records", "associated_domains": [], "total_domains": 0}}
        elif e.response.status_code == 403:
            logger.warning("SecurityTrails API access forbidden (invalid key)")
            return {"data": {"message": "Invalid API key"}, "mock": True}
        elif e.response.status_code == 429:
            logger.warning("SecurityTrails API rate limit exceeded")
            return {"data": {"associated_domains": [], "total_domains": 0}, "error": "Rate limit exceeded"}
        else:
            logger.error(f"SecurityTrails API HTTP error: {e.response.status_code}")
            return {"data": {"associated_domains": [], "total_domains": 0}, "error": str(e)}
    except Exception as e:
        logger.error(f"SecurityTrails API error: {str(e)}")
        return {"data": {"associated_domains": [], "total_domains": 0}, "error": str(e)}
