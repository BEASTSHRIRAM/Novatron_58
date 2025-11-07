import os
import httpx
import socket
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

HUNTER_API_KEY = os.environ.get("HUNTER_API_KEY", "")
HUNTER_DOMAIN_SEARCH_URL = "https://api.hunter.io/v2/domain-search"
CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query"


async def hunter_domain_search(domain: str) -> Dict[str, Any]:
    """
    Query Hunter.io API for email addresses associated with a domain
    
    Args:
        domain: Domain name to search (e.g., 'example.com')
    
    Returns:
        Dict containing email addresses and domain information
    """
    if not HUNTER_API_KEY:
        logger.warning("Hunter API key not configured, using mock data")
        return {
            "data": {
                "domain": domain,
                "emails": [
                    {
                        "value": f"admin@{domain}",
                        "type": "personal",
                        "confidence": 95,
                        "first_name": "Admin",
                        "last_name": domain.split('.')[0].upper(),
                        "position": "Administrator",
                        "company": domain.split('.')[0].upper()
                    }
                ],
                "meta": {
                    "results": 1,
                    "limit": 100,
                    "offset": 0
                }
            },
            "mock": True
        }
    
    try:
        params = {
            "domain": domain,
            "api_key": HUNTER_API_KEY,
            "limit": 100
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                HUNTER_DOMAIN_SEARCH_URL,
                params=params
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Filter emails with high confidence scores
            if "data" in data and "emails" in data["data"]:
                emails = data["data"]["emails"]
                high_confidence = [
                    e for e in emails 
                    if e.get("confidence", 0) >= 75
                ]
                data["data"]["emails"] = high_confidence
                data["data"]["high_confidence_count"] = len(high_confidence)
            
            logger.info(f"Hunter: Found {len(data.get('data', {}).get('emails', []))} emails for {domain}")
            return data
            
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.info(f"Hunter: No data found for domain {domain}")
            return {
                "data": {
                    "domain": domain,
                    "emails": [],
                    "message": "No emails found"
                },
                "error": "Domain not found in Hunter database"
            }
        elif e.response.status_code == 401:
            logger.warning("Hunter API authentication failed (invalid key)")
            return {
                "data": {"emails": []},
                "error": "Invalid Hunter API key"
            }
        elif e.response.status_code == 429:
            logger.warning("Hunter API rate limit exceeded")
            return {
                "data": {"emails": []},
                "error": "Rate limit exceeded"
            }
        else:
            logger.error(f"Hunter API HTTP error: {e.response.status_code}")
            return {
                "data": {"emails": []},
                "error": str(e)
            }
    except Exception as e:
        logger.error(f"Hunter API error: {str(e)}")
        return {
            "data": {"emails": []},
            "error": str(e)
        }


async def reverse_dns_lookup(ip: str) -> str:
    """
    Perform reverse DNS lookup to get domain from IP
    This is Step 1 of the OSINT chain
    
    Args:
        ip: IP address to look up
    
    Returns:
        Domain name if found, empty string otherwise
    """
    try:
        domain = socket.gethostbyaddr(ip)[0]
        logger.info(f"PTR record found for {ip}: {domain}")
        return domain
    except socket.herror:
        logger.debug(f"No PTR record found for IP {ip}")
        return ""
    except Exception as e:
        logger.error(f"Reverse DNS lookup failed for {ip}: {str(e)}")
        return ""


async def get_pdns_domains(ip: str) -> List[str]:
    """
    Query CIRCL Passive DNS to find domains associated with IP
    This is Step 2 of the OSINT chain (fallback if reverse DNS fails)
    
    Args:
        ip: IP address to query
    
    Returns:
        List of domain names associated with the IP
    """
    try:
        url = f"{CIRCL_PDNS_URL}/{ip}"
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            
            data = response.json()
            
            if isinstance(data, list) and len(data) > 0:
                # Extract domains where record type is 'A' (address record)
                domains = []
                for record in data:
                    if record.get("rrtype") == "A":
                        domain = record.get("rrname", "").rstrip(".")
                        if domain and domain not in domains:
                            domains.append(domain)
                
                logger.info(f"PDNS: Found {len(domains)} domains for {ip}")
                return domains[:5]  # Return top 5 domains
            else:
                logger.info(f"PDNS: No domains found for {ip}")
                return []
                
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.debug(f"PDNS: IP {ip} not found in CIRCL database")
        else:
            logger.error(f"PDNS API HTTP error: {e.response.status_code}")
        return []
    except Exception as e:
        logger.error(f"PDNS lookup failed for {ip}: {str(e)}")
        return []


async def get_attacker_emails(ip: str) -> Dict[str, Any]:
    """
    Main function: Find email addresses associated with an IP address
    Uses professional OSINT chain:
    1. Try reverse DNS lookup (PTR record)
    2. Fallback to passive DNS (CIRCL) to find associated domains
    3. Query Hunter.io for emails on found domains
    
    This is the standard chain used by professional threat intelligence analysts
    
    Args:
        ip: IP address to investigate
    
    Returns:
        Dict containing:
        - emails: List of email addresses found
        - domain_source: How the domain was identified (PTR, PDNS, or Not Found)
        - domains_checked: List of domains queried
        - confidence: Overall confidence score
    """
    result = {
        "ip": ip,
        "emails": [],
        "domains_checked": [],
        "domain_source": None,
        "chain_steps": [],
        "high_confidence_emails": [],
        "confidence": 0,
        "error": None
    }
    
    try:
        # STEP 1: Try Reverse DNS Lookup
        logger.info(f"[OSINT Chain] Step 1: Reverse DNS lookup for {ip}")
        result["chain_steps"].append("reverse_dns_attempted")
        
        domain = await reverse_dns_lookup(ip)
        
        if domain:
            logger.info(f"[OSINT Chain] ✓ PTR record found: {domain}")
            result["domain_source"] = "PTR_RECORD"
            result["domains_checked"].append(domain)
            result["chain_steps"].append("reverse_dns_success")
        else:
            # STEP 2: Fallback to Passive DNS
            logger.info(f"[OSINT Chain] Step 2: No PTR record, using Passive DNS fallback")
            result["chain_steps"].append("pdns_fallback_triggered")
            
            domains = await get_pdns_domains(ip)
            
            if domains:
                logger.info(f"[OSINT Chain] ✓ PDNS found {len(domains)} domains")
                result["domain_source"] = "PASSIVE_DNS"
                result["domains_checked"].extend(domains)
                result["chain_steps"].append("pdns_success")
            else:
                logger.warning(f"[OSINT Chain] ✗ No domains found via reverse DNS or PDNS")
                result["chain_steps"].append("pdns_failed")
                result["error"] = "No domain found for this IP via reverse DNS or Passive DNS"
                return result
        
        # STEP 3: Query Hunter.io for each domain
        logger.info(f"[OSINT Chain] Step 3: Querying Hunter.io for {len(result['domains_checked'])} domain(s)")
        result["chain_steps"].append("hunter_query_started")
        
        all_emails = []
        
        for domain in result["domains_checked"]:
            logger.info(f"[OSINT Chain] Checking Hunter for domain: {domain}")
            
            hunter_result = await hunter_domain_search(domain)
            
            if "data" in hunter_result and "emails" in hunter_result["data"]:
                emails = hunter_result["data"]["emails"]
                
                if emails:
                    logger.info(f"[OSINT Chain] ✓ Found {len(emails)} emails for {domain}")
                    all_emails.extend(emails)
                    
                    # Filter high-confidence emails (75%+)
                    high_conf = [e for e in emails if e.get("confidence", 0) >= 75]
                    result["high_confidence_emails"].extend(high_conf)
                else:
                    logger.info(f"[OSINT Chain] ✗ No emails found for {domain}")
        
        result["emails"] = all_emails
        result["chain_steps"].append("hunter_query_complete")
        
        # Calculate confidence score
        if result["high_confidence_emails"]:
            result["confidence"] = min(95, 75 + (len(result["high_confidence_emails"]) * 5))
        elif result["emails"]:
            result["confidence"] = min(75, 50 + (len(result["emails"]) * 3))
        elif result["domain_source"] == "PTR_RECORD":
            result["confidence"] = 60  # Domain found via PTR but no emails
        elif result["domain_source"] == "PASSIVE_DNS":
            result["confidence"] = 40  # Domain found via PDNS but no emails
        
        logger.info(f"[OSINT Chain] Complete. Found {len(result['emails'])} emails. "
                   f"Confidence: {result['confidence']}%")
        
        return result
        
    except Exception as e:
        logger.error(f"[OSINT Chain] Fatal error: {str(e)}")
        result["error"] = f"Fatal error during email discovery: {str(e)}"
        result["confidence"] = 0
        return result


# Mock data generator for testing
def _generate_mock_emails(ip: str, domain: str) -> List[Dict[str, Any]]:
    """Generate deterministic mock emails for testing"""
    seed = sum([int(x) for x in ip.split('.') if x.isdigit()]) if '.' in ip else sum(ord(c) for c in ip)
    
    mock_titles = ["CEO", "CTO", "Engineer", "Administrator", "Operator", "Manager"]
    mock_first_names = ["John", "Jane", "Alex", "Chris", "Sam", "Morgan"]
    mock_last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"]
    
    emails = []
    for i in range(1 + (seed % 3)):
        title_idx = (seed + i) % len(mock_titles)
        first_idx = (seed + i) % len(mock_first_names)
        last_idx = (seed + i + 1) % len(mock_last_names)
        
        first = mock_first_names[first_idx]
        last = mock_last_names[last_idx]
        
        emails.append({
            "value": f"{first.lower()}.{last.lower()}@{domain}",
            "type": "personal",
            "confidence": 70 + (seed % 25),
            "first_name": first,
            "last_name": last,
            "position": mock_titles[title_idx],
            "company": domain.split('.')[0].upper()
        })
    
    return emails
