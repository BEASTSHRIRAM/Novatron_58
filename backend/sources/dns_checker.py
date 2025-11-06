import socket
import logging
from typing import Dict, List, Any
import httpx
import os

logger = logging.getLogger(__name__)

async def get_dns_data(ip: str) -> Dict[str, Any]:
    """
    Get DNS information including:
    - Reverse DNS (hostname)
    - PTR records
    - Related domains
    - Whois information
    - Organization/ASN info
    """
    
    try:
        result = {
            "hostname": None,
            "ptr_records": [],
            "related_domains": [],
            "whois_info": {},
            "mx_records": [],
            "ns_records": [],
            "soa_record": None,
            "organization": None,
            "country": None,
            "asn": None
        }
        
        # Get reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)
            result["hostname"] = hostname[0]
            logger.info(f"Reverse DNS lookup for {ip}: {hostname[0]}")
        except (socket.herror, socket.gaierror) as e:
            logger.debug(f"Reverse DNS lookup failed for {ip}: {str(e)}")
            result["hostname"] = None
        
        # Try ipapi.co for comprehensive info (fastest and most reliable free service)
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, read=10.0)) as client:
                domain_response = await client.get(
                    f"https://ipapi.co/{ip}/json/",
                    timeout=httpx.Timeout(5.0, read=10.0)
                )
                if domain_response.status_code == 200:
                    domain_data = domain_response.json()
                    
                    # Extract hostname if not found via reverse DNS
                    if not result["hostname"] and domain_data.get("hostname"):
                        result["hostname"] = domain_data.get("hostname")
                    
                    # Extract organization/country info
                    if domain_data.get("org"):
                        result["organization"] = domain_data.get("org")
                        result["whois_info"]["Organization"] = domain_data.get("org")
                    
                    if domain_data.get("country_name"):
                        result["country"] = domain_data.get("country_name")
                        result["whois_info"]["Country"] = domain_data.get("country_name")
                    
                    if domain_data.get("asn"):
                        result["asn"] = domain_data.get("asn")
                        result["whois_info"]["ASN"] = domain_data.get("asn")
                    
                    if domain_data.get("city"):
                        result["whois_info"]["City"] = domain_data.get("city")
                    
                    logger.info(f"Domain info retrieved for {ip}")
        except Exception as e:
            logger.debug(f"ipapi.co lookup failed for {ip}: {str(e)}")
        
        # Extract domain from hostname if available
        if result["hostname"]:
            try:
                parts = result["hostname"].split('.')
                if len(parts) >= 2:
                    # Get the domain (last 2 parts usually)
                    domain = '.'.join(parts[-2:])
                    if domain not in result["related_domains"]:
                        result["related_domains"].append(domain)
                    logger.info(f"Extracted domain from hostname: {domain}")
            except Exception as e:
                logger.debug(f"Domain extraction failed: {str(e)}")
        
        # Extract from organization if it contains a domain
        if result.get("organization"):
            try:
                org = result["organization"].lower()
                # Try to extract domain-like patterns
                if "." in org:
                    parts = org.split()
                    for part in parts:
                        if "." in part and not part.startswith("http"):
                            domain = part.strip("(),")
                            if domain and domain not in result["related_domains"]:
                                result["related_domains"].append(domain)
            except Exception as e:
                logger.debug(f"Organization parsing failed: {str(e)}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error getting DNS data for {ip}: {str(e)}")
        return {
            "hostname": None,
            "ptr_records": [],
            "related_domains": [],
            "whois_info": {},
            "mx_records": [],
            "ns_records": [],
            "soa_record": None,
            "organization": None,
            "country": None,
            "asn": None,
            "error": str(e)
        }
