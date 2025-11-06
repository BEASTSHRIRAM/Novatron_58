from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


def correlate_threat_data(
    ip: str,
    abuseipdb: Dict[str, Any],
    shodan: Dict[str, Any],
    ipinfo: Dict[str, Any]
) -> Dict[str, Any]:
    abuse_data = abuseipdb.get("data", {})
    shodan_data = shodan.get("data", {})
    ipinfo_data = ipinfo.get("data", {})
    
    # Build context
    context = {
        "asn": shodan_data.get("asn", ipinfo_data.get("org", "").split()[0] if ipinfo_data.get("org") else ""),
        "org": shodan_data.get("org", abuse_data.get("isp", ipinfo_data.get("org", "Unknown"))),
        "country": ipinfo_data.get("country", shodan_data.get("country_code", abuse_data.get("countryCode", "Unknown"))),
        "city": ipinfo_data.get("city", shodan_data.get("city", "Unknown")),
        "region": ipinfo_data.get("region", ""),
        "location": ipinfo_data.get("loc", ""),
        "timezone": ipinfo_data.get("timezone", ""),
        "hostname": ipinfo_data.get("hostname", shodan_data.get("hostnames", [""])[0] if shodan_data.get("hostnames") else "")
    }
    
    # Determine threat categories
    categories = []
    if abuse_data.get("abuseConfidenceScore", 0) > 50:
        categories.append("Malicious Activity")
    if shodan_data.get("vulns"):
        categories.append("Known Vulnerabilities")
    if len(shodan_data.get("ports", [])) > 5:
        categories.append("High Port Exposure")
    if "ssh" in str(shodan_data.get("tags", [])).lower():
        categories.append("SSH Accessible")
    if abuse_data.get("totalReports", 0) > 10:
        categories.append("Reported Abuse")
    
    if not categories:
        categories.append("Low Risk")
    
    # Related artifacts
    related = {
        "domains": shodan_data.get("domains", []),
        "urls": [],
        "hostnames": shodan_data.get("hostnames", [])
    }
    
    # Evidence from all sources
    evidence = {
        "abuseipdb": {
            "confidence_score": abuse_data.get("abuseConfidenceScore", 0),
            "total_reports": abuse_data.get("totalReports", 0),
            "last_reported": abuse_data.get("lastReportedAt", ""),
            "is_whitelisted": abuse_data.get("isWhitelisted", False),
            "usage_type": abuse_data.get("usageType", "Unknown")
        },
        "shodan": {
            "open_ports": shodan_data.get("ports", []),
            "vulnerabilities": shodan_data.get("vulns", []),
            "services": shodan_data.get("tags", []),
            "os": shodan_data.get("os", "Unknown"),
            "last_update": shodan_data.get("last_update", "")
        },
        "ipinfo": {
            "geolocation": context["location"],
            "organization": context["org"],
            "hostname": context["hostname"],
            "postal_code": ipinfo_data.get("postal", "")
        }
    }
    
    return {
        "ip": ip,
        "context": context,
        "categories": categories,
        "related": related,
        "evidence": evidence
    }