from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


def correlate_threat_data(
    ip: str,
    abuseipdb: Dict[str, Any],
    virustotal: Dict[str, Any],
    ipinfo: Dict[str, Any]
) -> Dict[str, Any]:
    abuse_data = abuseipdb.get("data", {})
    vt_data = virustotal.get("data", {})
    ipinfo_data = ipinfo.get("data", {})
    
    # Build context
    context = {
        "asn": ipinfo_data.get("org", "").split()[0] if ipinfo_data.get("org") else vt_data.get("as_owner", "Unknown"),
        "org": vt_data.get("as_owner", abuse_data.get("isp", ipinfo_data.get("org", "Unknown"))),
        "country": ipinfo_data.get("country", vt_data.get("country", abuse_data.get("countryCode", "Unknown"))),
        "city": ipinfo_data.get("city", "Unknown"),
        "region": ipinfo_data.get("region", ""),
        "location": ipinfo_data.get("loc", ""),
        "timezone": ipinfo_data.get("timezone", ""),
        "hostname": ipinfo_data.get("hostname", "")
    }
    
    # Determine threat categories
    categories = []
    if abuse_data.get("abuseConfidenceScore", 0) > 50:
        categories.append("Malicious Activity")
    if vt_data.get("malicious", 0) > 3:
        categories.append("Detected as Malicious")
    if vt_data.get("reputation", 0) < -10:
        categories.append("Poor Reputation")
    if "malware" in vt_data.get("tags", []):
        categories.append("Malware Distribution")
    if abuse_data.get("totalReports", 0) > 10:
        categories.append("Reported Abuse")
    
    if not categories:
        categories.append("Low Risk")
    
    # Related artifacts
    related = {
        "domains": [],
        "urls": [],
        "hostnames": []
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
        "virustotal": {
            "malicious": vt_data.get("malicious", 0),
            "suspicious": vt_data.get("suspicious", 0),
            "harmless": vt_data.get("harmless", 0),
            "reputation": vt_data.get("reputation", 0),
            "tags": vt_data.get("tags", []),
            "total_votes": vt_data.get("total_votes", 0)
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