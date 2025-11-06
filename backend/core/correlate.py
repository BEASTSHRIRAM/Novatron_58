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
    
    # Extract CVE information from VirusTotal
    cve_list = []
    if vt_data.get("last_analysis_results"):
        # VirusTotal may have CVE data in various fields
        pass
    
    # VirusTotal may have CVE tags or in attributes
    if vt_data.get("tags"):
        cve_list.extend([tag for tag in vt_data.get("tags", []) if tag.startswith("CVE-")])
    
    context = {
        "asn": vt_data.get("asn", ipinfo_data.get("org", "").split()[0] if ipinfo_data.get("org") else ""),
        "org": vt_data.get("as_owner", abuse_data.get("isp", ipinfo_data.get("org", "Unknown"))),
        "country": ipinfo_data.get("country", vt_data.get("country", abuse_data.get("countryCode", "Unknown"))),
        "city": ipinfo_data.get("city", "Unknown"),
        "region": ipinfo_data.get("region", vt_data.get("continent", "")),
        "location": ipinfo_data.get("loc", ""),
        "timezone": ipinfo_data.get("timezone", ""),
        "hostname": ipinfo_data.get("hostname", ""),
        "network": vt_data.get("network", "")
    }
    
    categories = []
    if abuse_data.get("abuseConfidenceScore", 0) > 50:
        categories.append("Malicious Activity")
    vt_reputation = vt_data.get("reputation", 0)
    if vt_reputation < -10:
        categories.append("Bad Reputation")
    
    # Check VirusTotal malicious detections - data is already flattened
    vt_malicious = vt_data.get("malicious", 0)
    vt_suspicious = vt_data.get("suspicious", 0)
    vt_harmless = vt_data.get("harmless", 0)
    vt_undetected = vt_data.get("undetected", 0)
    
    if vt_malicious > 5:
        categories.append("Detected as Malicious")
    
    # Check for CVEs
    if cve_list:
        categories.append("Known Vulnerabilities")
    
    if abuse_data.get("totalReports", 0) > 10:
        categories.append("Reported Abuse")
    
    if not categories:
        categories.append("Low Risk")
    
    related = {
        "domains": [],
        "urls": [],
        "hostnames": [],
        "cves": cve_list
    }
    
    evidence = {
        "abuseipdb": {
            "confidence_score": abuse_data.get("abuseConfidenceScore", 0),
            "total_reports": abuse_data.get("totalReports", 0),
            "last_reported": abuse_data.get("lastReportedAt", ""),
            "is_whitelisted": abuse_data.get("isWhitelisted", False),
            "usage_type": abuse_data.get("usageType", "Unknown")
        },
        "virustotal": {
            "reputation": vt_reputation,
            "analysis_stats": {
                "malicious": vt_malicious,
                "suspicious": vt_suspicious,
                "harmless": vt_harmless,
                "undetected": vt_undetected
            },
            "total_votes": vt_data.get("total_votes", 0),
            "tags": vt_data.get("tags", []),
            "cves": cve_list,
            "whois": vt_data.get("whois", "")[:500] if vt_data.get("whois") else ""
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