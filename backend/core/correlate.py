from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


def correlate_threat_data(
    ip: str,
    abuseipdb: Dict[str, Any],
    virustotal: Dict[str, Any],
    otx: Dict[str, Any],
    ipinfo: Dict[str, Any],
    greynoise: Dict[str, Any] = None,
    shodan: Dict[str, Any] = None,
    censys: Dict[str, Any] = None,
    passive_dns: Dict[str, Any] = None
) -> Dict[str, Any]:
    abuse_data = abuseipdb.get("data", {})
    vt_data = virustotal.get("data", {})
    otx_data = otx.get("data", {})
    ipinfo_data = ipinfo.get("data", {})
    greynoise_data = greynoise.get("data", {}) if greynoise else {}
    shodan_data = shodan.get("data", {}) if shodan else {}
    censys_data = censys.get("data", {}) if censys else {}
    passive_dns_data = passive_dns.get("data", {}) if passive_dns else {}
    
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
    
    # GreyNoise classification
    gn_classification = greynoise_data.get("classification", "unknown")
    if gn_classification == "malicious":
        categories.append("Known Malicious Actor")
    elif gn_classification == "benign":
        categories.append("Known Benign Service")
    
    vt_reputation = vt_data.get("reputation", 0)
    if vt_reputation < -10:
        categories.append("Bad Reputation")
    
    # Check OTX malicious detections (primary threat source)
    otx_last_analysis = otx_data.get("last_analysis_stats", {})
    otx_malicious = otx_last_analysis.get("malicious", 0)
    otx_suspicious = otx_last_analysis.get("suspicious", 0)
    otx_harmless = otx_last_analysis.get("harmless", 0)
    otx_undetected = otx_last_analysis.get("undetected", 0)
    
    if otx_malicious > 5:
        categories.append("Detected as Malicious")
    
    # Shodan vulnerabilities
    shodan_vulns = shodan_data.get("vulns", [])
    if shodan_vulns:
        categories.append("Known Vulnerabilities")
    
    # Check for CVEs
    if cve_list or shodan_vulns:
        if "Known Vulnerabilities" not in categories:
            categories.append("Known Vulnerabilities")
    
    if abuse_data.get("totalReports", 0) > 10:
        categories.append("Reported Abuse")
    
    # Passive DNS suspicious domains
    if passive_dns_data.get("suspicious_keywords"):
        categories.append("Suspicious Domain History")
    
    if not categories:
        categories.append("Low Risk")
    
    related = {
        "domains": [d.get("domain", "") for d in passive_dns_data.get("associated_domains", [])[:10]] if passive_dns_data.get("associated_domains") else [],
        "urls": [],
        "hostnames": [ipinfo_data.get("hostname", "")] if ipinfo_data.get("hostname") else [],
        "cves": cve_list + shodan_vulns,
        "threat_groups": otx_data.get("threat_groups", [])  # Use OTX threat groups
    }
    
    # Extract threat group info from GreyNoise tags and VT tags
    threat_groups = []
    gn_tags = greynoise_data.get("tags", [])
    vt_tags = vt_data.get("tags", [])
    
    # Common APT/threat group indicators
    threat_indicators = ["apt", "lazarus", "fancy bear", "cozy bear", "apt28", "apt29", "turla", "sandworm", "carbanak", "fin7", "emotet", "trickbot", "mirai"]
    
    for tag in gn_tags + vt_tags:
        tag_lower = tag.lower()
        for indicator in threat_indicators:
            if indicator in tag_lower and tag not in threat_groups:
                threat_groups.append(tag)
    
    related["threat_groups"] = threat_groups
    
    evidence = {
        "abuseipdb": {
            "confidence_score": abuse_data.get("abuseConfidenceScore", 0),
            "total_reports": abuse_data.get("totalReports", 0),
            "last_reported": abuse_data.get("lastReportedAt", ""),
            "is_whitelisted": abuse_data.get("isWhitelisted", False),
            "usage_type": abuse_data.get("usageType", "Unknown"),
            "reports": abuse_data.get("reports", [])  # Include detailed attack reports
        },
        "virustotal": {
            "reputation": otx_data.get("reputation", 0),
            "analysis_stats": {
                "malicious": otx_malicious,
                "suspicious": otx_suspicious,
                "harmless": otx_harmless,
                "undetected": otx_undetected
            },
            "total_votes": otx_data.get("total_votes", 0),
            "tags": otx_data.get("tags", []),
            "cves": cve_list,
            "whois": otx_data.get("whois", "")[:500] if otx_data.get("whois") else ""
        },
        "otx": {
            "reputation": otx_data.get("reputation"),
            "pulse_count": otx_data.get("pulse_count", 0),
            "pulses": otx_data.get("pulses", []),
            "threat_groups": otx_data.get("threat_groups", []),
            "malware_families": otx_data.get("malware_families", []),
            "target_industries": otx_data.get("industries", []),
            "country": otx_data.get("country_name", ""),
            "asn": otx_data.get("asn", ""),
            "false_positives": otx_data.get("false_positives", [])
        },
        # Include a source flag so callers know the data is from OTX
        "virustotal_source": "otx",
        "ipinfo": {
            "geolocation": context["location"],
            "organization": context["org"],
            "hostname": context["hostname"],
            "postal_code": ipinfo_data.get("postal", "")
        },
        "greynoise": {
            "classification": gn_classification,
            "actor": greynoise_data.get("actor", ""),
            "tags": gn_tags,
            "first_seen": greynoise_data.get("first_seen", ""),
            "last_seen": greynoise_data.get("last_seen", ""),
            "riot": greynoise_data.get("riot", False)
        },
        "shodan": {
            "ports": shodan_data.get("ports", []),
            "services": shodan_data.get("services", []),
            "vulns": shodan_vulns,
            "hostnames": shodan_data.get("hostnames", []),
            "last_update": shodan_data.get("last_update", "")
        },
        "censys": {
            "services": censys_data.get("services", [])[:5] if censys_data.get("services") else [],  # Limit to 5
            "certificates": censys_data.get("certificates", [])[:3] if censys_data.get("certificates") else [],  # Limit to 3
            "autonomous_system": censys_data.get("autonomous_system", {}),
            "operating_system": censys_data.get("operating_system", {}),
            "last_updated": censys_data.get("last_updated_at", "")
        },
        "passive_dns": {
            "total_domains": passive_dns_data.get("total_domains", 0),
            "associated_domains": passive_dns_data.get("associated_domains", [])[:10],  # Limit to 10
            "suspicious_keywords": passive_dns_data.get("suspicious_keywords", [])
        }
    }
    
    return {
        "ip": ip,
        "context": context,
        "categories": categories,
        "related": related,
        "evidence": evidence
    }