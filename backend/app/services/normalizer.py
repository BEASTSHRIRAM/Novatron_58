"""
Threat Intelligence Data Normalization & Correlation Service
Unifies data from multiple threat feeds into standardized schema
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import re
import logging

logger = logging.getLogger(__name__)


def safe_int(value: Any, default: int = 0) -> int:
    """Convert to integer safely"""
    if value is None or value == "":
        return default
    try:
        if isinstance(value, str):
            value = value.replace(",", "").strip()
        return int(float(value))
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert to float safely"""
    if value is None or value == "":
        return default
    try:
        if isinstance(value, str):
            value = value.replace(",", "").strip()
        return float(value)
    except (ValueError, TypeError):
        return default


def normalize_timestamp(value: Any) -> Optional[str]:
    """Convert various timestamp formats to ISO 8601"""
    if not value:
        return None
    
    try:
        if isinstance(value, datetime):
            return value.isoformat()
        
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        
        if isinstance(value, str):
            value = value.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(value)
                return dt.isoformat()
            except ValueError:
                pass
        
        return None
    except Exception as e:
        logger.debug(f"Timestamp normalization failed: {e}")
        return None


def normalize_category(category: str) -> str:
    """Normalize category to unified taxonomy"""
    if not category:
        return "unknown"
    
    cat_lower = category.lower().strip()
    
    # Category mapping
    if any(x in cat_lower for x in ["malware", "trojan", "virus", "worm"]):
        return "malware"
    elif any(x in cat_lower for x in ["phish", "fraud"]):
        return "phishing"
    elif any(x in cat_lower for x in ["spam", "email spam", "web spam"]):
        return "spam"
    elif any(x in cat_lower for x in ["ddos", "dos", "ping of death"]):
        return "ddos"
    elif any(x in cat_lower for x in ["brute", "ssh attack", "ftp brute"]):
        return "brute_force"
    elif any(x in cat_lower for x in ["scan", "port scan", "vulnerability"]):
        return "port_scan"
    elif any(x in cat_lower for x in ["exploit", "sql injection", "hacking"]):
        return "exploit"
    elif any(x in cat_lower for x in ["botnet", "bot", "bad web bot"]):
        return "botnet"
    elif "vpn" in cat_lower:
        return "vpn"
    elif "proxy" in cat_lower:
        return "proxy"
    elif "tor" in cat_lower:
        return "tor"
    elif any(x in cat_lower for x in ["dns compromise", "dns poison"]):
        return "dns_abuse"
    
    return "suspicious"


def create_unified_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform evidence from multiple feeds into unified schema
    
    Args:
        evidence: Raw evidence dict with abuseipdb, virustotal, ipinfo keys
    
    Returns:
        Unified evidence structure
    """
    abuse_data = evidence.get("abuseipdb", {})
    vt_data = evidence.get("virustotal", {})
    ipinfo_data = evidence.get("ipinfo", {})
    greynoise_data = evidence.get("greynoise", {})
    shodan_data = evidence.get("shodan", {})
    
    # Unified threat metrics
    unified = {
        "threat_score": {
            "abuse_confidence": safe_float(abuse_data.get("confidence_score", 0)),
            "vt_reputation": safe_int(vt_data.get("reputation", 0)),
            "total_detections": safe_int(vt_data.get("analysis_stats", {}).get("malicious", 0))
        },
        
        "abuse_history": {
            "total_reports": safe_int(abuse_data.get("total_reports", 0)),
            "last_reported": normalize_timestamp(abuse_data.get("last_reported")),
            "is_whitelisted": abuse_data.get("is_whitelisted", False),
            "usage_type": abuse_data.get("usage_type", "Unknown"),
            "attack_reports": abuse_data.get("reports", [])
        },
        
        "malware_analysis": {
            "malicious_detections": safe_int(vt_data.get("analysis_stats", {}).get("malicious", 0)),
            "suspicious_detections": safe_int(vt_data.get("analysis_stats", {}).get("suspicious", 0)),
            "harmless_detections": safe_int(vt_data.get("analysis_stats", {}).get("harmless", 0)),
            "undetected": safe_int(vt_data.get("analysis_stats", {}).get("undetected", 0)),
            "reputation_score": safe_int(vt_data.get("reputation", 0)),
            "threat_tags": vt_data.get("tags", []),
            "cves": vt_data.get("cves", [])
        },
        
        "geolocation": {
            "location": ipinfo_data.get("geolocation", "Unknown"),
            "organization": ipinfo_data.get("organization", "Unknown"),
            "hostname": ipinfo_data.get("hostname", "N/A"),
            "postal_code": ipinfo_data.get("postal_code", "")
        },
        
        "threat_classification": {
            "greynoise_status": greynoise_data.get("classification", "unknown"),
            "actor": greynoise_data.get("actor", "Unknown"),
            "tags": greynoise_data.get("tags", []),
            "first_seen": normalize_timestamp(greynoise_data.get("first_seen")),
            "last_seen": normalize_timestamp(greynoise_data.get("last_seen")),
            "is_riot": greynoise_data.get("riot", False)
        },
        
        "infrastructure": {
            "open_ports": shodan_data.get("ports", []),
            "services": shodan_data.get("services", []),
            "vulnerabilities": shodan_data.get("vulns", []),
            "hostnames": shodan_data.get("hostnames", []),
            "last_update": normalize_timestamp(shodan_data.get("last_update"))
        },
        
        "categories": []
    }
    
    # Aggregate categories from all sources
    categories = set()
    
    # From AbuseIPDB reports
    for report in abuse_data.get("reports", []):
        for cat in report.get("categories", []):
            if isinstance(cat, str):
                categories.add(normalize_category(cat))
    
    # From VirusTotal tags
    for tag in vt_data.get("tags", []):
        categories.add(normalize_category(tag))
    
    # From GreyNoise tags
    for tag in greynoise_data.get("tags", []):
        categories.add(normalize_category(tag))
    
    # Add classification
    if greynoise_data.get("classification"):
        categories.add(normalize_category(greynoise_data["classification"]))
    
    unified["categories"] = sorted(list(categories))
    
    return unified
