from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


def calculate_risk_score(
    abuseipdb: Dict[str, Any],
    shodan: Dict[str, Any],
    ipinfo: Dict[str, Any]
) -> Dict[str, Any]:
    score = 0
    rationale = []
    
    abuse_data = abuseipdb.get("data", {})
    shodan_data = shodan.get("data", {})
    ipinfo_data = ipinfo.get("data", {})
    
    # AbuseIPDB reputation (40% weight)
    abuse_score = abuse_data.get("abuseConfidenceScore", 0)
    if abuse_score > 0:
        abuse_weight = abuse_score * 0.4
        score += abuse_weight
        if abuse_score > 75:
            rationale.append(f"High abuse confidence score ({abuse_score}%)")
        elif abuse_score > 50:
            rationale.append(f"Moderate abuse reports ({abuse_score}%)")
    
    total_reports = abuse_data.get("totalReports", 0)
    if total_reports > 20:
        score += 10
        rationale.append(f"Multiple abuse reports ({total_reports})")
    
    # Shodan exposure (40% weight)
    ports = shodan_data.get("ports", [])
    if len(ports) > 10:
        score += 20
        rationale.append(f"High port exposure ({len(ports)} open ports)")
    elif len(ports) > 5:
        score += 10
        rationale.append(f"Moderate port exposure ({len(ports)} open ports)")
    
    vulns = shodan_data.get("vulns", [])
    if len(vulns) > 0:
        vuln_score = min(len(vulns) * 10, 20)
        score += vuln_score
        rationale.append(f"Known vulnerabilities detected ({len(vulns)} CVEs)")
    
    # IPInfo context (20% weight)
    usage_type = abuse_data.get("usageType", "")
    if "hosting" in usage_type.lower() or "data center" in usage_type.lower():
        score += 5
        rationale.append("Hosted in data center (higher risk profile)")
    
    if abuse_data.get("isWhitelisted"):
        score = max(0, score - 30)
        rationale.append("IP is whitelisted (reduced risk)")
    
    # Cap score at 100
    score = min(int(score), 100)
    
    # Determine label
    if score >= 80:
        label = "Critical"
        confidence = "High"
    elif score >= 60:
        label = "High"
        confidence = "High"
    elif score >= 40:
        label = "Medium"
        confidence = "Medium"
    elif score >= 20:
        label = "Low"
        confidence = "Medium"
    else:
        label = "Minimal"
        confidence = "Low"
    
    if not rationale:
        rationale.append("No significant threats detected")
    
    return {
        "score": score,
        "label": label,
        "confidence": confidence,
        "rationale": rationale,
        "breakdown": {
            "abuse_reputation": abuse_score,
            "exposure_level": len(ports),
            "vulnerability_count": len(vulns),
            "report_count": total_reports
        }
    }