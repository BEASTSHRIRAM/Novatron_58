from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


def calculate_risk_score(
    abuseipdb: Dict[str, Any],
    virustotal: Dict[str, Any],
    ipinfo: Dict[str, Any]
) -> Dict[str, Any]:
    score = 0
    rationale = []
    
    abuse_data = abuseipdb.get("data", {})
    vt_data = virustotal.get("data", {})
    ipinfo_data = ipinfo.get("data", {})
    
    # AbuseIPDB scoring (40% weight)
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
    
    # VirusTotal scoring (40% weight) - data is already flattened
    vt_malicious = vt_data.get("malicious", 0)
    vt_suspicious = vt_data.get("suspicious", 0)
    
    if vt_malicious > 0:
        vt_score = min(vt_malicious * 5, 40)  # Max 40 points
        score += vt_score
        rationale.append(f"Detected as malicious by {vt_malicious} vendors")
    
    if vt_suspicious > 0:
        score += min(vt_suspicious * 2, 10)
        rationale.append(f"Flagged as suspicious by {vt_suspicious} vendors")
    
    # VirusTotal reputation
    vt_reputation = vt_data.get("reputation", 0)
    if vt_reputation < -20:
        score += 20
        rationale.append(f"Very bad reputation score ({vt_reputation})")
    elif vt_reputation < -10:
        score += 10
        rationale.append(f"Bad reputation score ({vt_reputation})")
    
    # Extract CVEs from tags
    cve_count = len([tag for tag in vt_data.get("tags", []) if tag.startswith("CVE-")])
    if cve_count > 0:
        score += min(cve_count * 10, 20)
        rationale.append(f"Associated with {cve_count} CVE(s)")
    
    # Context-based scoring (20% weight)
    usage_type = abuse_data.get("usageType", "")
    if "hosting" in usage_type.lower() or "data center" in usage_type.lower():
        score += 5
        rationale.append("Hosted in data center (higher risk profile)")
    
    if abuse_data.get("isWhitelisted"):
        score = max(0, score - 30)
        rationale.append("IP is whitelisted (reduced risk)")

    score = min(int(score), 100)

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
            "vt_malicious_detections": vt_malicious,
            "vt_reputation": vt_reputation,
            "cve_count": cve_count,
            "report_count": total_reports
        }
    }