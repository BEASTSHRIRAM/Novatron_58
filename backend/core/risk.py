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
    
    # VirusTotal detection (40% weight)
    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)
    
    if malicious > 5:
        score += 30
        rationale.append(f"High malicious detections ({malicious} engines)")
    elif malicious > 0:
        score += 15
        rationale.append(f"Malicious detections ({malicious} engines)")
    
    if suspicious > 3:
        score += 10
        rationale.append(f"Suspicious detections ({suspicious} engines)")
    
    reputation = vt_data.get("reputation", 0)
    if reputation < -20:
        score += 15
        rationale.append(f"Very poor reputation score ({reputation})")
    
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
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "report_count": total_reports
        }
    }