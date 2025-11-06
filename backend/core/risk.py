from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


def calculate_risk_score(
    abuseipdb: Dict[str, Any],
    virustotal: Dict[str, Any],
    ipinfo: Dict[str, Any],
    greynoise: Dict[str, Any] = None,
    shodan: Dict[str, Any] = None,
    censys: Dict[str, Any] = None,
    passive_dns: Dict[str, Any] = None
) -> Dict[str, Any]:
    score = 0
    rationale = []
    
    abuse_data = abuseipdb.get("data", {})
    vt_data = virustotal.get("data", {})
    ipinfo_data = ipinfo.get("data", {})
    greynoise_data = greynoise.get("data", {}) if greynoise else {}
    shodan_data = shodan.get("data", {}) if shodan else {}
    censys_data = censys.get("data", {}) if censys else {}
    passive_dns_data = passive_dns.get("data", {}) if passive_dns else {}
    
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
    
    # Extract CVEs from tags and Shodan
    cve_count = len([tag for tag in vt_data.get("tags", []) if tag.startswith("CVE-")])
    shodan_vulns = shodan_data.get("vulns", [])
    total_cves = cve_count + len(shodan_vulns)
    
    if total_cves > 0:
        score += min(total_cves * 10, 20)
        rationale.append(f"Associated with {total_cves} CVE(s)")
    
    # GreyNoise classification scoring
    gn_classification = greynoise_data.get("classification", "unknown")
    if gn_classification == "malicious":
        score += 20
        rationale.append("Classified as malicious by GreyNoise")
    elif gn_classification == "benign":
        score = max(0, score - 15)
        rationale.append("Classified as benign service by GreyNoise")
    
    # Check if IP is in GreyNoise RIOT (known good)
    if greynoise_data.get("riot"):
        score = max(0, score - 20)
        rationale.append("Known legitimate service (GreyNoise RIOT)")
    
    # Shodan open ports risk
    open_ports = shodan_data.get("ports", [])
    if len(open_ports) > 10:
        score += 10
        rationale.append(f"Excessive open ports ({len(open_ports)})")
    elif len(open_ports) > 5:
        score += 5
        rationale.append(f"Multiple open ports ({len(open_ports)})")
    
    # Passive DNS suspicious domains
    suspicious_keywords = passive_dns_data.get("suspicious_keywords", [])
    if suspicious_keywords:
        score += min(len(suspicious_keywords) * 5, 15)
        rationale.append(f"Associated with suspicious domains: {', '.join(suspicious_keywords[:3])}")
    
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
            "cve_count": total_cves,
            "report_count": total_reports,
            "greynoise_classification": gn_classification,
            "shodan_open_ports": len(open_ports),
            "passive_dns_suspicious": len(suspicious_keywords)
        }
    }