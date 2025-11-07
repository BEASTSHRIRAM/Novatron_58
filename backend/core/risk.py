from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)

def _safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def _clip01(x: float) -> float:
    return max(0.0, min(1.0, x))

def calculate_risk_score(
    abuseipdb: Dict[str, Any],
    otx: Optional[Dict[str, Any]] = None,             # AlienVault OTX – PRIMARY threat intelligence source
    ipinfo: Optional[Dict[str, Any]] = None,
    greynoise: Optional[Dict[str, Any]] = None,       # GN Community is free-limited
    shodan: Optional[Dict[str, Any]] = None,          # often paid – optional
    censys: Optional[Dict[str, Any]] = None,          # limited free – optional
    passive_dns: Optional[Dict[str, Any]] = None,     # CIRCL pDNS can be free
    threatfox: Optional[Dict[str, Any]] = None        # Abuse.ch ThreatFox – free
) -> Dict[str, Any]:
    """
    Risk score normalized to 0..100.
    We compute per-source subscores in 0..100, then weight them.
    Weights are dynamically normalized across PRESENT sources so totals remain coherent without VT/Shodan.
    """

    # ---- Extract raw source metrics safely ----
    abuse = (abuseipdb or {}).get("data", {})
    info = (ipinfo or {}).get("data", {})
    gn = (greynoise or {}).get("data", {})
    sh = (shodan or {}).get("data", {})
    cz = (censys or {}).get("data", {})
    pdns = (passive_dns or {}).get("data", {})
    otx_data = (otx or {}).get("data", {})  # e.g., {'pulse_info': {'count': int, ...}}
    tf = (threatfox or {}).get("data", {})  # often list-like results; we’ll handle flexibly

    rationale: List[str] = []

    # ---- Build per-source subscores in [0..100] ----
    subscores = {}

    # AbuseIPDB (strong signal, free) - USE RAW VALUES
    abuse_conf = _safe_int(abuse.get("abuseConfidenceScore", 0))
    abuse_reports = _safe_int(abuse.get("totalReports", 0))
    abuse_sub = abuse_conf  # Direct confidence score, no modifications
    if abuse_reports > 20:
        rationale.append(f"Multiple abuse reports ({abuse_reports})")
    if abuse_conf >= 75:
        rationale.append(f"High abuse confidence score ({abuse_conf}%)")
    elif abuse_conf >= 50:
        rationale.append(f"Moderate abuse confidence ({abuse_conf}%)")
    subscores["abuseipdb"] = abuse_sub

    # OTX (free): pulses indicate community-validated sightings - USE RAW PULSE COUNT
    pulse_count = _safe_int(otx_data.get("pulse_count", 0))
    # Use raw pulse count directly (each pulse = 5 points, cap at 80)
    otx_pulse_sub = min(80, pulse_count * 5) if pulse_count > 0 else 0
    # Use raw pulse count directly (each pulse = 5 points, cap at 80)
    otx_pulse_sub = min(80, pulse_count * 5) if pulse_count > 0 else 0
    if pulse_count > 0:
        rationale.append(f"OTX pulses associated ({pulse_count})")
    if otx_pulse_sub > 0:
        subscores["otx"] = otx_pulse_sub

    # ThreatFox (free): number of IOCs tied to the IP/domain/hash - USE RAW COUNT
    tf_results = tf.get("results") or tf.get("ioc") or tf.get("items") or []
    try:
        tf_count = len(tf_results)
    except TypeError:
        tf_count = _safe_int(tf.get("count", 0))
    # Use raw count directly (each IOC = 10 points, cap at 100)
    tf_sub = min(100, tf_count * 10)
    if tf_count > 0:
        rationale.append(f"ThreatFox IOCs associated ({tf_count})")
    if tf_sub > 0:
        subscores["threatfox"] = tf_sub

    # OTX (AlienVault) - USE RAW REPUTATION VALUE (no calculations)
    otx_last_analysis = otx_data.get("last_analysis_stats", {})
    otx_mal = _safe_int(otx_last_analysis.get("malicious", 0))
    otx_susp = _safe_int(otx_last_analysis.get("suspicious", 0))
    otx_rep_raw = otx_data.get("reputation")
    otx_rep = _safe_int(otx_rep_raw) if otx_rep_raw is not None else None
    
    # Use raw OTX reputation directly - convert negative reputation to positive risk score
    otx_sub = 0
    if otx_rep is not None:
        if otx_rep < 0:
            # Negative reputation = risk (convert -100 to +100 scale)
            otx_sub = min(100, abs(otx_rep))
            rationale.append(f"OTX reputation score: {otx_rep}")
    
    if otx_sub > 0:
        subscores["otx_reputation"] = otx_sub

    # Passive DNS (free if using CIRCL): suspicious keywords / flux can be a risk hint
    suspicious_keywords = pdns.get("suspicious_keywords", []) or []
    pdns_sub = min(100, len(suspicious_keywords) * 15)  # heavier weight per hit
    if suspicious_keywords:
        rationale.append("Suspicious passive-DNS associations: " +
                         ", ".join(map(str, suspicious_keywords[:3])))
    if pdns_sub > 0:
        subscores["passivedns"] = pdns_sub

    # GreyNoise (community free): classification
    gn_class = (gn.get("classification") or gn.get("noise") or "unknown")
    gn_sub = 0
    if isinstance(gn_class, str) and gn_class.lower() == "malicious":
        gn_sub = 60
        rationale.append("Classified as malicious by GreyNoise")
    elif isinstance(gn_class, str) and gn_class.lower() == "benign":
        gn_sub = -40  # negative influence (subtract later)
        rationale.append("Classified as benign service by GreyNoise")
    if gn.get("riot"):
        # Known good service
        gn_sub = min(gn_sub, -60)
        rationale.append("Known legitimate service (GreyNoise RIOT)")
    # We'll apply gn_sub as an adjustment rather than an ordinary subscore.
    # (So it won't get normalized away if other sources are missing.)

    # IPInfo (free basic): hosting / data center hint
    usage_type = (abuse.get("usageType") or info.get("privacy", {}).get("vpn")) or ""
    hosting_hint = str(usage_type).lower()
    ipinfo_sub = 0
    if "hosting" in hosting_hint or "data center" in hosting_hint or hosting_hint is True:
        ipinfo_sub = 30
        rationale.append("Hosted in data center / VPN (higher risk profile)")
    if ipinfo_sub > 0:
        subscores["ipinfo"] = ipinfo_sub

    # Shodan (optional/paid): open ports as weak proxy for attack surface
    open_ports = sh.get("ports", []) if isinstance(sh.get("ports", []), list) else []
    shodan_sub = 0
    if open_ports:
        p = len(open_ports)
        if p > 10:
            shodan_sub = 40
            rationale.append(f"Excessive open ports ({p})")
        elif p > 5:
            shodan_sub = 20
            rationale.append(f"Multiple open ports ({p})")
    if shodan_sub > 0:
        subscores["shodan"] = shodan_sub

    # Censys (optional): CVEs on exposed services (if you have them)
    shodan_vulns = sh.get("vulns", []) if isinstance(sh.get("vulns", []), list) else []
    otx_cves = otx_data.get("cves", []) if isinstance(otx_data.get("cves", []), list) else []
    cz_vulns = cz.get("vulns", [])
    total_cves = len(otx_cves) + (len(shodan_vulns) if shodan_vulns else 0) + (len(cz_vulns) if isinstance(cz_vulns, list) else 0)
    cve_sub = min(100, total_cves * 15)
    if total_cves > 0:
        rationale.append(f"Associated with {total_cves} CVE(s)")
        subscores["cves"] = cve_sub

    # Whitelist reduction (AbuseIPDB)
    whitelisted = bool(abuse.get("isWhitelisted"))
    whitelist_adjust = -60 if whitelisted else 0
    if whitelisted:
        rationale.append("IP is whitelisted (reduced risk)")

    # ---- Dynamic weighting across present sources ----
    # Preferred source weights (sum to 1.0 conceptually)
    # Note: "otx" has replaced "virustotal" as the primary threat intelligence source
    preferred_weights = {
        "abuseipdb": 0.40,
        "otx": 0.25,           # Primary threat detection source (was virustotal, now OTX)
        "threatfox": 0.20,
        "passivedns": 0.10,
        "ipinfo": 0.05,
        "cves": 0.10,
        "shodan": 0.10,
    }

    # Keep only present sources, then normalize weights to 1.0
    present = list(subscores.keys())
    if not present:
        # No signals at all
        return {
            "score": 0,
            "label": "Minimal",
            "confidence": "Low",
            "rationale": ["No significant threats detected"],
            "breakdown": {
                "abuse_reputation": abuse_conf,
                "report_count": abuse_reports,
                "otx_pulses": pulse_count,
                "threatfox_iocs": tf_count,
                "otx_malicious_detections": otx_mal,
                "otx_reputation": otx_rep,
                "cve_count": total_cves,
                "greynoise_classification": gn_class,
                "shodan_open_ports": len(open_ports),
                "passive_dns_suspicious": len(suspicious_keywords),
                "whitelisted": whitelisted
            }
        }

    # Build normalized weights for present sources
    raw_sum = sum(preferred_weights.get(s, 0.05) for s in present)
    weights = {s: (preferred_weights.get(s, 0.05) / raw_sum) for s in present}

    # Weighted sum of subscores
    weighted = sum(_clip01(subscores[s] / 100.0) * weights[s] for s in present)
    score = int(round(_clip01(weighted) * 100))

    # GreyNoise and whitelist adjust in absolute points then clip
    score = max(0, min(100, score + gn_sub + whitelist_adjust))

    # ---- Labels / confidence ----
    if score >= 80:
        label, confidence = "Critical", "High"
    elif score >= 60:
        label, confidence = "High", "High"
    elif score >= 40:
        label, confidence = "Medium", "Medium"
    elif score >= 20:
        label, confidence = "Low", "Medium"
    else:
        label, confidence = "Minimal", "Low"

    if not rationale:
        rationale.append("No significant threats detected")

    return {
        "score": score,
        "label": label,
        "confidence": confidence,
        "rationale": rationale,
        "breakdown": {
            "abuse_reputation": abuse_conf,
            "report_count": abuse_reports,
            "otx_pulses": pulse_count,
            "threatfox_iocs": tf_count,
            "otx_malicious_detections": otx_mal,
            "otx_reputation": otx_rep,
            "cve_count": total_cves,
            "greynoise_classification": gn_class,
            "shodan_open_ports": len(open_ports),
            "passive_dns_suspicious": len(suspicious_keywords),
            "whitelisted": whitelisted
        }
    }
