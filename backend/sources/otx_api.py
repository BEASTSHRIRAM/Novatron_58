import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"


def _estimate_detection_counts(reputation: int, pulse_count: int, pulses: list, 
                               false_positives: list, validation: list) -> tuple:
    """
    Estimate malicious/suspicious/harmless detection counts based on OTX threat indicators.
    
    Algorithm:
    - Malicious: Based on negative reputation and pulses with high-risk malware/ransomware
    - Suspicious: Based on number of pulses and their risk level
    - Harmless: Based on false positives and positive validation
    - Total simulates ~70 vendor detections (similar to VirusTotal's ~70 vendors)
    
    Returns:
        tuple: (malicious_count, suspicious_count, harmless_count)
    """
    
    malicious_count = 0
    suspicious_count = 0
    harmless_count = 0
    
    # ===== MALICIOUS COUNT ESTIMATION =====
    # Factor 1: Reputation score (negative = more malicious)
    if reputation < -30:
        malicious_count += 40  # Very bad reputation
    elif reputation < -15:
        malicious_count += 25  # Bad reputation
    elif reputation < 0:
        malicious_count += 10  # Slightly bad reputation
    
    # Factor 2: Pulses with ransomware, trojans, worms, botnets
    high_risk_keywords = [
        "ransomware", "trojan", "worm", "botnet", "backdoor", 
        "rootkit", "spyware", "keylogger", "cryptolocker", "petya", 
        "wannacry", "notpetya", "emotet", "trickbot"
    ]
    
    for pulse in pulses:
        pulse_tags = [str(t).lower() for t in pulse.get("tags", [])]
        pulse_malware = [str(m).lower() for m in pulse.get("malware_families", [])]
        
        if any(keyword in tag for tag in pulse_tags for keyword in high_risk_keywords):
            malicious_count += 8
        elif any(keyword in malware for malware in pulse_malware for keyword in high_risk_keywords):
            malicious_count += 8
    
    # Cap malicious at 70 (simulating ~70 vendors on VirusTotal)
    malicious_count = min(70, malicious_count)
    
    # ===== SUSPICIOUS COUNT ESTIMATION =====
    # Factor 1: Total pulse count (more pulses = more suspicious)
    if pulse_count >= 10:
        suspicious_count += 20
    elif pulse_count >= 5:
        suspicious_count += 12
    elif pulse_count >= 1:
        suspicious_count += 5
    
    # Factor 2: Pulses with medium-risk keywords
    medium_risk_keywords = [
        "phishing", "spam", "scam", "exploit", "vulnerability",
        "command and control", "c&c", "ddos", "brute force",
        "malvertising", "adware", "pup"
    ]
    
    for pulse in pulses:
        pulse_tags = [str(t).lower() for t in pulse.get("tags", [])]
        if any(keyword in tag for tag in pulse_tags for keyword in medium_risk_keywords):
            suspicious_count += 3
    
    # Cap suspicious at 30
    suspicious_count = min(30, suspicious_count)
    
    # ===== HARMLESS COUNT ESTIMATION =====
    # False positives indicate harmless detections
    harmless_count = len(false_positives)
    
    # Add positive validations
    for validation_item in validation:
        if isinstance(validation_item, dict):
            # Some validation items might indicate legitimacy
            harmless_count += 1
    
    # If there's positive reputation, add to harmless
    if reputation > 20:
        harmless_count += reputation // 10  # Small boost for high reputation
    
    # Ensure total doesn't exceed ~70 (VirusTotal norm)
    total = malicious_count + suspicious_count + harmless_count
    if total > 70:
        # Normalize to keep ratio but total ~70
        factor = 70 / total if total > 0 else 1
        malicious_count = int(malicious_count * factor)
        suspicious_count = int(suspicious_count * factor)
        harmless_count = int(harmless_count * factor)
    
    return malicious_count, suspicious_count, harmless_count


async def get_otx_data(ip: str) -> Dict[str, Any]:
    """
    Query OTX (AlienVault Open Threat Exchange) for IP reputation and threat data.
    Returns reputation, pulses, threat groups, and indicators.
    """

    if not OTX_API_KEY:
        logger.warning("OTX API key not configured; cannot fetch live data.")
        return {
            "source": "none",
            "data": {"error": "API key missing; live OTX lookup unavailable."}
        }

    headers = {"X-OTX-API-KEY": OTX_API_KEY, "Accept": "application/json"}
    url = f"{OTX_BASE_URL}/{ip}/general"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()
            logger.debug("OTX raw response for %s: %s", ip, result)

            # Extract pulse info
            pulse_info = result.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            
            # Extract threat groups and adversaries from related data
            related_data = pulse_info.get("related", {})
            adversaries = set()
            malware_families = set()
            industries = set()
            
            # From AlienVault data
            av_data = related_data.get("alienvault", {})
            adversaries.update(av_data.get("adversary", []))
            malware_families.update(av_data.get("malware_families", []))
            industries.update(av_data.get("industries", []))
            
            # From other sources
            other_data = related_data.get("other", {})
            adversaries.update(other_data.get("adversary", []))
            malware_families.update(other_data.get("malware_families", []))
            industries.update(other_data.get("industries", []))

            # Calculate threat detection counts based on OTX data using an estimation algorithm
            reputation = result.get("reputation", 0)
            pulse_count = pulse_info.get("count", 0)
            false_positives = result.get("false_positive", [])
            validation = result.get("validation", [])
            
            # Estimate detection counts based on threat indicators
            malicious_count, suspicious_count, harmless_count = _estimate_detection_counts(
                reputation=reputation,
                pulse_count=pulse_count,
                pulses=pulses,
                false_positives=false_positives,
                validation=validation
            )

            # Return OTX threat intelligence
            return {
                "source": "otx",
                "data": {
                    "reputation": reputation,
                    "indicator": result.get("indicator"),
                    "pulse_count": pulse_count,
                    "pulses": pulses,
                    "malicious": malicious_count,
                    "suspicious": suspicious_count,
                    "harmless": harmless_count,
                    "undetected": 0,
                    "last_analysis_stats": {
                        "malicious": malicious_count,
                        "suspicious": suspicious_count,
                        "harmless": harmless_count,
                        "undetected": 0
                    },
                    "asn": result.get("asn"),
                    "country_code": result.get("country_code"),
                    "country_name": result.get("country_name"),
                    "city": result.get("city"),
                    "latitude": result.get("latitude"),
                    "longitude": result.get("longitude"),
                    "threat_groups": list(adversaries),
                    "malware_families": list(malware_families),
                    "industries": list(industries),
                    "false_positives": false_positives,
                    "validation": validation,
                    "sections": result.get("sections", []),
                },
            }

    except httpx.HTTPStatusError as e:
        logger.error(f"OTX HTTP error {e.response.status_code}: {e.response.text}")
        return {
            "source": "otx",
            "data": {"error": f"HTTP {e.response.status_code} from OTX"},
        }
    except Exception as e:
        logger.error(f"OTX fetch error: {e}")
        return {"source": "otx", "data": {"error": str(e)}}
