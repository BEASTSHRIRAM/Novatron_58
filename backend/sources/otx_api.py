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
    elif reputation < -5:
        malicious_count += 15  # Moderately bad reputation
    elif reputation < 0:
        malicious_count += 8   # Slightly bad reputation
    
    # Factor 2: Pulses with ransomware, trojans, worms, botnets
    high_risk_keywords = [
        "ransomware", "trojan", "worm", "botnet", "backdoor", 
        "rootkit", "spyware", "keylogger", "cryptolocker", "petya", 
        "wannacry", "notpetya", "emotet", "trickbot", "malware"
    ]
    
    high_risk_pulse_count = 0
    for pulse in pulses:
        pulse_tags = [str(t).lower() for t in pulse.get("tags", [])]
        pulse_malware = [str(m).lower() for m in pulse.get("malware_families", [])]
        
        if any(keyword in tag for tag in pulse_tags for keyword in high_risk_keywords):
            malicious_count += 8
            high_risk_pulse_count += 1
        elif any(keyword in malware for malware in pulse_malware for keyword in high_risk_keywords):
            malicious_count += 8
            high_risk_pulse_count += 1
    
    # If there are pulses but none matched high-risk keywords, still add some malicious count
    if pulse_count > 0 and high_risk_pulse_count == 0:
        # Each pulse adds some suspicion even if not explicitly malware-related
        malicious_count += min(pulse_count * 3, 20)
    
    # Cap malicious at 70 (simulating ~70 vendors on VirusTotal)
    malicious_count = min(70, malicious_count)
    
    # ===== SUSPICIOUS COUNT ESTIMATION =====
    # Factor 1: Total pulse count (more pulses = more suspicious)
    if pulse_count >= 20:
        suspicious_count += 25
    elif pulse_count >= 10:
        suspicious_count += 20
    elif pulse_count >= 5:
        suspicious_count += 12
    elif pulse_count >= 1:
        suspicious_count += 8
    
    # Factor 2: Pulses with medium-risk keywords
    medium_risk_keywords = [
        "phishing", "spam", "scam", "exploit", "vulnerability",
        "command and control", "c&c", "c2", "ddos", "brute force",
        "malvertising", "adware", "pup", "scanning", "suspicious"
    ]
    
    for pulse in pulses:
        pulse_tags = [str(t).lower() for t in pulse.get("tags", [])]
        if any(keyword in tag for tag in pulse_tags for keyword in medium_risk_keywords):
            suspicious_count += 4
    
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
    
    # Ensure we always have some baseline vendors analyzed (minimum 30 if there's any data)
    current_total = malicious_count + suspicious_count + harmless_count
    if current_total > 0 and current_total < 30:
        # Add harmless vendors to reach minimum 30 total
        harmless_count += (30 - current_total)
    
    # If IP has pulses but low total, ensure we have realistic vendor counts
    if pulse_count > 0 and current_total < 50:
        # Add more vendors proportional to pulse count
        additional = min(20, pulse_count * 2)
        harmless_count += additional
    
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
    reputation_url = f"{OTX_BASE_URL}/{ip}/reputation"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # Fetch general info
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()
            
            # Try to fetch reputation separately if not in general response
            reputation_raw = result.get("reputation")
            if reputation_raw is None:
                try:
                    rep_response = await client.get(reputation_url, headers=headers)
                    if rep_response.status_code == 200:
                        rep_data = rep_response.json()
                        reputation_raw = rep_data.get("reputation", 0)
                        logger.info(f"OTX reputation from separate endpoint for {ip}: {reputation_raw}")
                except Exception as e:
                    logger.warning(f"Could not fetch OTX reputation separately: {e}")
                    reputation_raw = 0
            
            # Log the full response for debugging
            logger.info(f"=== OTX API RESPONSE FOR {ip} ===")
            logger.info(f"Pulse Count: {result.get('pulse_info', {}).get('count', 0)}")
            logger.info(f"Reputation (raw): {result.get('reputation')}")
            logger.info(f"Sections available: {result.get('sections', [])}")
            logger.info(f"Type indicator: {result.get('type_title', 'N/A')}")
            logger.debug("Full OTX response: %s", result)

            # Extract pulse info
            pulse_info = result.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = pulse_info.get("count", 0)
            
            # Log pulse details
            if pulses:
                logger.info(f"✓ OTX found {len(pulses)} pulses for {ip}")
                for i, pulse in enumerate(pulses[:3]):  # Log first 3 pulses
                    logger.info(f"  Pulse {i+1}: {pulse.get('name', 'unnamed')[:50]}, tags={pulse.get('tags', [])[:5]}")
            else:
                logger.info(f"✗ No threat pulses found for {ip} in OTX database")
            
            # Extract threat groups and adversaries from pulses directly
            adversaries = set()
            malware_families = set()
            industries = set()
            
            # Extract from each pulse
            for pulse in pulses:
                # Get adversary from pulse
                if pulse.get("adversary"):
                    adversaries.add(pulse.get("adversary"))
                
                # Get malware families from pulse
                pulse_malware = pulse.get("malware_families", [])
                if pulse_malware:
                    for mf in pulse_malware:
                        if isinstance(mf, dict):
                            malware_families.add(mf.get("display_name") or mf.get("name", ""))
                        else:
                            malware_families.add(str(mf))
                
                # Get industries from pulse
                pulse_industries = pulse.get("industries", [])
                if pulse_industries:
                    industries.update(pulse_industries)
                
                # Also check in tags for threat actor names
                pulse_tags = pulse.get("tags", [])
                for tag in pulse_tags:
                    tag_lower = str(tag).lower()
                    # Common APT and threat actor indicators
                    if any(keyword in tag_lower for keyword in ["apt", "lazarus", "fancy bear", "cozy bear", "carbanak"]):
                        adversaries.add(tag)
            
            # Also extract from related data structure (if exists)
            related_data = pulse_info.get("related", {})
            
            # From AlienVault data
            av_data = related_data.get("alienvault", {})
            if av_data.get("adversary"):
                adversaries.update(av_data.get("adversary", []))
            if av_data.get("malware_families"):
                malware_families.update(av_data.get("malware_families", []))
            if av_data.get("industries"):
                industries.update(av_data.get("industries", []))
            
            # From other sources
            other_data = related_data.get("other", {})
            if other_data.get("adversary"):
                adversaries.update(other_data.get("adversary", []))
            if other_data.get("malware_families"):
                malware_families.update(other_data.get("malware_families", []))
            if other_data.get("industries"):
                industries.update(other_data.get("industries", []))
            
            # Log extracted threat intelligence
            logger.info(f"OTX extracted for {ip}: adversaries={len(adversaries)}, malware={len(malware_families)}, industries={len(industries)}")

            # Use actual raw values from OTX API - reputation score will be calculated from aggregated risk
            # Handle None reputation - convert to 0 instead of None
            reputation = reputation_raw if reputation_raw is not None else 0
            logger.info(f"OTX raw reputation for {ip}: {reputation}")
            
            false_positives = result.get("false_positive", [])
            validation = result.get("validation", [])
            
            # Return raw OTX data without any estimation
            return {
                "source": "otx",
                "data": {
                    "reputation": reputation,  # Raw OTX reputation (can be negative, 0, or positive)
                    "reputation_score": 0,  # Will be calculated from aggregated risk score in main.py
                    "indicator": result.get("indicator"),
                    "pulse_count": pulse_count,
                    "pulses": pulses,
                    "malicious": 0,  # OTX doesn't provide vendor detection counts
                    "suspicious": 0,  # OTX doesn't provide vendor detection counts
                    "harmless": 0,   # OTX doesn't provide vendor detection counts
                    "undetected": 0,
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
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
