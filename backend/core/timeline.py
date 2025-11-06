from typing import Dict, Any, List
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


def generate_event_timeline(
    abuseipdb: Dict[str, Any],
    virustotal: Dict[str, Any],
    greynoise: Dict[str, Any],
    shodan: Dict[str, Any],
    passive_dns: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Generate chronological timeline of events from all threat intelligence sources
    Returns sorted list of events with timestamps, source, and description
    """
    events = []
    
    # Extract data
    abuse_data = abuseipdb.get("data", {})
    vt_data = virustotal.get("data", {})
    greynoise_data = greynoise.get("data", {}) if greynoise else {}
    shodan_data = shodan.get("data", {}) if shodan else {}
    passive_dns_data = passive_dns.get("data", {}) if passive_dns else {}
    
    # AbuseIPDB last reported
    if abuse_data.get("lastReportedAt"):
        try:
            events.append({
                "timestamp": abuse_data["lastReportedAt"],
                "source": "AbuseIPDB",
                "event_type": "abuse_report",
                "description": f"IP reported for abuse ({abuse_data.get('totalReports', 0)} total reports)",
                "severity": "high" if abuse_data.get("abuseConfidenceScore", 0) > 75 else "medium"
            })
        except Exception as e:
            logger.error(f"Error parsing AbuseIPDB timestamp: {e}")
    
    # VirusTotal last analysis
    if vt_data.get("last_analysis_date"):
        try:
            # Convert Unix timestamp to ISO format if needed
            timestamp = vt_data["last_analysis_date"]
            if isinstance(timestamp, int):
                timestamp = datetime.fromtimestamp(timestamp).isoformat()
            
            events.append({
                "timestamp": timestamp,
                "source": "VirusTotal",
                "event_type": "malware_scan",
                "description": f"Scanned by VirusTotal ({vt_data.get('malicious', 0)} malicious detections)",
                "severity": "high" if vt_data.get("malicious", 0) > 5 else "low"
            })
        except Exception as e:
            logger.error(f"Error parsing VirusTotal timestamp: {e}")
    
    # GreyNoise first seen
    if greynoise_data.get("first_seen"):
        try:
            events.append({
                "timestamp": greynoise_data["first_seen"],
                "source": "GreyNoise",
                "event_type": "first_observed",
                "description": f"First observed by GreyNoise (classification: {greynoise_data.get('classification', 'unknown')})",
                "severity": "high" if greynoise_data.get("classification") == "malicious" else "low"
            })
        except Exception as e:
            logger.error(f"Error parsing GreyNoise first_seen: {e}")
    
    # GreyNoise last seen
    if greynoise_data.get("last_seen"):
        try:
            events.append({
                "timestamp": greynoise_data["last_seen"],
                "source": "GreyNoise",
                "event_type": "last_observed",
                "description": f"Last observed by GreyNoise (actor: {greynoise_data.get('actor', 'unknown')})",
                "severity": "medium"
            })
        except Exception as e:
            logger.error(f"Error parsing GreyNoise last_seen: {e}")
    
    # Shodan last update
    if shodan_data.get("last_update"):
        try:
            events.append({
                "timestamp": shodan_data["last_update"],
                "source": "Shodan",
                "event_type": "port_scan",
                "description": f"Port scan completed ({len(shodan_data.get('ports', []))} open ports)",
                "severity": "medium"
            })
        except Exception as e:
            logger.error(f"Error parsing Shodan timestamp: {e}")
    
    # Passive DNS domain associations
    for domain_info in passive_dns_data.get("associated_domains", [])[:5]:  # Limit to 5 most recent
        try:
            if domain_info.get("first_seen"):
                events.append({
                    "timestamp": domain_info["first_seen"],
                    "source": "Passive DNS",
                    "event_type": "domain_association",
                    "description": f"First associated with domain: {domain_info.get('domain', 'unknown')}",
                    "severity": "medium"
                })
            
            if domain_info.get("last_seen"):
                events.append({
                    "timestamp": domain_info["last_seen"],
                    "source": "Passive DNS",
                    "event_type": "domain_association",
                    "description": f"Last associated with domain: {domain_info.get('domain', 'unknown')}",
                    "severity": "low"
                })
        except Exception as e:
            logger.error(f"Error parsing Passive DNS timestamp: {e}")
    
    # Sort events by timestamp (newest first)
    def parse_timestamp(event):
        try:
            ts = event["timestamp"]
            if isinstance(ts, str):
                # Handle various ISO formats and make timezone-aware
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                # Ensure all datetimes are timezone-aware (UTC)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            # Return timezone-aware datetime.min
            return datetime.min.replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.error(f"Error parsing timestamp: {e}")
            return datetime.min.replace(tzinfo=timezone.utc)
    
    events.sort(key=parse_timestamp, reverse=True)
    
    return events
