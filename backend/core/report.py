from typing import Dict, Any
import logging
import os
import json
import google.generativeai as genai
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-2.0-flash-exp')
    logger.info("Gemini AI configured successfully")
else:
    logger.warning("GEMINI_API_KEY not found, using fallback report generation")
    model = None

# In-memory cache for generated reports (IP -> (report, timestamp))
_report_cache = {}


def generate_threat_report(
    ip: str,
    correlated: Dict[str, Any],
    risk: Dict[str, Any]
) -> str:
    """Generate AI-powered threat intelligence report using Gemini with caching"""
    
    # Check if we have a cached report for this IP (cache for 24 hours)
    if ip in _report_cache:
        cached_report, cached_time = _report_cache[ip]
        time_diff = datetime.now(timezone.utc) - cached_time
        if time_diff.total_seconds() < 86400:  # 24 hours
            logger.info(f"Returning cached AI report for IP: {ip}")
            return cached_report
        else:
            # Remove expired cache entry
            del _report_cache[ip]
    
    # If Gemini is not configured, use fallback template
    if not model:
        report = generate_fallback_report(ip, correlated, risk)
        _report_cache[ip] = (report, datetime.now(timezone.utc))
        return report
    
    try:
        # Prepare data for AI analysis
        context = correlated.get("context", {})
        categories = correlated.get("categories", [])
        related = correlated.get("related", {})
        evidence = correlated.get("evidence", {})
        
        # Build comprehensive prompt for Gemini
        prompt = f"""You are a cybersecurity threat intelligence analyst. Analyze the following IP address and provide a detailed threat assessment report.

IP ADDRESS: {ip}
RISK SCORE: {risk['score']}/100
RISK RATIONALE: {risk.get('rationale', 'N/A')}

GEOLOCATION & ATTRIBUTION:
- Location: {context.get('city', 'Unknown')}, {context.get('country', 'Unknown')}
- Organization: {context.get('org', 'Unknown')}
- ASN: {context.get('asn', 'Unknown')}
- Hostname: {context.get('hostname', 'N/A')}

THREAT CATEGORIES:
{json.dumps(categories, indent=2)}

RELATED INDICATORS:
{json.dumps(related, indent=2)}

EVIDENCE FROM SOURCES:

AbuseIPDB:
- Confidence Score: {evidence.get('abuseipdb', {}).get('confidence_score', 0)}%
- Total Reports: {evidence.get('abuseipdb', {}).get('total_reports', 0)}
- Usage Type: {evidence.get('abuseipdb', {}).get('usage_type', 'Unknown')}
- Whitelisted: {evidence.get('abuseipdb', {}).get('is_whitelisted', False)}

VirusTotal:
- Malicious Detections: {evidence.get('virustotal', {}).get('malicious', 0)}
- Suspicious Detections: {evidence.get('virustotal', {}).get('suspicious', 0)}
- Harmless: {evidence.get('virustotal', {}).get('harmless', 0)}
- Reputation: {evidence.get('virustotal', {}).get('reputation', 0)}
- Tags: {', '.join(evidence.get('virustotal', {}).get('tags', []))}
- CVEs: {', '.join(evidence.get('virustotal', {}).get('cves', []))}

IPInfo:
- Organization: {evidence.get('ipinfo', {}).get('organization', 'Unknown')}
- Location: {evidence.get('ipinfo', {}).get('geolocation', 'Unknown')}

INSTRUCTIONS:
Generate a professional threat intelligence report in Markdown format with the following sections:

1. **Executive Summary** - Brief overview of the threat level and key findings
2. **Threat Classification** - Classify the IP (Malicious/Suspicious/Benign) with severity
3. **Technical Analysis** - Detailed analysis of the evidence from all sources
4. **Attribution & Context** - Geographic and organizational context
5. **Indicators of Compromise** - List any CVEs, malware, or attack patterns
6. **Risk Assessment** - Explain the risk score and contributing factors
7. **Recommended Actions** - Specific actionable recommendations based on threat level

Use professional cybersecurity terminology. Be concise but thorough. Use emoji indicators (🔴 for high risk, 🟡 for medium, 🟢 for low).
Format the response in clean Markdown with proper headers (##, ###), bullet points (•), and emphasis (**bold** for important terms).
Avoid using asterisks for bullet points. Use proper Markdown headers only (## and ###).
Keep text clean and professional without excessive special characters."""

        # Generate AI report
        response = model.generate_content(prompt)
        ai_report = response.text
        
        # Cache the report
        _report_cache[ip] = (ai_report, datetime.now(timezone.utc))
        
        logger.info(f"AI report generated successfully for IP: {ip}")
        return ai_report
        
    except Exception as e:
        logger.error(f"Error generating AI report: {str(e)}")
        # Fallback to template if AI fails
        report = generate_fallback_report(ip, correlated, risk)
        # Cache the fallback report too
        _report_cache[ip] = (report, datetime.now(timezone.utc))
        return report


def generate_fallback_report(
    ip: str,
    correlated: Dict[str, Any],
    risk: Dict[str, Any]
) -> str:
    """Fallback template-based report generation"""
    
    context = correlated.get("context", {})
    categories = correlated.get("categories", [])
    evidence = correlated.get("evidence", {})
    related = correlated.get("related", {})

    report_lines = []
    
    report_lines.append("## Threat Intelligence Summary")
    report_lines.append("")
    
    if risk["score"] >= 60:
        report_lines.append(f"🔴 **MALICIOUS** - This IP address ({ip}) exhibits suspicious behavior with a risk score of {risk['score']}/100.")
    elif risk["score"] >= 40:
        report_lines.append(f"🟡 **SUSPICIOUS** - This IP address ({ip}) shows concerning patterns with a risk score of {risk['score']}/100.")
    else:
        report_lines.append(f"🟢 **BENIGN** - This IP address ({ip}) appears relatively safe with a risk score of {risk['score']}/100.")
    
    report_lines.append("")
    report_lines.append("## Threat Classification")
    if categories:
        for cat in categories:
            report_lines.append(f"• {cat}")
    else:
        report_lines.append("• No significant threats identified")
    
    report_lines.append("")
    report_lines.append("## Attribution & Context")
    report_lines.append(f"• **Location**: {context.get('city', 'Unknown')}, {context.get('country', 'Unknown')}")
    report_lines.append(f"• **Organization**: {context.get('org', 'Unknown')}")
    report_lines.append(f"• **ASN**: {context.get('asn', 'Unknown')}")
    if context.get("hostname"):
        report_lines.append(f"• **Hostname**: {context.get('hostname')}")
    
    report_lines.append("")
    report_lines.append("## Technical Analysis")
    
    abuse = evidence.get("abuseipdb", {})
    if abuse.get("total_reports", 0) > 0:
        report_lines.append(f"### AbuseIPDB")
        report_lines.append(f"• Total Reports: {abuse.get('total_reports')}")
        report_lines.append(f"• Confidence Score: {abuse.get('confidence_score')}%")
    
    vt = evidence.get("virustotal", {})
    if vt.get("malicious", 0) > 0 or vt.get("tags", []):
        report_lines.append(f"### VirusTotal")
        if vt.get("malicious", 0) > 0:
            report_lines.append(f"• Malicious Detections: {vt.get('malicious')}")
            report_lines.append(f"• Suspicious Detections: {vt.get('suspicious', 0)}")
        if vt.get("tags"):
            report_lines.append(f"• Threat Tags: {', '.join(vt.get('tags', []))}")
    
    cves = related.get("cves", [])
    if cves:
        report_lines.append("")
        report_lines.append("## Indicators of Compromise")
        report_lines.append(f"• Known CVEs: {', '.join(cves)}")
    
    report_lines.append("")
    report_lines.append("## Risk Assessment")
    report_lines.append(f"• Risk Score: {risk['score']}/100")
    report_lines.append(f"• Rationale: {risk.get('rationale', 'Analysis completed')}")
    
    report_lines.append("")
    report_lines.append("## Recommended Actions")
    if risk["score"] >= 60:
        report_lines.append("🚨 **BLOCK** this IP immediately in firewall rules")
        report_lines.append("• Review logs for any connections from this IP")
        report_lines.append("• Monitor for related IOCs and lateral movement")
        report_lines.append("• Consider triggering incident response procedures")
    elif risk["score"] >= 40:
        report_lines.append("⚠️ **MONITOR** this IP closely for suspicious activity")
        report_lines.append("• Review connection logs and access patterns")
        report_lines.append("• Implement rate limiting if applicable")
    else:
        report_lines.append("✅ **MONITOR** - Continue standard monitoring procedures")
        report_lines.append("• No immediate blocking action required")
    
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("*Report generated by TICE - Threat Intelligence Correlation Engine*")
    
    return "\n".join(report_lines)