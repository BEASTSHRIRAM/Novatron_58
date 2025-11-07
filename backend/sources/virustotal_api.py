import os
import httpx
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


async def get_virustotal_data(ip: str) -> Dict[str, Any]:
    """
    Query VirusTotal for IP reputation and threat data.
    Returns only real VirusTotal fields — no synthetic calculations.
    """

    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured; cannot fetch live data.")
        return {
            "source": "none",
            "data": {"error": "API key missing; live VirusTotal lookup unavailable."}
        }

    headers = {"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"}
    url = VIRUSTOTAL_URL.format(ip=ip)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()
            logger.debug("VirusTotal raw response for %s: %s", ip, result)

            data = result.get("data", {})
            attributes = data.get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})

            # Return only genuine fields from VirusTotal
            return {
                "source": "virustotal",
                "data": {
                    "last_analysis_stats": last_analysis,
                    "reputation": attributes.get("reputation"),
                    "tags": attributes.get("tags"),
                    "country": attributes.get("country"),
                    "as_owner": attributes.get("as_owner"),
                    "network": attributes.get("network"),
                    "whois": attributes.get("whois"),
                    "regional_internet_registry": attributes.get("regional_internet_registry"),
                    "last_modification_date": attributes.get("last_modification_date"),
                    "total_votes": attributes.get("total_votes"),
                },
            }

    except httpx.HTTPStatusError as e:
        logger.error(f"VirusTotal HTTP error {e.response.status_code}: {e.response.text}")
        return {
            "source": "virustotal",
            "data": {"error": f"HTTP {e.response.status_code} from VirusTotal"},
        }
    except Exception as e:
        logger.error(f"VirusTotal fetch error: {e}")
        return {"source": "virustotal", "data": {"error": str(e)}}
