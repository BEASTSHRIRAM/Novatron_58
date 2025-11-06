"""
Data Cleaning Utilities
Normalize types, formats, and handle missing values
"""

import re
import ipaddress
from typing import Any, List, Optional, Union
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def clean_numeric(value: Any, default: Union[int, float] = 0) -> Union[int, float]:
    """Convert value to number, return default if failed"""
    if value is None or value == "":
        return default
    
    try:
        # Try int first
        if isinstance(value, (int, float)):
            return value
        
        # Handle string numbers
        cleaned = str(value).strip().replace(",", "")
        if "." in cleaned:
            return float(cleaned)
        return int(cleaned)
    except (ValueError, TypeError):
        return default


def clean_timestamp(value: Any) -> Optional[str]:
    """
    Normalize timestamp to ISO 8601 format
    Handles various input formats
    """
    if not value:
        return None
    
    try:
        # Already a datetime object
        if isinstance(value, datetime):
            return value.isoformat()
        
        # Unix timestamp (integer)
        if isinstance(value, int):
            return datetime.fromtimestamp(value).isoformat()
        
        # String timestamp
        if isinstance(value, str):
            # Try ISO format first
            if "T" in value or "Z" in value:
                # Clean up various ISO formats
                cleaned = value.replace("Z", "+00:00")
                dt = datetime.fromisoformat(cleaned)
                return dt.isoformat()
            
            # Try common formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"]:
                try:
                    dt = datetime.strptime(value, fmt)
                    return dt.isoformat()
                except ValueError:
                    continue
        
        return None
    except Exception as e:
        logger.warning(f"Failed to parse timestamp '{value}': {e}")
        return None


def clean_list(value: Any, unique: bool = True, lowercase: bool = False) -> List[str]:
    """
    Clean and normalize list values
    
    Args:
        value: List or comma-separated string
        unique: Remove duplicates
        lowercase: Convert to lowercase
    
    Returns:
        Cleaned list of strings
    """
    if not value:
        return []
    
    # Handle string input (comma-separated)
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
    elif isinstance(value, list):
        items = [str(item).strip() for item in value]
    else:
        return []
    
    # Filter empty strings
    items = [item for item in items if item]
    
    # Lowercase if requested
    if lowercase:
        items = [item.lower() for item in items]
    
    # Remove duplicates while preserving order
    if unique:
        seen = set()
        unique_items = []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique_items.append(item)
        return unique_items
    
    return items


def clean_domain(domain: str) -> Optional[str]:
    """Clean and validate domain name"""
    if not domain:
        return None
    
    domain = domain.strip().lower()
    
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    
    # Remove port
    domain = re.sub(r':\d+$', '', domain)
    
    # Remove path
    domain = domain.split('/')[0]
    
    # Basic validation
    if '.' in domain and len(domain) > 3:
        return domain
    
    return None


def clean_url(url: str) -> Optional[str]:
    """Clean and validate URL"""
    if not url:
        return None
    
    url = url.strip().lower()
    
    # Must have protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    return url if len(url) > 10 else None


def clean_ip(ip: str) -> Optional[str]:
    """Validate and normalize IP address"""
    if not ip:
        return None
    
    ip = ip.strip()
    
    try:
        # Validate IPv4 or IPv6
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def clean_cve(cve: str) -> Optional[str]:
    """Normalize CVE identifier"""
    if not cve:
        return None
    
    cve = cve.strip().upper()
    
    # Match CVE-YYYY-NNNNN pattern
    if re.match(r'^CVE-\d{4}-\d{4,}$', cve):
        return cve
    
    return None


def normalize_score(value: Any, max_value: float = 100.0) -> float:
    """
    Normalize score to 0-100 range
    
    Args:
        value: Raw score value
        max_value: Maximum value in original scale
    
    Returns:
        Normalized score (0-100)
    """
    score = clean_numeric(value, 0)
    
    # Already in 0-100 range
    if 0 <= score <= 100:
        return float(score)
    
    # Scale to 0-100
    if max_value > 0:
        normalized = (score / max_value) * 100
        return min(max(normalized, 0.0), 100.0)
    
    return 0.0
