"""
Category Normalization Mapping
Maps feed-specific categories to unified threat categories
"""

# Unified threat categories
UNIFIED_CATEGORIES = [
    "malware",
    "phishing",
    "spam",
    "ddos",
    "brute_force",
    "port_scan",
    "vulnerability_scan",
    "exploit",
    "botnet",
    "c2_server",
    "tor_exit",
    "vpn",
    "proxy",
    "hosting",
    "suspicious",
    "benign"
]

# AbuseIPDB category mappings (based on their category IDs)
ABUSEIPDB_CATEGORY_MAP = {
    "DNS Compromise": "malware",
    "DNS Poisoning": "malware",
    "Fraud Orders": "fraud",
    "DDoS Attack": "ddos",
    "FTP Brute-Force": "brute_force",
    "Ping of Death": "ddos",
    "Phishing": "phishing",
    "Fraud VoIP": "fraud",
    "Open Proxy": "proxy",
    "Web Spam": "spam",
    "Email Spam": "spam",
    "Blog Spam": "spam",
    "VPN IP": "vpn",
    "Port Scan": "port_scan",
    "Hacking": "exploit",
    "SQL Injection": "exploit",
    "Spoofing": "malware",
    "Brute-Force": "brute_force",
    "Bad Web Bot": "botnet",
    "Exploited Host": "exploit",
    "Web App Attack": "exploit",
    "SSH Attack": "brute_force",
    "IoT Targeted": "exploit"
}

# VirusTotal tag mappings
VIRUSTOTAL_TAG_MAP = {
    "malware": "malware",
    "trojan": "malware",
    "virus": "malware",
    "worm": "malware",
    "ransomware": "malware",
    "phishing": "phishing",
    "spam": "spam",
    "botnet": "botnet",
    "bruteforce": "brute_force",
    "brute-force": "brute_force",
    "scanner": "port_scan",
    "exploit": "exploit",
    "c2": "c2_server",
    "command-and-control": "c2_server",
    "tor": "tor_exit",
    "vpn": "vpn",
    "proxy": "proxy",
    "mining": "cryptomining",
    "cryptominer": "cryptomining"
}

# GreyNoise classification mappings
GREYNOISE_CLASSIFICATION_MAP = {
    "malicious": "malicious_actor",
    "benign": "benign",
    "unknown": "unknown"
}

# GreyNoise tag mappings
GREYNOISE_TAG_MAP = {
    "web scanner": "vulnerability_scan",
    "ssh bruteforce": "brute_force",
    "rdp bruteforce": "brute_force",
    "smb scanner": "vulnerability_scan",
    "tor exit node": "tor_exit",
    "vpn": "vpn",
    "proxy": "proxy",
    "mass scanner": "port_scan",
    "shodan": "port_scan",
    "censys": "port_scan"
}


def normalize_category(category: str, source: str = "generic") -> str:
    """
    Normalize a category string to unified category
    
    Args:
        category: Raw category string from feed
        source: Feed name (abuseipdb, virustotal, greynoise)
    
    Returns:
        Unified category string
    """
    if not category:
        return "unknown"
    
    category_lower = category.lower().strip()
    
    # Direct match in unified categories
    if category_lower in UNIFIED_CATEGORIES:
        return category_lower
    
    # Feed-specific mappings
    if source == "abuseipdb":
        return ABUSEIPDB_CATEGORY_MAP.get(category, "suspicious")
    
    elif source == "virustotal":
        for key, value in VIRUSTOTAL_TAG_MAP.items():
            if key in category_lower:
                return value
        return "suspicious"
    
    elif source == "greynoise":
        # Check classification first
        if category in GREYNOISE_CLASSIFICATION_MAP:
            return GREYNOISE_CLASSIFICATION_MAP[category]
        
        # Then check tags
        for key, value in GREYNOISE_TAG_MAP.items():
            if key in category_lower:
                return value
        return "unknown"
    
    # Fallback: fuzzy matching
    if "malware" in category_lower or "trojan" in category_lower:
        return "malware"
    elif "phish" in category_lower:
        return "phishing"
    elif "spam" in category_lower:
        return "spam"
    elif "ddos" in category_lower or "dos" in category_lower:
        return "ddos"
    elif "brute" in category_lower or "bruteforce" in category_lower:
        return "brute_force"
    elif "scan" in category_lower:
        return "port_scan"
    elif "exploit" in category_lower:
        return "exploit"
    elif "botnet" in category_lower or "bot" in category_lower:
        return "botnet"
    elif "tor" in category_lower:
        return "tor_exit"
    elif "vpn" in category_lower:
        return "vpn"
    elif "proxy" in category_lower:
        return "proxy"
    
    return "suspicious"
