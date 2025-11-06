"""
Unified Threat Intelligence Schema Definition
All normalized data must conform to this structure
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class UnifiedThreatData(BaseModel):
    """Unified schema for threat intelligence data"""
    
    # Identity
    ip: str = Field(..., description="IP address")
    
    # Scores (0-100)
    score_abuseipdb: float = Field(0.0, ge=0, le=100)
    score_virustotal: float = Field(0.0, ge=0, le=100)
    score_greynoise: float = Field(0.0, ge=0, le=100)
    score_max: float = Field(0.0, ge=0, le=100, description="Maximum score across all feeds")
    score_avg: float = Field(0.0, ge=0, le=100, description="Average score across all feeds")
    
    # Counts
    counts: Dict[str, int] = Field(default_factory=dict, description="Various metric counts")
    
    # Geolocation
    geo: Dict[str, Any] = Field(default_factory=dict)
    
    # Network
    network: Dict[str, Any] = Field(default_factory=dict)
    
    # Normalized categories (unified)
    categories: List[str] = Field(default_factory=list)
    
    # Related artifacts
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    
    # Timestamps (ISO 8601)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    
    # Source flags
    feeds_flagged: int = Field(0, description="Number of feeds that flagged this IP")
    feeds_checked: int = Field(0, description="Number of feeds consulted")
    
    # Raw evidence (optional, for debugging)
    raw_evidence: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        extra = "allow"  # Allow additional fields
