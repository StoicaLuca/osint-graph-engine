from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime, timezone

def get_utc_now() -> datetime:
    """Helper function to get current UTC time."""
    return datetime.now(timezone.utc)

class TargetDomain(BaseModel):
    """
    Represents a domain name target for investigation.
    Strict validation ensures we don't process invalid inputs.
    """
    domain_name: str = Field(
        ..., 
        description="The fully qualified domain name (FQDN) to investigate",
        min_length=4,
        max_length=253
    )
    submitted_at: datetime = Field(
        default_factory=get_utc_now, 
        description="Timestamp of submission in UTC"
    )

class OSINTResult(BaseModel):
    """
    Standardized output for any OSINT module.
    """
    source_module: str = Field(..., description="Name of the module")
    target: str = Field(..., description="The specific target that was queried")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Raw JSON data")
    risk_score: int = Field(0, ge=0, le=100, description="Calculated risk score")
    error_message: Optional[str] = Field(None, description="Error message if failed")