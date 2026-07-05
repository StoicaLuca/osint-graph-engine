import re
from enum import Enum
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone
from typing import Dict, Any, Optional

_FQDN_REGEX = re.compile(r"^(?=.{4,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$", re.IGNORECASE)
_IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)

class TargetType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"

class ProviderStatus(str, Enum):
    OK = "ok"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    ERROR = "error"

class InvestigationTarget(BaseModel):
    value: str = Field(..., description="The raw target string from the omnibox")
    target_type: Optional[TargetType] = Field(None, description="Auto-detected type")
    submitted_at: datetime = Field(default_factory=get_utc_now)

    @model_validator(mode='after')
    def classify_target(self) -> 'InvestigationTarget':
        """
        The intelligence layer: automatically detects what the user typed.
        """
        v = self.value.strip().lower()
        self.value = v  # Normalize the input
        
        # 1. Deterministic Checks
        if _IPV4_REGEX.match(v):
            self.target_type = TargetType.IP
        elif "@" in v and "." in v.split("@")[1]:
            self.target_type = TargetType.EMAIL
        elif _FQDN_REGEX.match(v):
            self.target_type = TargetType.DOMAIN
        # 2. Heuristic Checks
        elif " " in v:
            self.target_type = TargetType.PERSON
        else:
            self.target_type = TargetType.USERNAME
            
        return self

class OSINTResult(BaseModel):
    source_module: str
    target: str
    status: ProviderStatus = ProviderStatus.OK
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(0, ge=0, le=100)
    error_message: Optional[str] = None