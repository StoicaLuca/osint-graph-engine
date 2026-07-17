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
    UNKNOWN = "unknown"

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
        v = self.value.strip().lower()
        self.value = v

        # 1. IP: strict four-octet form
        if _IPV4_REGEX.match(v):
            self.target_type = TargetType.IP
        # 2. Email: exactly one @, and a valid-looking domain after it
        elif v.count("@") == 1 and _FQDN_REGEX.match(v.split("@")[1]):
            self.target_type = TargetType.EMAIL
        # 3. Domain: FQDN shape, no @
        elif "@" not in v and _FQDN_REGEX.match(v):
            self.target_type = TargetType.DOMAIN
        # 4. Person: has a space (a name), no @
        elif " " in v and "@" not in v:
            self.target_type = TargetType.PERSON
        # 5. Username: a single clean handle — letters/digits/._- only, no @, no space
        elif re.fullmatch(r"[a-z0-9._-]{1,39}", v):
            self.target_type = TargetType.USERNAME
        # 6. Anything else is unclassifiable
        else:
            self.target_type = TargetType.UNKNOWN

        return self

class OSINTResult(BaseModel):
    source_module: str
    target: str
    status: ProviderStatus = ProviderStatus.OK
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    risk_score: int = Field(0, ge=0, le=100)
    error_message: Optional[str] = None