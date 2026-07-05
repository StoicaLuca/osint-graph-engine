from enum import Enum
from datetime import datetime, timezone
import re
from pydantic import BaseModel, Field, field_validator


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


_FQDN = re.compile(
    r"^(?=.{4,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


class ProviderStatus(str, Enum):
    OK = "ok"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    ERROR = "error"


class TargetDomain(BaseModel):
    domain_name: str = Field(..., min_length=4, max_length=253)
    submitted_at: datetime = Field(default_factory=get_utc_now)

    @field_validator("domain_name")
    @classmethod
    def must_be_fqdn(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if not _FQDN.match(v):
            raise ValueError("not a valid fully-qualified domain name")
        return v


class OSINTResult(BaseModel):
    source_module: str
    target: str
    status: ProviderStatus = ProviderStatus.OK
    raw_data: dict = Field(default_factory=dict)
    risk_score: int = Field(0, ge=0, le=100)
    error_message: str | None = None
    collected_at: datetime = Field(default_factory=get_utc_now)