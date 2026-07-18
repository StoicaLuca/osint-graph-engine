# OSINT Attribution Engine
# Copyright (c) 2026 Stoica Luca Ioan Michele. All rights reserved.

import httpx
from typing import List
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


class CertSpotterProvider(OSINTProvider):
    """
    Certificate Transparency via SSLMate's Cert Spotter — the same CT data as crt.sh
    but on a far more reliable endpoint. Runs alongside crt.sh, not instead of it.
    """

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.DOMAIN]

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        url = "https://api.certspotter.com/v1/issuances"
        params = {
            "domain": target_value,
            "include_subdomains": "true",
            "expand": "dns_names",
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                r = await client.get(url, params=params)
                if r.status_code == 429:
                    return OSINTResult(
                        source_module="CertSpotter", target=target_value,
                        status=ProviderStatus.RATE_LIMITED,
                        error_message="CertSpotter free tier rate limit reached",
                    )
                r.raise_for_status()
                issuances = r.json()
            except httpx.TimeoutException:
                return OSINTResult(
                    source_module="CertSpotter", target=target_value,
                    status=ProviderStatus.TIMEOUT, error_message="CertSpotter timed out",
                )
            except httpx.HTTPError as e:
                return OSINTResult(
                    source_module="CertSpotter", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e),
                )

        subdomains: set[str] = set()
        for issuance in issuances:
            for name in issuance.get("dns_names", []):
                cleaned = name.lstrip("*.").strip().lower()
                if cleaned:
                    subdomains.add(cleaned)

        if not subdomains:
            return OSINTResult(
                source_module="CertSpotter", target=target_value,
                status=ProviderStatus.NOT_FOUND,
                error_message="No certificates found for this domain.",
            )

        return OSINTResult(
            source_module="CertSpotter", target=target_value, status=ProviderStatus.OK,
            raw_data={"subdomains": sorted(subdomains), "count": len(subdomains)},
        )