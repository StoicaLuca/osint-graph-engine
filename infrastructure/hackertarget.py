# OSINT Attribution Engine
# Copyright (c) 2026 Stoica Luca Ioan Michele. All rights reserved.

import httpx
from typing import List
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


class HackerTargetProvider(OSINTProvider):
    """
    Passive DNS host search — returns hostname/IP pairs for a domain.
    Unlike CT logs, this gives resolved addresses, which become graph edges.
    """

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.DOMAIN]

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        url = "https://api.hackertarget.com/hostsearch/"

        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                r = await client.get(url, params={"q": target_value})
                r.raise_for_status()
                body = r.text.strip()
            except httpx.TimeoutException:
                return OSINTResult(
                    source_module="HackerTarget", target=target_value,
                    status=ProviderStatus.TIMEOUT, error_message="HackerTarget timed out",
                )
            except httpx.HTTPError as e:
                return OSINTResult(
                    source_module="HackerTarget", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e),
                )

        # This API answers in plain text, and reports failure as prose rather than a status code.
        lowered = body.lower()
        if "api count exceeded" in lowered:
            return OSINTResult(
                source_module="HackerTarget", target=target_value,
                status=ProviderStatus.RATE_LIMITED,
                error_message="HackerTarget daily free quota exceeded",
            )
        if "error" in lowered or "," not in body:
            return OSINTResult(
                source_module="HackerTarget", target=target_value,
                status=ProviderStatus.NOT_FOUND,
                error_message="No host records returned.",
            )

        # Each line is "hostname,ip".
        hosts = []
        for line in body.splitlines():
            parts = line.split(",")
            if len(parts) == 2:
                host, ip = parts[0].strip().lower(), parts[1].strip()
                if host and ip:
                    hosts.append({"hostname": host, "ip": ip})

        return OSINTResult(
            source_module="HackerTarget", target=target_value, status=ProviderStatus.OK,
            raw_data={"hosts": hosts, "count": len(hosts)},
        )