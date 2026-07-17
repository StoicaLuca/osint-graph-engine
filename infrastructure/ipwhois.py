import httpx
from typing import List
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


class IPWhoisProvider(OSINTProvider):
    """Resolves ASN, network name, org and country for an IP via RDAP."""

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.IP]

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        url = f"https://rdap.org/ip/{target_value}"
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            try:
                r = await client.get(url)
                r.raise_for_status()
                data = r.json()
            except httpx.HTTPError as e:
                return OSINTResult(
                    source_module="IP RDAP", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e),
                )
        return OSINTResult(
            source_module="IP RDAP", target=target_value, status=ProviderStatus.OK,
            raw_data={
                "handle": data.get("handle"),
                "name": data.get("name"),
                "country": data.get("country"),
                "cidr": data.get("cidr0_cidrs"),
                "entities": [e.get("handle") for e in data.get("entities", [])],
            },
        )