import httpx
from typing import List
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


class CrtShProvider(OSINTProvider):
    """Extracts the deduplicated subdomain set for a domain from Certificate Transparency (crt.sh)."""

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.DOMAIN]

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        params = {"q": f"%.{target_value}", "output": "json"}

        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                resp = await client.get("https://crt.sh/", params=params)
                resp.raise_for_status()
            except httpx.TimeoutException:
                # Specific before generic: TimeoutException is a subclass of HTTPError.
                return OSINTResult(
                    source_module="crt.sh", target=target_value,
                    status=ProviderStatus.TIMEOUT, error_message="crt.sh timed out",
                )
            except httpx.HTTPError as e:
                return OSINTResult(
                    source_module="crt.sh", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e),
                )

            # name_value holds several SANs per line; strip wildcards, dedupe via set.
            subdomains: set[str] = set()
            for row in resp.json():
                for name in row.get("name_value", "").splitlines():
                    cleaned = name.lstrip("*.").strip().lower()
                    if cleaned:
                        subdomains.add(cleaned)

        return OSINTResult(
            source_module="crt.sh", target=target_value, status=ProviderStatus.OK,
            raw_data={"subdomains": sorted(subdomains), "count": len(subdomains)},
        )