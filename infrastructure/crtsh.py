import httpx
from core.models import OSINTResult, ProviderStatus


class CrtShProvider:
    name = "crt.sh"

    async def fetch(self, target: str, client: httpx.AsyncClient) -> OSINTResult:
        try:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": target, "output": "json"},
                timeout=15,
            )
            resp.raise_for_status()
        except httpx.TimeoutException:
            return OSINTResult(
                source_module=self.name, target=target,
                status=ProviderStatus.TIMEOUT, error_message="crt.sh timed out",
            )
        except httpx.HTTPError as e:
            return OSINTResult(
                source_module=self.name, target=target,
                status=ProviderStatus.ERROR, error_message=str(e),
            )

        subdomains: set[str] = set()
        for row in resp.json():
            for name in row["name_value"].splitlines():
                cleaned = name.lstrip("*.").strip().lower()
                if cleaned:
                    subdomains.add(cleaned)

        return OSINTResult(
            source_module=self.name,
            target=target,
            status=ProviderStatus.OK,
            raw_data={"subdomains": sorted(subdomains)},
        )