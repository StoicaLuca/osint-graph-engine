import asyncio
import httpx
from typing import List, Optional
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


# Fiecare platformă: URL + un validator care decide corect "există profilul?".
# validator(response) -> True daca profilul EXISTĂ. Blanket status==200 e capcană:
# unele site-uri intorc 200 cu pagina "not found". Fiecare site iși știe semnalul.
def _exists_200(r: httpx.Response) -> bool:
    return r.status_code == 200

def _reddit_valid(r: httpx.Response) -> bool:
    # Reddit .json intoarce 200 mereu; profilul real are cheia data.name populata
    if r.status_code != 200:
        return False
    try:
        return bool(r.json().get("data", {}).get("name"))
    except Exception:
        return False

def _keybase_valid(r: httpx.Response) -> bool:
    # Keybase API intoarce mereu 200; codul de status intern spune daca userul exista
    if r.status_code != 200:
        return False
    try:
        return r.json().get("status", {}).get("code") == 0
    except Exception:
        return False

def _telegram_valid(r: httpx.Response) -> bool:
    # t.me intoarce 200 mereu; o pagina inexistenta contine marker-ul de mai jos
    if r.status_code != 200:
        return False
    return "tgme_page_title" in r.text


# name: (url_template, validator, response_needs_body)
PLATFORMS = {
    "GitHub":    ("https://api.github.com/users/{u}",            _exists_200,    False),
    "GitLab":    ("https://gitlab.com/{u}",                      _exists_200,    False),
    "DockerHub": ("https://hub.docker.com/v2/users/{u}/",        _exists_200,    False),
    "Reddit":    ("https://www.reddit.com/user/{u}/about.json",  _reddit_valid,  True),
    "Keybase":   ("https://keybase.io/_/api/1.0/user/lookup.json?username={u}", _keybase_valid, True),
    "Telegram":  ("https://t.me/{u}",                            _telegram_valid, True),
    "Instagram": ("https://www.instagram.com/{u}/",              _exists_200,    False),
    "Steam":     ("https://steamcommunity.com/id/{u}",           _exists_200,    False),
    "Twitch":    ("https://www.twitch.tv/{u}",                   _exists_200,    False),
    "Pastebin":  ("https://pastebin.com/u/{u}",                  _exists_200,    False),
    "TryHackMe": ("https://tryhackme.com/p/{u}",                 _exists_200,    False),
    "HackTheBox":("https://app.hackthebox.com/users/{u}",        _exists_200,    False),
}


class UsernameScannerProvider(OSINTProvider):
    """Concurrently probes public platforms with per-site validators to map a handle's footprint."""

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.USERNAME]

    async def _check(self, client: httpx.AsyncClient, name: str,
                     tmpl: str, validator, username: str) -> tuple[str, Optional[str]]:
        url = tmpl.format(u=username)
        try:
            r = await client.get(url)
            return name, (url if validator(r) else None)
        except Exception:
            return name, None

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        headers = {"User-Agent": "Mozilla/5.0 (OSINT-Graph-Engine research)"}
        async with httpx.AsyncClient(timeout=8.0, headers=headers, follow_redirects=True) as client:
            tasks = [
                self._check(client, name, tmpl, validator, target_value)
                for name, (tmpl, validator, _) in PLATFORMS.items()
            ]
            results = await asyncio.gather(*tasks)

        found = {name: url for name, url in results if url is not None}

        if not found:
            return OSINTResult(
                source_module="Username Scanner", target=target_value,
                status=ProviderStatus.NOT_FOUND,
                error_message="No public footprint found across scanned platforms.",
            )

        return OSINTResult(
            source_module="Username Scanner", target=target_value,
            status=ProviderStatus.OK,
            raw_data={"profiles": found, "platforms_checked": len(PLATFORMS)},
            risk_score=min(len(found) * 5, 100),
        )