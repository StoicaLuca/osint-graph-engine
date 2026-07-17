import asyncio
import httpx
from typing import List, Optional
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


# Each platform: URL + a validator that correctly decides "does this profile exist?".
# validator(response) -> True if the profile EXISTS. A blanket status==200 is a trap:
# some sites return 200 with a "not found" page. Each site knows its own signal.
def _exists_200(r: httpx.Response) -> bool:
    return r.status_code == 200

def _reddit_valid(r: httpx.Response) -> bool:
    # Reddit's .json always returns 200; a real profile has data.name populated.
    if r.status_code != 200:
        return False
    try:
        return bool(r.json().get("data", {}).get("name"))
    except Exception:
        return False

def _keybase_valid(r: httpx.Response) -> bool:
    # Keybase API always returns 200; an internal status.code == 0 means the user exists.
    if r.status_code != 200:
        return False
    try:
        return r.json().get("status", {}).get("code") == 0
    except Exception:
        return False

def _telegram_valid(r: httpx.Response) -> bool:
    # t.me always returns 200; a real page contains the channel title marker below.
    return r.status_code == 200 and "tgme_page_title" in r.text

def _json_ok(r: httpx.Response) -> bool:
    # For APIs that return 200 + valid JSON only when the user exists.
    if r.status_code != 200:
        return False
    try:
        r.json()
        return True
    except Exception:
        return False


# name: (url_template, validator, response_needs_body)
PLATFORMS = {
    # --- Code & developer ---
    "GitHub":     ("https://api.github.com/users/{u}",            _exists_200,    False),
    "GitLab":     ("https://gitlab.com/{u}",                      _exists_200,    False),
    "DockerHub":  ("https://hub.docker.com/v2/users/{u}/",        _exists_200,    False),
    "Replit":     ("https://replit.com/@{u}",                     _exists_200,    False),
    "Pastebin":   ("https://pastebin.com/u/{u}",                  _exists_200,    False),
    "NpmJS":      ("https://www.npmjs.com/~{u}",                  _exists_200,    False),
    "PyPI":       ("https://pypi.org/user/{u}/",                  _exists_200,    False),

    # --- Security / hacking (clearnet, relevant for a "technical actor") ---
    "Keybase":    ("https://keybase.io/_/api/1.0/user/lookup.json?username={u}", _keybase_valid, True),
    "TryHackMe":  ("https://tryhackme.com/p/{u}",                 _exists_200,    False),
    "HackTheBox": ("https://app.hackthebox.com/users/{u}",        _exists_200,    False),
    "HackerOne":  ("https://hackerone.com/{u}",                   _exists_200,    False),
    "Bugcrowd":   ("https://bugcrowd.com/{u}",                    _exists_200,    False),

    # --- Communication / "where someone might hide" (clearnet, verifiable) ---
    "Telegram":   ("https://t.me/{u}",                            _telegram_valid, True),

    # --- Social & general ---
    "Reddit":     ("https://www.reddit.com/user/{u}/about.json",  _reddit_valid,  True),
    "Instagram":  ("https://www.instagram.com/{u}/",              _exists_200,    False),
    "Twitch":     ("https://www.twitch.tv/{u}",                   _exists_200,    False),
    "Steam":      ("https://steamcommunity.com/id/{u}",           _exists_200,    False),
    "Telegraph":  ("https://telegra.ph/{u}",                      _exists_200,    False),
    "Vimeo":      ("https://vimeo.com/{u}",                       _exists_200,    False),
    "SoundCloud": ("https://soundcloud.com/{u}",                  _exists_200,    False),

    # --- Creative / freelance (real-identity signal) ---
    "Behance":    ("https://www.behance.net/{u}",                 _exists_200,    False),
    "DeviantArt": ("https://www.deviantart.com/{u}",              _exists_200,    False),
    "Medium":     ("https://medium.com/@{u}",                     _exists_200,    False),
    "Chess":      ("https://api.chess.com/pub/player/{u}",        _json_ok,       True),
    "Gravatar":   ("https://en.gravatar.com/{u}.json",            _json_ok,       True),
}


class UsernameScannerProvider(OSINTProvider):
    """Concurrently probes public platforms with per-site validators to map a handle's footprint."""

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.USERNAME]

    async def _check(self, client: httpx.AsyncClient, name: str,
                     tmpl: str, validator, username: str) -> tuple[str, Optional[str]]:
        # Format the URL, fetch it, apply the validator. Return (name, url) on a hit, (name, None) otherwise.
        url = tmpl.format(u=username)
        try:
            r = await client.get(url)
            return name, (url if validator(r) else None)
        except Exception:
            # A network error on one platform must not sink the whole scan.
            return name, None

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        headers = {"User-Agent": "Mozilla/5.0 (OSINT-Graph-Engine research)"}
        async with httpx.AsyncClient(timeout=8.0, headers=headers, follow_redirects=True) as client:
            # Build one coroutine per platform (not awaited yet), then fire them all concurrently.
            tasks = [
                self._check(client, name, tmpl, validator, target_value)
                for name, (tmpl, validator, _) in PLATFORMS.items()
            ]
            results = await asyncio.gather(*tasks)

        # Keep only platforms where the validator confirmed a hit.
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