"""Map hostnames (SNI / HTTP Host) to application categories."""

from __future__ import annotations

from .types import AppType


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower = sni.lower()

    if any(
        token in lower
        for token in (
            "google",
            "gstatic",
            "googleapis",
            "ggpht",
            "gvt1",
        )
    ):
        return AppType.GOOGLE

    if any(
        token in lower for token in ("youtube", "ytimg", "youtu.be", "yt3.ggpht")
    ):
        return AppType.YOUTUBE

    if any(
        token in lower
        for token in ("facebook", "fbcdn", "fb.com", "fbsbx", "meta.com")
    ):
        return AppType.FACEBOOK

    if "instagram" in lower or "cdninstagram" in lower:
        return AppType.INSTAGRAM

    if "whatsapp" in lower or "wa.me" in lower:
        return AppType.WHATSAPP

    if any(token in lower for token in ("twitter", "twimg")):
        return AppType.TWITTER
    if lower.endswith(".x.com") or lower == "x.com" or lower.endswith(".t.co") or lower == "t.co":
        return AppType.TWITTER

    if any(token in lower for token in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    if any(
        token in lower for token in ("amazon", "amazonaws", "cloudfront", "aws")
    ):
        return AppType.AMAZON

    if any(
        token in lower
        for token in (
            "microsoft",
            "msn.com",
            "office",
            "azure",
            "live.com",
            "outlook",
            "bing",
        )
    ):
        return AppType.MICROSOFT

    if any(token in lower for token in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    if "telegram" in lower or "t.me" in lower:
        return AppType.TELEGRAM

    if any(
        token in lower
        for token in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")
    ):
        return AppType.TIKTOK

    if "spotify" in lower or "scdn.co" in lower:
        return AppType.SPOTIFY

    if "zoom" in lower:
        return AppType.ZOOM

    if "discord" in lower or "discordapp" in lower:
        return AppType.DISCORD

    if "github" in lower or "githubusercontent" in lower:
        return AppType.GITHUB

    if "cloudflare" in lower or "cf-" in lower:
        return AppType.CLOUDFLARE

    return AppType.HTTPS