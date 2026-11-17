"""Blocking rules for IPs, applications, and domains."""

from __future__ import annotations

from .types import AppType, app_type_label, parse_ipv4_string


class BlockingRules:
    def __init__(self) -> None:
        self.blocked_ips: set[int] = set()
        self.blocked_apps: set[AppType] = set()
        self.blocked_domains: list[str] = []

    def block_ip(self, ip: str) -> None:
        self.blocked_ips.add(parse_ipv4_string(ip))
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, name: str) -> None:
        normalized = name.strip().lower().replace("/", "_").replace(" ", "")
        for app in AppType:
            label = app_type_label(app).lower().replace("/", "_").replace(" ", "")
            if label == normalized or app.name.lower() == normalized:
                self.blocked_apps.add(app)
                print(f"[Rules] Blocked app: {app_type_label(app)}")
                return
        print(f"[Rules] Unknown app: {name}")

    def block_domain(self, domain: str) -> None:
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        for domain in self.blocked_domains:
            if domain in sni:
                return True
        return False