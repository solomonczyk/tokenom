"""Local-only proxy binding policy for Tokenom."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any


DEFAULT_PROXY_HOST = "127.0.0.1"
_PUBLIC_BIND_HOSTS = {"0.0.0.0", "::", ""}


@dataclass(frozen=True)
class ProxyDecision:
    allowed: bool
    host: str
    warnings: tuple[str, ...] = field(default_factory=tuple)
    audit_event: dict[str, Any] | None = None


def validate_proxy_host(
    host: str | None = None,
    *,
    allow_remote_proxy: bool = False,
    unsafe_override: bool = False,
    audit_logger: Any | None = None,
) -> ProxyDecision:
    """Validate a proxy bind host under Tokenom's local-only default."""

    effective_host = (host or DEFAULT_PROXY_HOST).strip()
    warnings: list[str] = []

    if _is_loopback_host(effective_host):
        return ProxyDecision(True, effective_host)

    if effective_host in _PUBLIC_BIND_HOSTS or not _is_loopback_host(effective_host):
        if allow_remote_proxy and unsafe_override:
            warning = f"UNSAFE remote proxy bind allowed for {effective_host}"
            warnings.append(warning)
            event = {
                "event": "unsafe_remote_proxy_override",
                "host": effective_host,
                "warning": warning,
            }
            if audit_logger is not None:
                audit_logger.record_event("unsafe_remote_proxy_override", event)
            return ProxyDecision(True, effective_host, tuple(warnings), event)

        event = {
            "event": "remote_proxy_bind_blocked",
            "host": effective_host,
            "allow_remote_proxy": allow_remote_proxy,
            "unsafe_override": unsafe_override,
        }
        if audit_logger is not None:
            audit_logger.record_event("remote_proxy_bind_blocked", event)
        return ProxyDecision(False, effective_host, ("Remote proxy binding is blocked by default.",), event)

    return ProxyDecision(True, effective_host)


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
