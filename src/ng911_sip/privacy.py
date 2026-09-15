"""Privacy boundary for caller identifiers.

Real NG911 SIP carries caller telephone numbers in From/To/Contact/Request-URI
and caller location in PIDF-LO bodies referenced by ``Geolocation``. None of
that is needed to detect traffic anomalies: the models consume counts and
cardinalities, never identities.

So identity is reduced to a keyed hash at parse time, before anything is written
to disk. Downstream code can still count distinct callers and correlate a dialog
across messages, but a leaked feature file does not expose who called 911.

The key is per-deployment and lives outside the repository. Losing it only means
hashes from a later run will not match hashes from an earlier one.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

_TOKEN_BYTES = 8  # 16 hex characters: ample against collision at PSAP volumes.

DEFAULT_KEY_PATH = Path.home() / ".ng911_sip" / "pseudonym.key"
_KEY_ENV_VAR = "NG911_SIP_PSEUDONYM_KEY"

# user@host out of a SIP/SIPS URI, tolerating display names and parameters.
_URI_RE = re.compile(
    r"(?P<scheme>sips?):(?:(?P<user>[^@;:>\s]+)@)?(?P<host>[^;:>\s]+)?",
    re.IGNORECASE,
)

# A tel: URI is a bare subscriber number with no host part (RFC 3966). It is
# matched separately because treating it like a SIP URI would put the telephone
# number itself in the host field -- in the clear, in every feature export.
_TEL_RE = re.compile(r"tel:(?P<number>[^;>\s]+)", re.IGNORECASE)

# NG911 i3 addresses emergency calls to a service URN rather than a user@host
# (RFC 5031). "urn:service:sos" and its sub-services name a service, not a
# person, so they are kept verbatim -- they are the marker that distinguishes a
# real emergency call from keepalive traffic.
_URN_RE = re.compile(r"urn:(?P<namespace>[A-Za-z0-9][A-Za-z0-9-]*):(?P<rest>\S+)", re.IGNORECASE)

_SAFE_URN_NAMESPACES = {"service"}


def load_or_create_key(key_path: str | Path | None = None) -> bytes:
    """Return the pseudonymisation key, generating one on first use.

    An explicit ``NG911_SIP_PSEUDONYM_KEY`` environment variable wins, which is
    how a multi-host lab keeps hashes consistent across machines.
    """
    from_env = os.environ.get(_KEY_ENV_VAR)
    if from_env:
        return from_env.encode("utf-8")

    path = Path(key_path) if key_path else DEFAULT_KEY_PATH
    if path.exists():
        return path.read_bytes().strip()

    key = secrets.token_hex(32).encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:  # Best effort on Windows, which ignores the POSIX mode.
        path.chmod(0o600)
    except OSError:
        pass
    return key


class Pseudonymiser:
    """Maps identity strings to stable, non-reversible tokens."""

    __slots__ = ("_key", "_cache", "enabled")

    def __init__(self, key: bytes | None = None, *, enabled: bool = True) -> None:
        self._key = key if key is not None else load_or_create_key()
        self._cache: dict[str, str] = {}
        self.enabled = enabled

    def token(self, value: str | None) -> str | None:
        """Hash one identity value, caching because callers repeat constantly."""
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if not self.enabled:
            return value

        cached = self._cache.get(value)
        if cached is None:
            digest = hmac.new(self._key, value.encode("utf-8", "replace"), hashlib.sha256)
            cached = digest.hexdigest()[: _TOKEN_BYTES * 2]
            self._cache[value] = cached
        return cached

    def split_uri(self, header_value: str | None) -> tuple[str | None, str | None]:
        """Return (user_token, host) for a URI-bearing header.

        The host is infrastructure — an ESInet element or carrier gateway — and
        is kept in the clear because identifying which element misbehaves is the
        entire point. Only the user part is treated as identifying.

        Service URNs (``urn:service:sos``) are returned as the host: they name a
        service rather than a caller. Any other URN namespace may embed a call
        or incident identifier, so its value is hashed. A ``tel:`` URI is all
        subscriber number and is hashed whole.
        """
        if not header_value:
            return None, None

        tel = _TEL_RE.search(header_value)
        if tel is not None:
            # The whole number identifies a subscriber; there is no host to keep.
            return self.token(tel.group("number").rstrip(">;, ")), "tel"

        urn = _URN_RE.search(header_value)
        if urn is not None:
            namespace = urn.group("namespace").lower()
            rest = urn.group("rest").rstrip(">;, ").lower()
            if namespace in _SAFE_URN_NAMESPACES:
                return None, f"urn:{namespace}:{rest}"
            return self.token(f"urn:{namespace}:{rest}"), f"urn:{namespace}"

        match = _URI_RE.search(header_value)
        if match is None:
            return None, None

        host = match.group("host")
        if host:
            host = host.rstrip(">;, ").lower() or None
        return self.token(match.group("user")), host
