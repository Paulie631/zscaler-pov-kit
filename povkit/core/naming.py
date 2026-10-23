"""Names and description stamps for everything the kit creates.

Every object is named '<prefix>: <suffix>' (ZIA rule names are limited to 31 characters) and its description
carries 'zpov:<pov-id>'. The name and stamp are two of the three ownership tests; the ledger is the third.
"""
import re

DEFAULT_PREFIX = "ZPOV"
NAME_MAX = 31  # ZIA rule-name limit


def name(prefix: str, suffix: str, limit: int = NAME_MAX) -> str:
    return f"{prefix}: {suffix}"[:limit].rstrip()


def safe_name(n: str, prefix: str, limit: int = NAME_MAX) -> str:
    """Some ZIA objects (rule labels) reject ':' and punctuation: 'ZPOV: x' -> 'ZPOV - x'. As in the demo kit."""
    n = n.replace(f"{prefix}:", f"{prefix} -", 1)
    return re.sub(r"[^A-Za-z0-9 _.()-]", "", n)[:limit].rstrip()


def split_prefix(n: str) -> str:
    """The prefix of a POV name: 'ZPOV' out of 'ZPOV: x' or 'ZPOV - x'."""
    return re.split(r":| - ", str(n or ""), maxsplit=1)[0].strip()


def has_prefix(n: str, prefix: str) -> bool:
    n = str(n or "")
    return n.startswith(prefix + ":") or n.startswith(prefix + " - ")


def stamp(pov_id: str) -> str:
    return f"zpov:{pov_id}"


def describe(pov_id: str, text: str) -> str:
    return f"{stamp(pov_id)} POV kit: {text}"


def has_stamp(description: str, pov_id: str) -> bool:
    return re.search(rf"(^|\s){re.escape(stamp(pov_id))}(\s|$)", str(description or "")) is not None
