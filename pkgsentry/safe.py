"""Making attacker-controlled text safe to show. Package names, code and indicators all come from the attacker."""

import re

_URL_TEXT = re.compile(r"(?i)\bhttp(s?)://([^\s/'\"<>]+)")
_IPV4_TEXT = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def printable(text: str) -> str:
    # Raw control characters could rewrite a terminal.
    return "".join(ch if ch.isprintable() else "?" for ch in text)


def defang(text: str) -> str:
    """Indicators in reports must not be clickable: hxxps://evil[.]example, 203[.]0[.]113[.]5."""
    text = _URL_TEXT.sub(lambda m: f"hxxp{m.group(1)}://{m.group(2).replace('.', '[.]')}", text)
    return _IPV4_TEXT.sub(lambda m: "[.]".join(m.groups()), text)


def show_key(key: str) -> str:
    # Link keys hold hostnames and IP addresses; defang every dot so nothing turns them into links.
    return printable(key.replace(".", "[.]"))
