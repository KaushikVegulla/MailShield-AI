"""Homograph / confusable domain detection (Unicode UTS #39).

Internationalised domains can imitate a brand with characters that
look identical to Latin letters — Cyrillic "а" (U+0430) for "a",
Greek "ο" (U+03BF) for "o", fullwidth "ｐ" for "p", and so on. UTS #39
defines a *skeleton*: replace every confusable character with its
Latin prototype, and two strings that look alike share a skeleton.

This module computes a focused skeleton for a domain:

- punycode labels (``xn--``) are decoded with the raw punycode codec
  (the strict idna codec rejects labels that do not round-trip,
  which crafted phishing labels often do not);
- fullwidth forms fold to ASCII;
- a built-in table maps the common Cyrillic and Greek lookalikes of
  Latin letters to their prototypes. The table is deliberately
  focused — it covers the letters used in real brand-imitation
  domains, not the full UTS #39 confusables list.

A domain is a homograph of a protected brand when its skeleton's
registrable domain equals the brand's official domain while the
actual (decoded) registrable domain differs. The brand's own genuine
domain therefore never flags: skeleton and actual agree there.
"""

from __future__ import annotations

# Confusable -> Latin prototype. Focused subset of the UTS #39
# confusables data for the scripts most abused in phishing domains.
CONFUSABLES = {
    # Cyrillic lookalikes
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "р": "p", "Р": "P", "с": "c", "С": "C", "х": "x", "Х": "X",
    "у": "y", "У": "Y", "ѕ": "s", "Ѕ": "S", "і": "i", "І": "I",
    "ј": "j", "Ј": "J", "һ": "h", "ԁ": "d", "ԍ": "g", "ԛ": "q",
    "ԝ": "w", "м": "m", "М": "M", "н": "h", "Н": "H", "к": "k",
    "К": "K", "т": "t", "Т": "T", "в": "b", "В": "B", "п": "n",
    "г": "r", "ѕ": "s", "ꙁ": "s", "ꮁ": "l", "᥇": "b",
    # Greek lookalikes
    "α": "a", "Α": "A", "ο": "o", "Ο": "O", "ρ": "p", "Ρ": "P",
    "τ": "t", "Τ": "T", "υ": "u", "ν": "v", "Ν": "N", "χ": "x",
    "Χ": "X", "γ": "y", "κ": "k", "Κ": "K", "μ": "u", "Μ": "M",
    "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Ζ": "Z",
    # Latin-script confusables sometimes embedded in domains
    "ł": "l", "ø": "o", "đ": "d", "ɡ": "g", "ο": "o",
}

_LATIN_RANGES = ((0x0041, 0x005A), (0x0061, 0x007A), (0x00C0, 0x024F))
_CYRILLIC_RANGES = ((0x0400, 0x04FF), (0x0500, 0x052F))
_GREEK_RANGES = ((0x0370, 0x03FF), (0x1F00, 0x1FFF))


def _script_of(char: str) -> str | None:
    code = ord(char)
    for lo, hi in _LATIN_RANGES:
        if lo <= code <= hi:
            return "latin"
    for lo, hi in _CYRILLIC_RANGES:
        if lo <= code <= hi:
            return "cyrillic"
    for lo, hi in _GREEK_RANGES:
        if lo <= code <= hi:
            return "greek"
    if 0xFF01 <= code <= 0xFF65:
        return "fullwidth"
    return None


def decode_punycode(host: str) -> str:
    """Decode xn-- labels to their Unicode form (best effort)."""
    labels = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except Exception:
                pass
        labels.append(label)
    return ".".join(labels)


def skeleton(domain: str) -> str:
    """UTS #39-style skeleton: confusables replaced by Latin prototypes."""
    out = []
    for char in domain.lower():
        code = ord(char)
        if 0xFF41 <= code <= 0xFF5A:  # fullwidth a-z
            out.append(chr(code - 0xFF41 + ord("a")))
        elif 0xFF10 <= code <= 0xFF19:  # fullwidth 0-9
            out.append(chr(code - 0xFF10 + ord("0")))
        elif 0xFF21 <= code <= 0xFF3A:  # fullwidth A-Z
            out.append(chr(code - 0xFF21 + ord("a")))
        else:
            out.append(CONFUSABLES.get(char, char))
    return "".join(out)


def mixed_scripts(domain: str) -> list[str]:
    """Scripts present in the domain's letter labels (decoded form)."""
    scripts = set()
    for char in domain:
        if char.isalpha():
            script = _script_of(char)
            if script:
                scripts.add(script)
    return sorted(scripts)


def analyse_domain(host: str, registrable_fn, brands: dict) -> dict:
    """Assess one host for homograph / mixed-script abuse.

    ``registrable_fn`` and ``brands`` come from urls.py so both
    modules share one brand list and one registrable heuristic.
    Returns the decoded domain, its skeleton, the scripts present,
    and the brand the domain imitates (if any).
    """
    decoded = decode_punycode(host.lower())
    skel = skeleton(decoded)
    scripts = mixed_scripts(decoded)
    imitates = None
    actual_reg = registrable_fn(decoded)
    skeleton_reg = registrable_fn(skel)
    for official in brands.values():
        if skeleton_reg == official and actual_reg != official:
            imitates = official
            break
    return {
        "decoded": decoded,
        "skeleton": skel,
        "scripts": scripts,
        "mixed_script": len([s for s in scripts if s in ("latin", "cyrillic", "greek")]) > 1,
        "imitates": imitates,
    }
