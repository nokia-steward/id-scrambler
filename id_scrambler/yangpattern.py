"""YANG/XSD pattern handling for the scrambler.

© 2026 Nokia
Licensed under the BSD 3-Clause License
SPDX-License-Identifier: BSD-3-Clause

YANG ``pattern`` statements use the XML Schema (XSD) regular-expression
flavor and may be written as several quoted string fragments joined with
``+`` (string concatenation), exactly as they appear in a YANG model::

    '(([0-9]|...)\\.){3}'
  +  '([0-9]|...)'
  + '(%[\\p{N}\\p{L}]+)?'

This module turns that source text into a single Python ``re`` pattern.

Translation notes / known limitations (v1):
- YANG patterns are implicitly anchored against a whole value. The scrambler
  instead searches for matches *within* a line (``finditer``), so we do NOT
  add ``^``/``$`` anchors here.
- ``\\p{L}`` and ``\\p{N}``/``\\p{Nd}`` are translated. Outside a character
  class they map to Unicode-aware equivalents; inside a character class
  (where Python cannot nest classes) they fall back to ASCII ranges.
- Exotic XSD constructs (character-class subtraction ``[a-z-[aeiou]]``,
  the ``\\i``/``\\c`` XML name escapes, and uncommon ``\\p{...}`` categories)
  are not supported and raise ``ValueError``. Installing the third-party
  ``regex`` module would be the path to full ``\\p{...}`` fidelity later.
"""

from __future__ import annotations

import re

__all__ = ["compile_pattern", "parse_yang_pattern", "xsd_to_python"]


def parse_yang_pattern(raw: str) -> str:
    """Concatenate the quoted fragments of a YANG pattern statement.

    If the text contains no quoted fragments it is treated as a single
    pattern and returned with surrounding whitespace stripped.
    """
    text = raw.strip()
    if not text:
        return ""

    fragments: list[str] = []
    i = 0
    n = len(text)
    found_quote = False
    while i < n:
        ch = text[i]
        if ch in ("'", '"'):
            found_quote = True
            quote = ch
            j = i + 1
            buf = []
            while j < n and text[j] != quote:
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ValueError("unterminated quoted fragment in match-pattern")
            fragments.append("".join(buf))
            i = j + 1
        elif ch in "+ \t\r\n":
            # concatenation operator / whitespace between fragments
            i += 1
        else:
            # Non-quoted, non-operator content. If we never saw quotes this is
            # a bare pattern; bail out and return it verbatim.
            if not found_quote:
                return text
            raise ValueError(
                f"unexpected character {ch!r} between YANG pattern fragments"
            )

    if not found_quote:
        return text
    return "".join(fragments)


_PROP_OUTSIDE = {
    "L": r"[^\W\d_]",  # any Unicode letter
    "N": r"\d",  # any number (approx: decimal digits, Unicode-aware)
    "Nd": r"\d",
}

_PROP_INSIDE = {
    "L": "A-Za-z",  # nested classes are illegal in Python -> ASCII fallback
    "N": "0-9",
    "Nd": "0-9",
}


def xsd_to_python(pattern: str) -> str:
    """Translate XSD-regex specifics into a Python ``re`` compatible string."""
    out: list[str] = []
    i = 0
    n = len(pattern)
    in_class = False  # inside a [...] character class
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt in ("p", "P"):
                # \p{Name} or \P{Name}
                if i + 2 >= n or pattern[i + 2] != "{":
                    raise ValueError("malformed \\p escape in pattern")
                close = pattern.find("}", i + 3)
                if close == -1:
                    raise ValueError("unterminated \\p{...} escape in pattern")
                name = pattern[i + 3 : close]
                negate = nxt == "P"
                out.append(_translate_property(name, negate, in_class))
                i = close + 1
                continue
            if nxt in ("i", "c", "I", "C"):
                raise ValueError(
                    f"unsupported XSD escape \\{nxt} in pattern (XML name classes)"
                )
            # keep any other escape as-is (e.g. \. \d \w \s)
            out.append(ch)
            out.append(nxt)
            i += 2
            continue
        if ch == "[":
            # detect XSD class subtraction: [...-[...]]
            in_class = True
            out.append(ch)
            i += 1
            continue
        if ch == "]":
            in_class = False
            out.append(ch)
            i += 1
            continue
        if in_class and ch == "-" and i + 1 < n and pattern[i + 1] == "[":
            raise ValueError("XSD character-class subtraction is not supported in v1")
        out.append(ch)
        i += 1
    return "".join(out)


def _translate_property(name: str, negate: bool, in_class: bool) -> str:
    table = _PROP_INSIDE if in_class else _PROP_OUTSIDE
    if name not in table:
        raise ValueError(f"unsupported Unicode property \\p{{{name}}} in pattern")
    repl = table[name]
    if not negate:
        return repl
    # Negation: only well-defined for the outside-class, single-escape forms.
    if in_class:
        raise ValueError(
            f"negated property \\P{{{name}}} unsupported inside a character class"
        )
    if repl == r"\d":
        return r"\D"
    if repl == r"[^\W\d_]":
        return r"[\W\d_]"
    raise ValueError(f"cannot negate \\P{{{name}}}")


# Characters that compose a "value" token. YANG patterns are implicitly
# anchored against a whole value, so when searching within a line we require
# the match to be a complete token (not glued to more value characters). This
# also forces ordered alternations such as [0-9]|[1-9][0-9]|... to consume the
# longest valid octet instead of stopping early.
#
# Note: '.' is intentionally excluded. The longest-octet behavior is driven by
# the alphanumerics in this class; including '.' would wrongly suppress a valid
# match that merely abuts a period (e.g. an IP ending a sentence).
_TOKEN_CHAR = r"[0-9A-Za-z_]"


def compile_pattern(raw_match_pattern: str, pattern_format: str) -> re.Pattern:
    """Compile a rule ``match-pattern`` into a Python regex.

    ``pattern_format`` is ``"yang"`` (XSD flavor, fragment concatenation) or
    ``"posix"`` (used as a Python regex verbatim).
    """
    fmt = (pattern_format or "yang").strip().lower()
    if fmt == "yang":
        joined = parse_yang_pattern(raw_match_pattern)
        translated = xsd_to_python(joined)
        anchored = f"(?<!{_TOKEN_CHAR})(?:{translated})(?!{_TOKEN_CHAR})"
        return re.compile(anchored, re.UNICODE)
    if fmt == "posix":
        return re.compile(raw_match_pattern.strip("\n"), re.UNICODE)
    raise ValueError(f"unknown pattern-format {pattern_format!r} (use yang or posix)")
