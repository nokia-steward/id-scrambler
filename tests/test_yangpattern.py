"""© 2026 Nokia
Licensed under the BSD 3-Clause License
SPDX-License-Identifier: BSD-3-Clause
"""

import pytest

from id_scrambler import yangpattern as yp

# The dotted-quad rule as it appears in a YANG model, used by the tests below
# that exercise the implicit-anchoring behavior.
IPV4_PATTERN = (
    "'(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}'\n"
    "+ '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'\n"
)


def test_parse_concatenates_quoted_fragments():
    raw = (
        "'(([0-9])\\.){3}'\n"
        "  + '([0-9])'\n"
        "  + '(%[\\p{N}\\p{L}]+)?'\n"
    )
    joined = yp.parse_yang_pattern(raw)
    assert joined == "(([0-9])\\.){3}([0-9])(%[\\p{N}\\p{L}]+)?"


def test_parse_bare_pattern_passthrough():
    assert yp.parse_yang_pattern("peer-as \\d+") == "peer-as \\d+"


def test_parse_empty_input_returns_empty():
    assert yp.parse_yang_pattern("") == ""
    assert yp.parse_yang_pattern("  \n\t ") == ""


def test_parse_accepts_double_and_mixed_quotes():
    assert yp.parse_yang_pattern('"ab" + "cd"') == "abcd"
    assert yp.parse_yang_pattern("'ab' + \"cd\"") == "abcd"


def test_parse_ignores_empty_fragments():
    assert yp.parse_yang_pattern("'' + 'a'") == "a"


def test_parse_unterminated_fragment_raises():
    with pytest.raises(ValueError):
        yp.parse_yang_pattern("'abc")


def test_parse_bare_text_after_fragment_raises():
    # A bare pattern is only accepted when nothing at all was quoted; once a
    # fragment appears, unquoted content is a typo rather than a pattern.
    with pytest.raises(ValueError):
        yp.parse_yang_pattern("'a' + b")
    with pytest.raises(ValueError):
        yp.parse_yang_pattern("'a' x 'b'")


def test_xsd_property_outside_class():
    assert yp.xsd_to_python("\\p{L}") == "[^\\W\\d_]"
    assert yp.xsd_to_python("\\p{N}") == "\\d"
    assert yp.xsd_to_python("\\p{Nd}") == "\\d"


def test_xsd_property_inside_class_falls_back_to_ascii():
    assert yp.xsd_to_python("[\\p{N}\\p{L}]") == "[0-9A-Za-z]"


def test_xsd_unsupported_escapes_raise():
    with pytest.raises(ValueError):
        yp.xsd_to_python("\\i")
    with pytest.raises(ValueError):
        yp.xsd_to_python("[a-z-[aeiou]]")
    with pytest.raises(ValueError):
        yp.xsd_to_python("\\p{Lu}")


def test_xsd_rejects_every_xml_name_escape():
    for escape in ("\\i", "\\c", "\\I", "\\C"):
        with pytest.raises(ValueError):
            yp.xsd_to_python(escape)


def test_xsd_negated_property_outside_class():
    assert yp.xsd_to_python("\\P{N}") == "\\D"
    assert yp.xsd_to_python("\\P{Nd}") == "\\D"
    assert yp.xsd_to_python("\\P{L}") == "[\\W\\d_]"


def test_xsd_negated_property_inside_class_raises():
    with pytest.raises(ValueError):
        yp.xsd_to_python("[\\P{L}]")


def test_xsd_malformed_property_escape_raises():
    with pytest.raises(ValueError):
        yp.xsd_to_python("\\p")
    with pytest.raises(ValueError):
        yp.xsd_to_python("\\pL")
    with pytest.raises(ValueError):
        yp.xsd_to_python("\\p{L")


def test_xsd_preserves_ordinary_escapes():
    assert yp.xsd_to_python("\\.\\d\\w\\s") == "\\.\\d\\w\\s"


def test_xsd_subtraction_rejected_only_inside_class():
    # '-[' is class subtraction only within [...]; elsewhere it is a literal
    # dash followed by a new class, and must survive translation untouched.
    assert yp.xsd_to_python("a-[b]") == "a-[b]"


def test_ipv4_pattern_matches_full_token():
    raw = (
        "'(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}'\n"
        "+ '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'\n"
        "+ '(%[\\p{N}\\p{L}]+)?'\n"
    )
    pat = yp.compile_pattern(raw, "yang")
    m = pat.search("address 192.0.2.54/30")
    assert m is not None
    # Implicit-anchoring fix: must grab the whole address, not "192.0.2.5".
    assert m.group(0) == "192.0.2.54"


def test_ipv4_pattern_with_zone_index():
    raw = (
        "'(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}'\n"
        "+ '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'\n"
        "+ '(%[\\p{N}\\p{L}]+)?'\n"
    )
    pat = yp.compile_pattern(raw, "yang")
    m = pat.search("10.0.0.1%eth0 next")
    assert m is not None and m.group(0) == "10.0.0.1%eth0"


def test_ipv4_matches_when_followed_by_period():
    raw = (
        "'(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}'\n"
        "+ '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'\n"
    )
    pat = yp.compile_pattern(raw, "yang")
    m = pat.search("Server is 10.0.0.1.")
    # A trailing sentence period must not suppress the match.
    assert m is not None and m.group(0) == "10.0.0.1"


def test_ipv4_rejects_out_of_range_octet():
    pat = yp.compile_pattern(IPV4_PATTERN, "yang")
    # Without the token guards these would match the embedded "99.0.0.1" and
    # "10.0.0.25", quietly scrambling part of an invalid address.
    assert pat.search("999.0.0.1") is None
    assert pat.search("10.0.0.256") is None


def test_ipv4_requires_token_boundaries():
    pat = yp.compile_pattern(IPV4_PATTERN, "yang")
    assert pat.search("x10.0.0.1") is None
    assert pat.search("10.0.0.1x") is None
    assert pat.search("a 1.2.3.4 b").group(0) == "1.2.3.4"


def test_unicode_property_outside_class_is_unicode_aware():
    pat = yp.compile_pattern("'\\p{L}+'", "yang")
    assert pat.search("héllo").group(0) == "héllo"


def test_unicode_property_inside_class_is_ascii_only():
    # Documented v1 limitation: Python cannot nest character classes, so a
    # \p{L} inside [...] degrades to A-Za-z and stops at the first non-ASCII.
    pat = yp.compile_pattern("'[\\p{L}]+'", "yang")
    assert pat.search("héllo").group(0) == "h"
    assert pat.search("hello").group(0) == "hello"


def test_posix_passthrough():
    pat = yp.compile_pattern("peer-as \\d+", "posix")
    assert pat.search("peer-as 65001").group(0) == "peer-as 65001"


def test_posix_is_not_token_anchored():
    # The yang path wraps the pattern in token guards; posix is used verbatim,
    # so the same text matches when glued to surrounding value characters.
    assert yp.compile_pattern("1.2.3.4", "posix").search("x1.2.3.4x") is not None
    assert yp.compile_pattern("1.2.3.4", "yang").search("x1.2.3.4x") is None


def test_default_format_is_yang():
    for fmt in (None, ""):
        pat = yp.compile_pattern("abc", fmt)
        assert pat.search("abc").group(0) == "abc"
        assert pat.search("xabc") is None


def test_format_ignores_case_and_surrounding_space():
    assert yp.compile_pattern("abc", " YANG ").search("abc") is not None
    assert yp.compile_pattern("a.c", "POSIX").search("abc") is not None


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        yp.compile_pattern("x", "perl")
