"""© 2026 Nokia
Licensed under the BSD 3-Clause License
SPDX-License-Identifier: BSD-3-Clause
"""

import hashlib
import hmac
import io
import os
import pathlib
import random
import re
import signal
import subprocess
import sys

import pytest

import id_scrambler as sc
from id_scrambler import yangpattern as yp
from id_scrambler.id_scrambler import (
    _GramIndex,
    _iter_literal_tokens,
    _LineView,
    _required_texts,
)

KEY = "0123456789abcdef0123456789abcdef"  # 32 chars, valid


def hmac_hex(value: str) -> str:
    return hmac.new(KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def make_rule(
    name,
    pattern,
    fmt="posix",
    prefix=None,
    suffix="",
    padding=False,
    enabled=True,
    ignore_match_prefix="",
    scramble_group=None,
):
    # prefix=None keeps the old convenience: it marks an "ignore" rule. Any
    # string (including "") is a scramble rule with that prefix.
    return sc.Rule(
        name=name,
        enabled=enabled,
        pattern=yp.compile_pattern(pattern, fmt),
        ignore=prefix is None,
        scramble_prefix="" if prefix is None else prefix,
        scramble_suffix=suffix,
        padding=padding,
        ignore_match_prefix=ignore_match_prefix,
        scramble_group=scramble_group,
    )


# --------------------------------------------------------------------------- #
# Key
# --------------------------------------------------------------------------- #


def test_key_passthrough_valid():
    assert sc.acquire_key("a" * 32) == "a" * 32
    assert sc.acquire_key("a" * 128) == "a" * 128


def test_key_generated_when_absent():
    key = sc.acquire_key(None)
    assert sc.KEY_MIN <= len(key.encode("utf-8")) <= sc.KEY_MAX
    # Each invocation should yield a fresh random key.
    assert sc.acquire_key(None) != key


def test_key_length_is_measured_in_utf8_bytes():
    # "é" is 2 bytes and "中" is 3 bytes in UTF-8, so fewer than KEY_MIN
    # characters can still satisfy the byte minimum.
    assert sc.acquire_key("é" * 16) == "é" * 16
    assert sc.acquire_key("中" * 11) == "中" * 11
    assert sc.acquire_key("😀" * 8) == "😀" * 8


def test_key_multibyte_too_short_exits(capsys):
    # 10 Chinese characters are 30 bytes, below the 32-byte minimum.
    with pytest.raises(SystemExit) as exc:
        sc.acquire_key("中" * 10)
    assert exc.value.code == 1
    assert (
        "key must be a minimum of 32 bytes"
        in capsys.readouterr().err
    )


def test_key_multibyte_too_long_exits(capsys):
    # 43 Chinese characters are 129 bytes, above the 128-byte maximum,
    # even though they are well below 128 characters.
    with pytest.raises(SystemExit) as exc:
        sc.acquire_key("中" * 43)
    assert exc.value.code == 1
    assert (
        "key must be a maximum of 128 bytes"
        in capsys.readouterr().err
    )


def test_key_is_nfc_normalized():
    composed = "\u00e9" * 16  # precomposed "é", 32 bytes
    decomposed = "e\u0301" * 16  # "e" + combining acute accent, 48 bytes
    assert composed != decomposed
    assert sc.acquire_key(decomposed) == composed
    assert sc.acquire_key(composed) == composed


def test_nfc_equivalent_keys_scramble_identically():
    composed = sc.acquire_key("\u00e9" * 16)
    decomposed = sc.acquire_key("e\u0301" * 16)
    a = sc.Scrambler(composed, [])
    b = sc.Scrambler(decomposed, [])
    assert a.scramble("10.0.0.1", "IP-", "", False) == b.scramble(
        "10.0.0.1", "IP-", "", False
    )


def test_key_bounds_apply_after_normalization(capsys):
    # 11 decomposed "é" are 33 bytes before NFC but only 22 bytes after, so
    # the key is rejected rather than accepted on its pre-normalized length.
    with pytest.raises(SystemExit) as exc:
        sc.acquire_key("e\u0301" * 11)
    assert exc.value.code == 1
    assert "key must be a minimum of 32 bytes" in capsys.readouterr().err


def test_key_with_unencodable_surrogate_exits(capsys):
    # Undecodable argv bytes (POSIX surrogateescape) or a lone UTF-16
    # surrogate (Windows) reach Python as surrogate code points.
    with pytest.raises(SystemExit) as exc:
        sc.acquire_key("a" * 32 + "\udcff")
    assert exc.value.code == 1
    assert (
        "key contains characters that cannot be encoded as UTF-8"
        in capsys.readouterr().err
    )


def test_key_debug_reports_where_the_key_came_from(capsys):
    sc.acquire_key("a" * 32, debug=True)
    assert "key supplied by user, using the 32-byte key" in capsys.readouterr().err
    sc.acquire_key("中" * 11, debug=True)
    assert "key supplied by user, using the 33-byte key" in capsys.readouterr().err
    sc.acquire_key(None, debug=True)
    assert "no key supplied, generated a random 32-byte key" in capsys.readouterr().err


def test_key_origin_is_not_reported_without_debug(capsys):
    sc.acquire_key("a" * 32)
    sc.acquire_key(None)
    assert capsys.readouterr().err == ""


def test_key_too_short_exits(capsys):
    with pytest.raises(SystemExit) as exc:
        sc.acquire_key("short")
    assert exc.value.code == 1
    assert (
        "key must be a minimum of 32 bytes"
        in capsys.readouterr().err
    )


def test_key_too_long_exits(capsys):
    with pytest.raises(SystemExit) as exc:
        sc.acquire_key("a" * 129)
    assert exc.value.code == 1
    assert (
        "key must be a maximum of 128 bytes"
        in capsys.readouterr().err
    )


# --------------------------------------------------------------------------- #
# Hashing / scrambling
# --------------------------------------------------------------------------- #


def test_hash_is_hmac_sha256_truncated_to_eight():
    s = sc.Scrambler(KEY, [])
    value = "hello-world"
    expected = hmac_hex(value)
    out = s.scramble(value, "STR-", "", padding=False)
    assert out == "STR-" + expected[:8]


def test_padding_matches_length_of_input():
    s = sc.Scrambler(KEY, [])
    matched = "Interface name 2 with spaces"  # 28 chars
    out = s.scramble(matched, "STR-", "", padding=True)
    assert len(out) == len(matched)
    assert out.startswith("STR-")
    full = hmac_hex(matched)
    assert out == "STR-" + full[: len(matched) - len("STR-")]


def test_padding_overflow_uses_lowercase_alnum():
    s = sc.Scrambler(KEY, [])
    matched = "x" * 100  # longer than prefix + 64
    out = s.scramble(matched, "STR-", "", padding=True)
    assert len(out) == 100
    full = hmac_hex(matched)
    body = out[len("STR-") :]
    assert body.startswith(full)  # full 64-char hash preserved
    pad = body[len(full) :]
    assert pad  # padding was actually appended beyond the hash
    assert all(c in sc.PAD_ALPHABET for c in pad)


def test_padding_overflow_with_suffix_keeps_suffix_at_end():
    s = sc.Scrambler(KEY, [])
    matched = "x" * 100
    out = s.scramble(matched, "STR-", "!", padding=True)
    assert len(out) == 100
    assert out.startswith("STR-")
    assert out.endswith("!")
    pad = out[len("STR-") + 64 : -len("!")]
    assert all(c in sc.PAD_ALPHABET for c in pad)


def test_padding_overflow_is_deterministic():
    s = sc.Scrambler(KEY, [])
    matched = "y" * 120
    first = s.scramble(matched, "STR-", "", padding=True)
    second = s.scramble(matched, "STR-", "", padding=True)
    assert first == second


def test_collision_extends_body_length():
    s = sc.Scrambler(KEY, [])
    value = "collide-me"
    full = hmac_hex(value)
    # Pretend the 8-char body is already taken by a different value.
    s._scramble_index[("STR-", full[:8])] = "someone-else"
    out = s.scramble(value, "STR-", "", padding=False)
    assert out != "STR-" + full[:8]
    assert out.startswith("STR-" + full[:8])  # extended, not changed
    assert len(out) > len("STR-" + full[:8])


def test_ignore_match_prefix_hashes_only_remainder():
    s = sc.Scrambler(KEY, [])
    out = s.scramble(
        "peer-as 12345", "AS-", "", padding=False, ignore_match_prefix="peer-as "
    )
    full = hmac_hex("12345")
    # The stripped prefix is preserved verbatim; only "12345" is hashed.
    assert out == "peer-as AS-" + full[:8]


def test_ignore_match_prefix_is_context_independent():
    s = sc.Scrambler(KEY, [])
    cropped = s.scramble(
        "peer-as 12345", "AS-", "", padding=False, ignore_match_prefix="peer-as "
    )
    bare = s.scramble("12345", "AS-", "", padding=False)
    # Same underlying value hashes identically regardless of the stripped part.
    assert cropped == "peer-as " + bare


def test_ignore_match_prefix_absent_hashes_whole_match():
    s = sc.Scrambler(KEY, [])
    out = s.scramble("peer-as 12345", "AS-", "", padding=False)
    full = hmac_hex("peer-as 12345")
    assert out == "AS-" + full[:8]


def test_ignore_match_prefix_spawns_rule_for_bare_value():
    rule = make_rule(
        "peer-as", r"peer-as \d+", prefix="AS-", ignore_match_prefix="peer-as "
    )
    s = sc.Scrambler(KEY, [rule])
    line1 = s.process_line("peer-as 12345")
    scramble = line1.split()[-1]  # "AS-<hash of 12345>"
    # A runtime rule was added (originals + 1 dynamic).
    assert len(s.rules) == 2
    # The bare value is now scrambled on a subsequent line, identically.
    assert s.process_line("bare 12345 here") == f"bare {scramble} here"


def test_ignore_match_prefix_spawn_not_applied_to_current_line():
    rule = make_rule(
        "peer-as", r"peer-as \d+", prefix="AS-", ignore_match_prefix="peer-as "
    )
    s = sc.Scrambler(KEY, [rule])
    # On the discovery line, the bare occurrence stays cleartext.
    out = s.process_line("peer-as 777 and bare 777")
    assert "and bare 777" in out
    assert out.startswith("peer-as AS-")


def test_ignore_match_prefix_spawn_respects_token_boundary():
    rule = make_rule(
        "peer-as", r"peer-as \d+", prefix="AS-", ignore_match_prefix="peer-as "
    )
    s = sc.Scrambler(KEY, [rule])
    s.process_line("peer-as 12345")
    # "12345" inside a larger token must not be replaced.
    assert s.process_line("value 123456 end") == "value 123456 end"


def test_literal_token_scan_matches_boundary_regex():
    # The scanner replaced a per-value compiled pattern. These spans are the
    # cases the pattern was written for, including a failed boundary that
    # overlaps a later hit.
    samples = [
        ("12345", "value 123456 end"),
        ("12345", "ASN 12345: closed"),
        ("12345", "ASN 12345:678"),
        ("12345", "ASN 12345:\nnext"),
        ("ab", "ab ab. (ab) ab: xab"),
        ("a.b", "a.b a.bc .a.b"),
        ("aa", "aaa aa"),
        ("a.a", "a.a.a"),
        ("EXAMPLE-IX ONE", "see EXAMPLE-IX ONE."),
        ("Q", "mark Q done"),
        ("foo-bar", "foo-bar: next"),
        ("é", " é: xé"),
        ("a_b", "a_b _a_b"),
    ]
    boundary = r"(?<![\w.:-]){}(?=$|[^\w.:-]|:(?=\s|$))"
    for value, line in samples:
        pattern = re.compile(boundary.format(re.escape(value)))
        expected = [(m.start(), m.end()) for m in pattern.finditer(line)]
        assert list(_iter_literal_tokens(line, value)) == expected


def test_index_lookup_never_misses_a_claimable_token():
    # The index may return extra candidates, but must return every value that
    # the token scanner would claim, whatever mix of boundary characters.
    rng = random.Random(1234)
    alphabet = "ab1:.-_ \"/é#"
    values = {"".join(rng.choices(alphabet, k=rng.randint(1, 6))) for _ in range(300)}
    index = _GramIndex()
    for value in values:
        index.add(value, value)
    for _ in range(2000):
        line = "".join(rng.choices(alphabet, k=rng.randint(0, 24)))
        found = set(index.lookup(_LineView(line)))
        for value in values:
            if any(True for _ in _iter_literal_tokens(line, value)):
                assert value in found, (value, line)


def test_ignore_match_prefix_spawn_allows_sentence_colon():
    rule = make_rule(
        "peer-as", r"peer-as \d+", prefix="AS-", ignore_match_prefix="peer-as "
    )
    s = sc.Scrambler(KEY, [rule])
    discovered = s.process_line("peer-as 12345").split()[-1]

    assert s.process_line("ASN 12345: closed") == f"ASN {discovered}: closed"
    assert s.process_line("ASN 12345:678") == "ASN 12345:678"


def test_dynamic_rule_replays_the_inner_text_of_a_quoted_literal():
    # The dynamic rule's literal is quoted. Once it has matched, the bare inner
    # text must still reach it, even though the literal itself is absent.
    rule = make_rule(
        "name", r'name "[^"]+"', prefix="STR-", ignore_match_prefix="name "
    )
    s = sc.Scrambler(KEY, [rule])
    s.process_line('name "foo-1"')
    quoted = s.process_line('x "foo-1"').split()[-1]
    assert quoted.startswith("STR-")
    assert s.process_line("y foo-1") == f"y {quoted}"


def test_dynamic_rules_skip_absent_literals_but_keep_spawn_order():
    rule = make_rule(
        "peer-as", r"peer-as \d+", prefix="AS-", ignore_match_prefix="peer-as "
    )
    s = sc.Scrambler(KEY, [rule])
    first = s.process_line("peer-as 12345").split()[-1]
    second = s.process_line("peer-as 123").split()[-1]
    for i in range(50):
        s.process_line(f"peer-as {1000 + i}")
    assert s.process_line("x 123 y 12345") == f"x {second} y {first}"


def test_ignore_match_prefix_spawn_deduplicated():
    rule = make_rule(
        "peer-as", r"peer-as \d+", prefix="AS-", ignore_match_prefix="peer-as "
    )
    s = sc.Scrambler(KEY, [rule])
    s.process_line("peer-as 12345")
    s.process_line("peer-as 12345")  # same value again
    s.process_line("peer-as 12345")
    assert len(s.rules) == 2  # only one dynamic rule ever added


# --------------------------------------------------------------------------- #
# scramble-group
# --------------------------------------------------------------------------- #


def test_scramble_group_scrambles_only_the_group():
    rule = make_rule("kv", r'="([^"]*)"', prefix="STR-", scramble_group=1)
    s = sc.Scrambler(KEY, [rule])
    full = hmac_hex("4001")
    # Only the value inside the quotes is hashed; the ="..." delimiters stay.
    assert s.process_line('filter-id="4001"') == f'filter-id="STR-{full[:8]}"'


def test_scramble_group_preserves_surrounding_text():
    rule = make_rule("kv", r'="([^"]*)"', prefix="STR-", scramble_group=1)
    s = sc.Scrambler(KEY, [rule])
    out = s.process_line('a filter-id="4001" entry-id="7" b')
    v1 = hmac_hex("4001")[:8]
    v2 = hmac_hex("7")[:8]
    assert out == f'a filter-id="STR-{v1}" entry-id="STR-{v2}" b'


def test_scramble_group_empty_group_left_unchanged():
    rule = make_rule("kv", r'="([^"]*)"', prefix="STR-", scramble_group=1)
    s = sc.Scrambler(KEY, [rule])
    # Empty value => nothing to hash, match emitted verbatim.
    assert s.process_line('type=""') == 'type=""'


def test_scramble_group_claims_full_match_span():
    # A later rule that would otherwise match the raw value must not fire,
    # because the whole match span (including the group) is claimed.
    kv = make_rule("kv", r'="([^"]*)"', prefix="STR-", scramble_group=1)
    greedy = make_rule("greedy", r"4001", prefix="NUM-")
    s = sc.Scrambler(KEY, [kv, greedy])
    full = hmac_hex("4001")
    assert s.process_line('filter-id="4001"') == f'filter-id="STR-{full[:8]}"'


def test_scramble_group_loaded_from_config(tmp_path):
    cfg = tmp_path / "ok.yml"
    cfg.write_text(
        "kv:\n"
        "  pattern-format: posix\n"
        '  match-pattern: \'="([^"]*)"\'\n'
        "  scramble-prefix: 'STR-'\n"
        "  scramble-group: 1\n"
    )
    rules = sc.load_rules(str(cfg), debug=False)
    assert rules[0].scramble_group == 1


def test_scramble_group_absent_defaults_to_none(tmp_path):
    cfg = tmp_path / "ok.yml"
    cfg.write_text(
        "r:\n"
        "  pattern-format: posix\n"
        '  match-pattern: \'"[^"]*"\'\n'
        "  scramble-prefix: 'STR-'\n"
    )
    rules = sc.load_rules(str(cfg), debug=False)
    assert rules[0].scramble_group is None


def test_scramble_group_on_ignore_rule_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text(
        "r:\n  pattern-format: posix\n  match-pattern: '(x)'\n  scramble-group: 1\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert (
        "'scramble-group' cannot be used on an ignore rule" in capsys.readouterr().err
    )


def test_scramble_group_non_integer_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text(
        "r:\n"
        "  pattern-format: posix\n"
        "  match-pattern: '(x)'\n"
        "  scramble-prefix: 'STR-'\n"
        "  scramble-group: 'one'\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "'scramble-group' must be a positive integer" in capsys.readouterr().err


def test_scramble_group_zero_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text(
        "r:\n"
        "  pattern-format: posix\n"
        "  match-pattern: '(x)'\n"
        "  scramble-prefix: 'STR-'\n"
        "  scramble-group: 0\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "'scramble-group' must be a positive integer" in capsys.readouterr().err


def test_scramble_group_out_of_range_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text(
        "r:\n"
        "  pattern-format: posix\n"
        '  match-pattern: \'="([^"]*)"\'\n'
        "  scramble-prefix: 'STR-'\n"
        "  scramble-group: 2\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "exceeds the 1 capture group(s)" in capsys.readouterr().err


def test_ignore_match_prefix_loaded_and_defaulted(tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "with:\n  pattern-format: posix\n  match-pattern: 'peer-as \\d+'\n"
        "  scramble-prefix: 'AS-'\n  ignore-match-prefix: 'peer-as '\n"
        "without:\n  pattern-format: posix\n  match-pattern: 'x'\n"
        "  scramble-prefix: 'X-'\n"
    )
    rules = {r.name: r for r in sc.load_rules(str(cfg), debug=False)}
    assert rules["with"].ignore_match_prefix == "peer-as "
    assert rules["without"].ignore_match_prefix == ""


def test_scramble_suffix_is_appended():
    s = sc.Scrambler(KEY, [])
    value = "hello-world"
    full = hmac_hex(value)
    out = s.scramble(value, "STR-", "!", padding=False)
    assert out == "STR-" + full[:8] + "!"


def test_padding_keeps_suffix_at_end():
    s = sc.Scrambler(KEY, [])
    matched = "abcdefghijklmnop"  # 16 chars
    out = s.scramble(matched, "P-", "#", padding=True)
    assert len(out) == len(matched)
    assert out.startswith("P-")
    assert out.endswith("#")


def test_empty_prefix_scrambles_without_prefix():
    rules = [make_rule("empty", r"TOKEN\d+", prefix="")]
    s = sc.Scrambler(KEY, rules)
    out = s.process_line("TOKEN12")
    full = hmac_hex("TOKEN12")
    assert out == full[:8]


# --------------------------------------------------------------------------- #
# Line processing / ordering / ignore
# --------------------------------------------------------------------------- #


def test_ignore_rule_blocks_scrambling():
    rules = [
        make_rule("ignore", r'^echo ".+"$', prefix=None),
        make_rule("quoted", r'".+"', prefix="STR-"),
    ]
    s = sc.Scrambler(KEY, rules)
    line = 'echo "keep me"'
    assert s.process_line(line) == line  # ignore rule wins, no scramble


def test_first_match_wins_per_span():
    rules = [
        make_rule("quoted", r'".+"', prefix="Q-"),
        make_rule("word", r"me", prefix="W-"),
    ]
    s = sc.Scrambler(KEY, rules)
    out = s.process_line('"call me"')
    # The whole quoted span is claimed first; "me" inside is not re-scrambled.
    assert out.startswith("Q-")
    assert "W-" not in out


def test_disabled_rule_is_skipped():
    rules = [make_rule("quoted", r'".+"', prefix="STR-", enabled=False)]
    s = sc.Scrambler(KEY, rules)
    assert s.process_line('"abc"') == '"abc"'


# --------------------------------------------------------------------------- #
# Cross-line reuse
# --------------------------------------------------------------------------- #


def test_quoted_value_reused_for_unquoted_occurrence():
    rules = [make_rule("quoted", r'".+"', prefix="STR-")]
    s = sc.Scrambler(KEY, rules)
    first = s.process_line('interface "rtr1.example"')
    scramble = first.split()[-1]
    second = s.process_line("  Dyn[I] rtr1.example")
    assert second.endswith(scramble)


def test_quoted_value_reused_before_sentence_colon():
    rules = [make_rule("quoted", r'"([^"]+)"', prefix="STR-", scramble_group=1)]
    s = sc.Scrambler(KEY, rules)
    scramble = s.process_line('group "EBGP"').split()[-1].strip('"')

    assert s.process_line("Group EBGP: Peer") == f"Group {scramble}: Peer"
    assert s.process_line("Group EBGP:secondary") == "Group EBGP:secondary"


def test_reuse_emits_existing_match_debug_line(capsys):
    rules = [make_rule("quoted", r'".+"', prefix="STR-")]
    s = sc.Scrambler(KEY, rules, debug=True)
    first = s.process_line('description "EXAMPLE-IX ONE"')
    scramble = first.split()[-1]
    capsys.readouterr()  # discard the first line's debug output
    s.process_line("EXAMPLE-IX ONE up")
    err = capsys.readouterr().err
    assert f"EXISTING MATCH: 'EXAMPLE-IX ONE' REPLACED WITH: '{scramble}'" in err


def test_ignore_rule_emits_debug_line_even_when_unchanged(capsys):
    rules = [make_rule("ignore-banner", r"^#-+$", prefix=None)]
    s = sc.Scrambler(KEY, rules, debug=True)
    line = "#--------"
    out = s.process_line(line)
    assert out == line  # ignore rule keeps the line cleartext
    err = capsys.readouterr().err
    assert f"RULE: ignore-banner MATCHED: '{line}' IGNORED (kept cleartext)" in err
    assert f"CLEARTEXT : {line}" in err
    assert f"SCRAMBLED : {line}" in err


def test_reuse_does_not_touch_ignore_protected_text():
    rules = [
        make_rule("keep", r"# keep: keepme", prefix=None),
        make_rule("quoted", r'".+"', prefix="STR-"),
    ]
    s = sc.Scrambler(KEY, rules)
    s.process_line('set name "keepme"')  # registers inner value 'keepme'
    out = s.process_line("# keep: keepme")
    # The ignore rule is listed first, so it claims this span before the quoting
    # rule's cache is consulted, and reuse cannot scramble 'keepme'.
    assert out == "# keep: keepme"


def test_a_rules_own_scramble_survives_a_later_rules_pattern():
    # A value stays in the form its own rule gave it: the rule's cache is
    # consulted before the rules listed after it get a turn.
    rules = [
        make_rule("quoted-string", r'"([^"]*)"', prefix="STR-", scramble_group=1),
        make_rule("string", "int-example-1", prefix="TST-"),
    ]
    s = sc.Scrambler(KEY, rules)

    quoted = s.process_line('interface "int-example-1"')
    scramble = quoted.split()[-1].strip('"')
    assert scramble.startswith("STR-")

    # The bare name matches the 'string' rule too, but the quoting rule owns it.
    assert s.process_line("192.168.10.1 int-example-1") == f"192.168.10.1 {scramble}"
    assert "TST-" not in s.process_line("10.0.0.1 int-example-1")


def test_the_first_listed_rule_owns_a_value_both_rules_match():
    # The mirror image: with the plain rule first, it claims the name even
    # inside the quotes, and its form is the one that persists.
    rules = [
        make_rule("string", "int-example-1", prefix="TST-"),
        make_rule("quoted-string", r'"([^"]*)"', prefix="STR-", scramble_group=1),
    ]
    s = sc.Scrambler(KEY, rules)

    quoted = s.process_line('interface "int-example-1"')
    scramble = quoted.split()[-1].strip('"')
    assert scramble.startswith("TST-")
    assert s.process_line("192.168.10.1 int-example-1") == f"192.168.10.1 {scramble}"


def test_reuse_prefers_the_longer_cached_value():
    # The shorter value is cached first. Reuse must still claim the longer one
    # as a whole, which only holds if the bucket is walked longest-first.
    rules = [make_rule("quoted", r'"([^"]*)"', prefix="STR-", scramble_group=1)]
    s = sc.Scrambler(KEY, rules)
    short = s.process_line('id "ab"').split()[-1].strip('"')
    long = s.process_line('id "abc"').split()[-1].strip('"')

    assert s.process_line("abc later") == f"{long} later"
    assert s.process_line("ab later") == f"{short} later"


def test_reuse_finds_a_value_cached_among_many():
    rules = [make_rule("quoted", r'"([^"]*)"', prefix="STR-", scramble_group=1)]
    s = sc.Scrambler(KEY, rules)
    target = "host-0123.example"
    wanted = None
    for i in range(300):
        token = f"host-{i:04d}.example"
        out = s.process_line(f'"{token}"').strip('"')
        if token == target:
            wanted = out
    assert s.process_line(f"peer {target} up") == f"peer {wanted} up"


def test_reuse_finds_a_single_character_value():
    rules = [make_rule("quoted", r'"([^"]*)"', prefix="STR-", scramble_group=1)]
    s = sc.Scrambler(KEY, rules)
    wanted = s.process_line('"Q"').strip('"')
    assert s.process_line("mark Q done") == f"mark {wanted} done"


def test_reuse_replays_a_value_scrambled_earlier_on_the_same_line():
    rules = [make_rule("quoted", r'"([^"]*)"', prefix="STR-", scramble_group=1)]
    s = sc.Scrambler(KEY, rules)
    out = s.process_line('name "foo-1" alias foo-1')
    scramble = out.split()[1].strip('"')
    assert out == f'name "{scramble}" alias {scramble}'


@pytest.mark.parametrize(
    ("pattern", "flags", "expected"),
    [
        (r"peer-as \d+", 0, ("peer-as ",)),
        (r"rd-entry (\d+):(\d+)", 0, ("rd-entry ", ":")),
        (r'"([^"]*)"', 0, ('"',)),
        (r"peer-as|local-as", 0, ("-", "a", "s")),
        (r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", 0, (":",)),
        (r"\d+(\.\d+){3}", 0, (".",)),
        (r"a(?:b|c)?", 0, ("a",)),
        (r"x*y{0,2}", 0, ()),
        (r"(?=q)\w", 0, ()),
        (r"(?i:k)z", 0, ("z",)),
        (r"[z]", 0, ("z",)),
        (r"[yz]", 0, ()),
        (r"peer-as \d+", re.IGNORECASE, ()),
        (r"(?i)peer-as \d+", 0, ()),
        (r"ab?c", 0, ("a", "c")),
    ],
)
def test_required_texts_are_only_what_every_match_contains(pattern, flags, expected):
    assert _required_texts(re.compile(pattern, flags)) == expected


def test_required_texts_never_reject_a_line_the_rule_matches():
    rules = sc.load_rules(
        str(pathlib.Path(sc.__file__).parent / "sr_os_rules.yml"), debug=False
    )
    lines = [
        "  mac 0a:1b:2c:3d:4e:5f",
        "interface 10.1.2.3/24 and 192.0.2.1",
        "neighbor fe80::1 and 2001:db8::/32 down",
        "peer-as 64511",
        'description "x"',
        "|::::\\|",
        "0.0.0.0/0 default",
    ]
    for rule in rules:
        need = _required_texts(rule.pattern)
        for line in lines:
            if rule.pattern.search(line):
                assert all(text in line for text in need), (rule.name, line)


def test_each_rule_caches_only_the_values_it_scrambled():
    ip = make_rule("ip", r"\d+\.\d+\.\d+\.\d+", prefix="IP-")
    quoted = make_rule("quoted", r'"([^"]*)"', prefix="STR-", scramble_group=1)
    s = sc.Scrambler(KEY, [ip, quoted])

    s.process_line('addr 192.168.10.7 name "example"')

    assert set(s._owned[ip]) == {"192.168.10.7"}
    assert set(s._owned[quoted]) == {"example"}


def test_a_cached_value_outranks_an_ignore_rule_listed_after_its_rule():
    # The flip side of consulting a rule's cache before the later rules: an
    # ignore rule only keeps a value cleartext if it is listed ahead of the rule
    # that scrambles it.
    rules = [
        make_rule("quoted", r'"([^"]*)"', prefix="STR-", scramble_group=1),
        make_rule("keep", "keepme", prefix=None),
    ]
    s = sc.Scrambler(KEY, rules)

    scramble = s.process_line('set name "keepme"').split()[-1].strip('"')

    assert s.process_line("# keep: keepme") == f"# keep: {scramble}"


def test_same_value_scrambles_consistently():
    rules = [make_rule("ip", r"\d+\.\d+\.\d+\.\d+", prefix="IP-")]
    s = sc.Scrambler(KEY, rules)
    a = s.process_line("addr 192.0.2.54 here")
    b = s.process_line("again 192.0.2.54 there")
    assert a.split()[1] == b.split()[1]


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #


def test_unrecognized_key_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("r1:\n  match-pattern: 'x'\n  bogus-key: true\n")
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "unrecognized key" in capsys.readouterr().err


def test_non_boolean_enabled_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("r1:\n  match-pattern: 'x'\n  enabled: 'false'\n")
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "'enabled' must be true or false" in capsys.readouterr().err


def test_output_padding_key_is_honored(tmp_path):
    cfg = tmp_path / "ok.yml"
    cfg.write_text(
        "r1:\n"
        "  pattern-format: posix\n"
        '  match-pattern: \'"[^"]+"\'\n'
        "  scramble-prefix: 'STR-'\n"
        "  output-padding: true\n"
    )
    rules = sc.load_rules(str(cfg), debug=False)
    assert rules[0].padding is True


def test_old_padding_key_now_rejected(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("r1:\n  match-pattern: 'x'\n  padding: true\n")
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "unrecognized key(s): padding" in capsys.readouterr().err


def test_non_boolean_output_padding_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("r1:\n  match-pattern: 'x'\n  output-padding: 'yes'\n")
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "'output-padding' must be true or false" in capsys.readouterr().err


def test_missing_match_pattern_exits(tmp_path, capsys):
    cfg = tmp_path / "bad.yml"
    cfg.write_text("r1:\n  scramble-prefix: 'X-'\n")
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "missing required 'match-pattern'" in capsys.readouterr().err


def test_missing_config_exits(tmp_path, capsys):
    with pytest.raises(SystemExit):
        sc.load_rules(str(tmp_path / "nope.yml"), debug=False)
    assert "cannot open configuration file" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content",
    ["", "   \n\n   \n", "# only a comment\n", "---\n", "{}\n", "null\n"],
    ids=["zero-byte", "blank", "comment-only", "doc-marker", "empty-map", "null"],
)
def test_a_config_defining_no_rules_is_rejected(tmp_path, capsys, content):
    # Running with nothing to apply would copy the input through unscrambled.
    cfg = tmp_path / "empty.yml"
    cfg.write_text(content)

    with pytest.raises(SystemExit) as exc:
        sc.load_rules(str(cfg), debug=False)

    assert exc.value.code == 1
    assert f"no rules are defined in {cfg}" in capsys.readouterr().err


def test_a_config_defining_no_rules_stops_the_run(tmp_path, capsys):
    # With no rules nothing would match, so the input would be copied through in
    # the clear. The run has to stop before it writes anything.
    cfg = tmp_path / "empty.yml"
    cfg.write_text("")
    src = tmp_path / "in.txt"
    src.write_text('autonomous-system 64511 "desc"\n192.0.2.4\n')

    argv = ["-k", KEY, "-c", str(cfg), str(src)]
    with pytest.raises(SystemExit) as exc:
        sc.main(argv)

    assert exc.value.code == 1
    assert f"no rules are defined in {cfg}" in capsys.readouterr().err
    assert not (tmp_path / "in.txt.scrm").exists()


def test_rules_preserve_order(tmp_path):
    cfg = tmp_path / "ok.yml"
    cfg.write_text(
        "first:\n  match-pattern: 'a'\n"
        "second:\n  match-pattern: 'b'\n"
        "third:\n  match-pattern: 'c'\n"
    )
    rules = sc.load_rules(str(cfg), debug=False)
    assert [r.name for r in rules] == ["first", "second", "third"]


def test_duplicate_rule_name_is_rejected(tmp_path, capsys):
    # Plain YAML keeps only the last of a repeated key, so the first rule and
    # whatever it was meant to scramble would disappear without a word.
    cfg = tmp_path / "dup.yml"
    cfg.write_text(
        "keep:\n  match-pattern: 'a'\n  scramble-prefix: 'A-'\n"
        "dup:\n  match-pattern: 'b'\n  scramble-prefix: 'B-'\n"
        "dup:\n  match-pattern: 'c'\n  scramble-prefix: 'C-'\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    err = capsys.readouterr().err
    assert "duplicate key 'dup'" in err
    assert "(line 7)" in err  # the repeat, not the first definition


def test_duplicate_setting_inside_a_rule_is_rejected(tmp_path, capsys):
    # Same silent loss one level down: the second match-pattern would win.
    cfg = tmp_path / "dup.yml"
    cfg.write_text(
        "r:\n  match-pattern: 'a'\n  scramble-prefix: 'A-'\n  match-pattern: 'b'\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    err = capsys.readouterr().err
    assert "duplicate key 'match-pattern'" in err
    assert "(line 4)" in err


def test_rule_names_that_differ_only_in_yaml_type_are_rejected(tmp_path, capsys):
    # 1 and "1" are separate keys to YAML but the same rule name to the tool.
    cfg = tmp_path / "dup.yml"
    cfg.write_text(
        "1:\n  match-pattern: 'a'\n  scramble-prefix: 'A-'\n"
        "'1':\n  match-pattern: 'b'\n  scramble-prefix: 'B-'\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "rule '1': defined more than once" in capsys.readouterr().err


def test_a_merge_key_can_still_override_what_it_inherits(tmp_path):
    # "<<" is inheritance syntax, so a setting the rule also states itself is an
    # override rather than a repeat, and the duplicate check must allow it.
    cfg = tmp_path / "merge.yml"
    cfg.write_text(
        "r1: &common\n  match-pattern: 'aaa'\n  scramble-prefix: 'X-'\n"
        "r2:\n  <<: *common\n  match-pattern: 'bbb'\n"
    )

    rules = sc.load_rules(str(cfg), debug=False)

    assert [r.name for r in rules] == ["r1", "r2"]
    assert [r.scramble_prefix for r in rules] == ["X-", "X-"]  # inherited
    assert rules[1].pattern.search("bbb") is not None  # overridden
    assert rules[1].pattern.search("aaa") is None


def test_a_key_repeated_beside_a_merge_key_is_still_rejected(tmp_path, capsys):
    cfg = tmp_path / "merge.yml"
    cfg.write_text(
        "r1: &common\n  match-pattern: 'aaa'\n  scramble-prefix: 'X-'\n"
        "r2:\n  <<: *common\n  match-pattern: 'bbb'\n  match-pattern: 'ccc'\n"
    )
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "duplicate key 'match-pattern' (line 7)" in capsys.readouterr().err


def test_an_unhashable_key_is_left_to_the_yaml_loader(tmp_path, capsys):
    # The duplicate check cannot hash such a key, so the loader's own complaint
    # has to survive rather than turn into a TypeError.
    cfg = tmp_path / "odd.yml"
    cfg.write_text("? [a, b]\n: value\n")
    with pytest.raises(SystemExit):
        sc.load_rules(str(cfg), debug=False)
    assert "found unhashable key" in capsys.readouterr().err


def test_discover_config_single(tmp_path, monkeypatch):
    (tmp_path / "only.yml").write_text("r:\n  match-pattern: 'a'\n")
    monkeypatch.chdir(tmp_path)
    assert sc.discover_config() == os.path.join(".", "only.yml")


def test_discover_config_multiple_exits(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.yml").write_text("r:\n  match-pattern: 'a'\n")
    (tmp_path / "b.yml").write_text("r:\n  match-pattern: 'b'\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        sc.discover_config()
    assert exc.value.code == 1
    assert "multiple YAML files found, use -c to specify the file" in (
        capsys.readouterr().err
    )


def test_discover_config_none_exits(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        sc.discover_config()
    assert exc.value.code == 1
    assert "no YAML file found, use -c to specify the file" in capsys.readouterr().err


def test_discover_config_ignores_the_rules_file_shipped_with_the_package(
    tmp_path, monkeypatch, capsys
):
    # The package ships rulesets as package data, and will ship more than one.
    # None of them may be picked up implicitly: a run always names its ruleset.
    assert SHIPPED_CONFIG.is_file()
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit):
        sc.discover_config()

    assert "no YAML file found" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Output naming
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "inp,expected",
    [(None, "stdin.scrm"), ("-", "stdin.scrm"), ("foo.txt", "foo.txt.scrm")],
)
def test_output_path_for(inp, expected):
    assert sc.output_path_for(inp) == expected


def test_output_stdout_writes_to_stdout(tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text('name "secret"\n')
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "q:\n"
        "  match-pattern: '\".+\"'\n"
        "  pattern-format: posix\n"
        "  scramble-prefix: 'STR-'\n"
    )
    argv = ["-k", KEY, "-c", str(cfg), "-o", "stdout", str(src)]
    assert sc.main(argv) == 0
    out = capsys.readouterr().out
    assert "STR-" in out
    # No ".scrm" file and no file literally named "stdout" should be created.
    assert not (tmp_path / "in.txt.scrm").exists()
    assert not (tmp_path / "stdout").exists()


def test_named_file_reports_line_progress(tmp_path, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text("first\nsecond\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'nomatch'\n  scramble-prefix: 'X-'\n")
    events = []

    class FakeProgress:
        def __init__(self, **kwargs):
            events.append(("start", kwargs))

        def update(self, amount):
            events.append(("update", amount))

        def close(self):
            events.append(("close", None))

    monkeypatch.setattr(sc.id_scrambler, "tqdm", FakeProgress)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 0
    assert events == [
        (
            "start",
            {
                "total": 2,
                "desc": "in.txt ",
                "unit": "line",
                "bar_format": "{l_bar}{bar}| {n_fmt}/{total_fmt} lines",
                "ascii": " .",
            },
        ),
        ("update", 1),
        ("update", 1),
        ("close", None),
    ]


def test_progress_filenames_are_padded_to_equal_width(tmp_path, monkeypatch):
    short = tmp_path / "a.txt"
    long = tmp_path / "much-longer.txt"
    short.write_text("first\n")
    long.write_text("second\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'nomatch'\n  scramble-prefix: 'X-'\n")
    descriptions = []

    class FakeProgress:
        def __init__(self, **kwargs):
            descriptions.append(kwargs["desc"])

        def update(self, _amount):
            pass

        def close(self):
            pass

    monkeypatch.setattr(sc.id_scrambler, "tqdm", FakeProgress)

    argv = ["-k", KEY, "-c", str(cfg), str(short), str(long)]
    assert sc.main(argv) == 0
    assert descriptions == ["a.txt           ", "much-longer.txt "]
    assert len(descriptions[0]) == len(descriptions[1])


def test_progress_escapes_control_chars_in_filename(tmp_path, monkeypatch, capsys):
    src = tmp_path / "abc\rdef.cfg"
    short = tmp_path / "a.cfg"
    src.write_text("one\ntwo\nthree\n")
    short.write_text("x\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'nomatch'\n  scramble-prefix: 'X-'\n")
    descriptions = []

    class FakeProgress:
        def __init__(self, **kwargs):
            descriptions.append(kwargs["desc"])

        def update(self, _amount):
            pass

        def close(self):
            pass

    monkeypatch.setattr(sc.id_scrambler, "tqdm", FakeProgress)

    argv = ["-k", KEY, "-c", str(cfg), str(src), str(short)]
    assert sc.main(argv) == 0
    assert descriptions == ["abc^Mdef.cfg ", "a.cfg        "]
    assert len(descriptions[0]) == len(descriptions[1])
    assert all("\r" not in desc for desc in descriptions)
    err = capsys.readouterr().err
    assert "\r" not in err
    assert "abc^Mdef.cfg : Scrambled 0 strings\n" in err
    assert (tmp_path / "abc\rdef.cfg.scrm").exists()


@pytest.mark.parametrize("input_mode", ["stdin", "debug"])
def test_progress_is_disabled_for_stdin_and_debug(input_mode, tmp_path, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text("line\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'nomatch'\n  scramble-prefix: 'X-'\n")

    def unexpected_progress(**_kwargs):
        raise AssertionError("progress bar should be disabled")

    monkeypatch.setattr(sc.id_scrambler, "tqdm", unexpected_progress)
    argv = ["-k", KEY, "-c", str(cfg)]
    if input_mode == "stdin":
        monkeypatch.setattr(sc.id_scrambler.sys, "stdin", io.StringIO("line\n"))
        argv += ["-o", "stdout"]
    else:
        argv += ["--debug", str(src)]

    assert sc.main(argv) == 0


def test_progress_summary_counts_each_substitution(tmp_path, monkeypatch, capsys):
    src = tmp_path / "in.txt"
    # Two substitutions on the first line and one on the second, so a
    # per-substitution tally reports 3 where a per-line one would report 2.
    src.write_text("host1 host2\nhost1\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'host[0-9]'\n  scramble-prefix: 'X-'\n")

    class FakeProgress:
        def __init__(self, **_kwargs):
            pass

        def update(self, _amount):
            pass

        def close(self):
            sys.stderr.write("BAR-CLOSED\n")

    monkeypatch.setattr(sc.id_scrambler, "tqdm", FakeProgress)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 0
    # The summary follows the finished bar rather than cutting into it.
    assert capsys.readouterr().err == "BAR-CLOSED\nin.txt : Scrambled 3 strings\n"


def test_progress_summary_count_resets_between_files(tmp_path, monkeypatch, capsys):
    first = tmp_path / "a.txt"
    first.write_text("host1 host2\n")
    second = tmp_path / "b.txt"
    second.write_text("host3\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'host[0-9]'\n  scramble-prefix: 'X-'\n")
    silence_progress(monkeypatch)

    argv = ["-k", KEY, "-c", str(cfg), str(first), str(second)]
    assert sc.main(argv) == 0
    # The second file reports only its own substitution, not a running total,
    # and a count of one is reported in the singular.
    assert capsys.readouterr().err == (
        "a.txt : Scrambled 2 strings\nb.txt : Scrambled 1 string\n"
    )


@pytest.mark.parametrize("mode", ["stdin", "stdout"])
def test_substitution_total_is_reported_without_a_progress_bar(
    mode, tmp_path, monkeypatch, capsys
):
    # Neither stdin nor "-o stdout" gets a progress bar, and each still reports
    # the total for its input on stderr, where it cannot mix into the results.
    src = tmp_path / "in.txt"
    src.write_text("host1 host2\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'host[0-9]'\n  scramble-prefix: 'X-'\n")
    monkeypatch.chdir(tmp_path)  # keeps a stdin ".scrm" out of the source tree

    argv = ["-k", KEY, "-c", str(cfg)]
    if mode == "stdin":
        monkeypatch.setattr(sc.id_scrambler.sys, "stdin", io.StringIO("host1\n"))
        expected = "stdin : Scrambled 1 string\n"
    else:
        argv += ["-o", "stdout", str(src)]
        expected = "in.txt : Scrambled 2 strings\n"

    assert sc.main(argv) == 0

    captured = capsys.readouterr()
    assert captured.err == expected
    # Guard against passing vacuously: each run really did scramble something.
    if mode == "stdout":
        assert "X-" in captured.out
    else:
        assert "X-" in (tmp_path / "stdin.scrm").read_text()


@pytest.mark.parametrize("mode", ["file", "stdin", "stdout"])
def test_substitution_total_is_reported_in_debug_mode(
    mode, tmp_path, monkeypatch, capsys
):
    # Debug mode has no progress bar to carry the total, so it reports the total
    # itself, labelled with the input it belongs to and last of all the debug
    # output for that input.
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'host[0-9]'\n  scramble-prefix: 'X-'\n")
    monkeypatch.chdir(tmp_path)  # keeps a stdin ".scrm" out of the source tree

    argv = ["-k", KEY, "-c", str(cfg), "--debug"]
    if mode == "stdin":
        monkeypatch.setattr(sc.id_scrambler.sys, "stdin", io.StringIO("host1 host2\n"))
        expected = "stdin : Scrambled 2 strings\n"
    else:
        src = tmp_path / "in.txt"
        src.write_text("host1 host2\n")
        if mode == "stdout":
            argv += ["-o", "stdout"]
        argv.append(str(src))
        expected = "in.txt : Scrambled 2 strings\n"

    assert sc.main(argv) == 0
    assert capsys.readouterr().err.endswith(expected)


def test_debug_total_is_per_file_and_uses_the_singular_for_one(
    tmp_path, monkeypatch, capsys
):
    first = tmp_path / "a.txt"
    first.write_text("host1 host2\n")
    second = tmp_path / "b.txt"
    second.write_text("host3\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'host[0-9]'\n  scramble-prefix: 'X-'\n")

    argv = ["-k", KEY, "-c", str(cfg), "--debug", str(first), str(second)]
    assert sc.main(argv) == 0

    err = capsys.readouterr().err
    assert "a.txt : Scrambled 2 strings\n" in err
    assert "b.txt : Scrambled 1 string\n" in err


def test_strip_control_chars_helper():
    # C0 controls and DEL are removed; TAB and printable text are kept.
    assert sc._strip_control_chars("a\rb\x07c\x7fd") == "abcd"
    assert sc._strip_control_chars("\tkeep\ttabs") == "\tkeep\ttabs"
    assert sc._strip_control_chars("plain text") == "plain text"


def test_escape_control_chars_helper():
    assert sc._escape_control_chars("abc\rdef.cfg") == "abc^Mdef.cfg"
    assert sc._escape_control_chars("a\x07b\x7fc") == "a^Gb^?c"
    assert sc._escape_control_chars("a\tb") == "a^Ib"
    assert sc._escape_control_chars("plain text") == "plain text"
    assert sc._escape_control_chars("a *$.cfg'\"") == "a *$.cfg'\""
    assert sc._escape_control_chars("a\x9bb") == "a\\u009bb"
    assert sc._escape_control_chars("a\u2028b") == "a\\u2028b"
    assert sc._escape_control_chars("a\u202eb") == "a\\u202eb"


def test_control_chars_are_stripped(tmp_path, capsys):
    src = tmp_path / "in.txt"
    # Lone CR (^M), BEL (^G), and the CR of a CRLF ending are all stripped;
    # output line endings are normalized to LF.
    src.write_bytes(b"peer-as 65001\rmid\x07tail\n\tindented\r\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(
        "p:\n"
        "  match-pattern: 'peer-as \\d+'\n"
        "  pattern-format: posix\n"
        "  scramble-prefix: 'AS-'\n"
    )
    argv = ["-k", KEY, "-c", str(cfg), "-o", "stdout", str(src)]
    assert sc.main(argv) == 0
    out = capsys.readouterr().out
    assert "\x07" not in out  # BEL stripped
    assert "\r" not in out  # all carriage returns stripped (CRLF -> LF)
    assert "midtail" in out  # stray ^M/^G removed, tokens joined
    assert "AS-" in out  # the match before the ^M was still scrambled
    assert "\tindented\n" in out  # TAB kept, CRLF ending normalized to LF


def test_control_chars_stripped_at_every_line_position(tmp_path, capsys):
    # BEL (^G) and CR (^M) must be stripped regardless of where they sit:
    #   line 1: mid-line
    #   line 2: immediately before the LF
    #   line 3: before a CRLF ending (both ^G and ^M go)
    #   line 4: at end-of-file with no trailing newline
    src = tmp_path / "in.txt"
    src.write_bytes(b"aaa\x07bbb\nccc\x07\nddd\x07\r\neee\x07")
    cfg = tmp_path / "c.yml"
    cfg.write_text("x:\n  match-pattern: 'zzzznomatch'\n  scramble-prefix: 'X-'\n")
    argv = ["-k", KEY, "-c", str(cfg), "-o", "stdout", str(src)]
    assert sc.main(argv) == 0
    out = capsys.readouterr().out
    assert "\x07" not in out  # BEL removed in every position
    assert "\r" not in out  # CR removed in every position (incl. before CRLF)
    # Exact output: control chars gone, CRLF -> LF, and no trailing newline is
    # invented for the final unterminated line.
    assert out == "aaabbb\nccc\nddd\neee"


def test_stdin_combined_with_file_exits(tmp_path, capsys):
    f1 = tmp_path / "a.txt"
    f1.write_text("x\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'z'\n  scramble-prefix: 'Z-'\n")
    argv = ["-k", KEY, "-c", str(cfg), "-", str(f1)]
    with pytest.raises(SystemExit):
        sc.main(argv)
    assert "cannot combine stdin (-) with other input files" in capsys.readouterr().err


def test_multiple_files_with_output_exits(tmp_path, capsys, monkeypatch):
    f1 = tmp_path / "a.txt"
    f2 = tmp_path / "b.txt"
    f1.write_text("x\n")
    f2.write_text("y\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'z'\n  scramble-prefix: 'Z-'\n")
    argv = ["-k", KEY, "-c", str(cfg), "-o", "out.txt", str(f1), str(f2)]
    with pytest.raises(SystemExit):
        sc.main(argv)
    assert "cannot be used with multiple input files" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Interrupt and error cleanup
# --------------------------------------------------------------------------- #

RULES = "r:\n  match-pattern: 'nomatch'\n  scramble-prefix: 'X-'\n"


def silence_progress(monkeypatch):
    class NoProgress:
        def __init__(self, **kwargs):
            pass

        def update(self, _amount):
            pass

        def close(self):
            pass

    monkeypatch.setattr(sc.id_scrambler, "tqdm", NoProgress)


def interrupt_after_lines(count, monkeypatch):
    """Make the scrambler raise KeyboardInterrupt once ``count`` lines are done.

    Stands in for the user pressing Ctrl+C part way through a run; the count is
    kept across input files, so a run over several files can be interrupted
    while writing any one of them.
    """
    original = sc.Scrambler.process_line
    processed = 0

    def process_line(self, line):
        nonlocal processed
        if processed >= count:
            raise KeyboardInterrupt
        processed += 1
        return original(self, line)

    monkeypatch.setattr(sc.Scrambler, "process_line", process_line)


def fail_after_lines(count, monkeypatch, exc):
    """Make the scrambler raise ``exc`` once ``count`` lines are done.

    The counterpart of ``interrupt_after_lines`` for runs that stop on a
    failure rather than on Ctrl+C, with the same partly written output file.
    """
    original = sc.Scrambler.process_line
    processed = 0

    def process_line(self, line):
        nonlocal processed
        if processed >= count:
            raise exc
        processed += 1
        return original(self, line)

    monkeypatch.setattr(sc.Scrambler, "process_line", process_line)


def test_interrupt_removes_the_partial_output_file(tmp_path, monkeypatch, capsys):
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\nthree\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    # A ".scrm" file from an earlier run, which this run never writes to.
    stale = tmp_path / "earlier.txt.scrm"
    stale.write_text("earlier run\n")
    silence_progress(monkeypatch)
    interrupt_after_lines(1, monkeypatch)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 130

    out = tmp_path / "in.txt.scrm"
    assert not out.exists()
    assert stale.read_text() == "earlier run\n"
    assert src.read_text() == "one\ntwo\nthree\n"  # input left intact
    err = capsys.readouterr().err
    assert "interrupted" in err
    assert f"removed output file: {out}" in err


def test_interrupt_removes_outputs_already_completed(tmp_path, monkeypatch):
    # Interrupted while writing the second file: the first one is finished but
    # still belongs to the aborted run, so it goes too.
    first = tmp_path / "a.txt"
    first.write_text("one\n")
    second = tmp_path / "b.txt"
    second.write_text("two\nthree\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)
    interrupt_after_lines(2, monkeypatch)

    argv = ["-k", KEY, "-c", str(cfg), str(first), str(second)]
    assert sc.main(argv) == 130

    assert not (tmp_path / "a.txt.scrm").exists()
    assert not (tmp_path / "b.txt.scrm").exists()


def test_interrupt_removes_an_output_file_it_overwrote(tmp_path, monkeypatch):
    # Re-scrambling an input truncates the existing ".scrm", so that file holds
    # nothing but this run's partial output and is removed with the rest.
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\n")
    out = tmp_path / "in.txt.scrm"
    out.write_text("previous result\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)
    interrupt_after_lines(1, monkeypatch)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 130
    assert not out.exists()


def test_interrupt_on_stdout_output_removes_nothing(tmp_path, monkeypatch, capsys):
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    interrupt_after_lines(1, monkeypatch)

    argv = ["-k", KEY, "-c", str(cfg), "-o", "stdout", str(src)]
    assert sc.main(argv) == 130

    assert not (tmp_path / "stdout").exists()
    err = capsys.readouterr().err
    assert "interrupted" in err
    assert "removed output file" not in err


def test_completed_run_keeps_its_output_file(tmp_path, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 0
    assert (tmp_path / "in.txt.scrm").read_text() == "one\ntwo\n"


def test_remove_run_outputs_only_deletes_registered_files(tmp_path):
    mine = tmp_path / "mine.scrm"
    mine.write_text("this run\n")
    theirs = tmp_path / "theirs.scrm"
    theirs.write_text("another run\n")
    vanished = tmp_path / "vanished.scrm"  # registered, but already gone

    sc.reset_run_outputs()
    sc.register_run_output(str(mine))
    sc.register_run_output(str(vanished))
    sc.register_run_output(str(mine))  # registering twice reports one removal

    assert sc.remove_run_outputs() == [str(mine)]
    assert not mine.exists()
    assert theirs.read_text() == "another run\n"
    # The registry is emptied, so a repeated cleanup does nothing.
    assert sc.remove_run_outputs() == []


def test_new_run_forgets_the_outputs_of_the_previous_one(tmp_path, monkeypatch):
    src = tmp_path / "in.txt"
    src.write_text("one\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 0
    kept = tmp_path / "in.txt.scrm"

    # A second run over a different input, interrupted: the first run finished
    # cleanly, so its output must survive.
    other = tmp_path / "other.txt"
    other.write_text("two\nthree\n")
    interrupt_after_lines(1, monkeypatch)
    assert sc.main(["-k", KEY, "-c", str(cfg), str(other)]) == 130

    assert kept.read_text() == "one\n"
    assert not (tmp_path / "other.txt.scrm").exists()


def test_undecodable_input_removes_the_partial_output_file(
    tmp_path, monkeypatch, capsys
):
    src = tmp_path / "in.txt"
    src.write_bytes(b"one\ntw\xff\xfeo\nthree\n")  # not valid UTF-8
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    # A ".scrm" file from an earlier run, which this run never writes to.
    stale = tmp_path / "earlier.txt.scrm"
    stale.write_text("earlier run\n")
    silence_progress(monkeypatch)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 1

    out = tmp_path / "in.txt.scrm"
    assert not out.exists()
    assert stale.read_text() == "earlier run\n"
    assert src.read_bytes() == b"one\ntw\xff\xfeo\nthree\n"  # input left intact
    err = capsys.readouterr().err
    assert "error while scrambling in.txt: UnicodeDecodeError" in err
    assert f"removed output file: {out}" in err
    assert "Traceback" not in err  # the traceback is reserved for -d


def test_undecodable_input_in_debug_mode_removes_the_output_file(tmp_path, capsys):
    # Debug mode prints its own running commentary and no progress bar, so the
    # failure lands mid-write rather than while the lines are being counted.
    src = tmp_path / "in.txt"
    src.write_bytes(b"one\ntw\xff\xfeo\nthree\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)

    assert sc.main(["-k", KEY, "-c", str(cfg), "-d", str(src)]) == 1

    out = tmp_path / "in.txt.scrm"
    assert not out.exists()
    err = capsys.readouterr().err
    assert "error while scrambling in.txt: UnicodeDecodeError" in err
    assert "Traceback" in err  # -d keeps the full traceback
    assert f"removed output file: {out}" in err


@pytest.mark.parametrize(
    "exc", [RuntimeError("rule engine blew up"), MemoryError(), re.error("bad pattern")]
)
def test_any_failure_removes_the_partial_output_file(
    tmp_path, monkeypatch, capsys, exc
):
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\nthree\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)
    fail_after_lines(1, monkeypatch, exc)

    assert sc.main(["-k", KEY, "-c", str(cfg), str(src)]) == 1

    out = tmp_path / "in.txt.scrm"
    assert not out.exists()
    err = capsys.readouterr().err
    # A failure with nothing to say is still named rather than reported blank.
    assert type(exc).__name__ in err
    assert f"removed output file: {out}" in err


class _Doomed(BaseException):
    """A failure that is not even an Exception, e.g. a system-level abort."""


def test_an_unhandled_abort_still_removes_the_output_file(
    tmp_path, monkeypatch, capsys
):
    # Aborts outside the Exception hierarchy keep propagating, as Python
    # intends, but the partial output goes on the way out.
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\nthree\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)
    fail_after_lines(1, monkeypatch, _Doomed("out of everything"))

    with pytest.raises(_Doomed):
        sc.main(["-k", KEY, "-c", str(cfg), str(src)])

    out = tmp_path / "in.txt.scrm"
    assert not out.exists()
    assert f"removed output file: {out}" in capsys.readouterr().err


def test_failure_reports_stdin_as_the_source(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)  # keeps a stdin ".scrm" out of the source tree
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    monkeypatch.setattr(sys, "stdin", io.StringIO("one\ntwo\n"))
    fail_after_lines(1, monkeypatch, RuntimeError("boom"))

    assert sc.main(["-k", KEY, "-c", str(cfg)]) == 1

    assert not (tmp_path / "stdin.scrm").exists()
    err = capsys.readouterr().err
    assert "error while scrambling stdin: RuntimeError: boom" in err


def test_failure_removes_outputs_already_completed(tmp_path, monkeypatch):
    # Failed while writing the second file: the first one is finished but still
    # belongs to the aborted run, so it goes too.
    first = tmp_path / "a.txt"
    first.write_text("one\n")
    second = tmp_path / "b.txt"
    second.write_text("two\nthree\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)
    fail_after_lines(2, monkeypatch, RuntimeError("boom"))

    argv = ["-k", KEY, "-c", str(cfg), str(first), str(second)]
    assert sc.main(argv) == 1

    assert not (tmp_path / "a.txt.scrm").exists()
    assert not (tmp_path / "b.txt.scrm").exists()


def test_failure_on_stdout_output_removes_nothing(tmp_path, monkeypatch, capsys):
    src = tmp_path / "in.txt"
    src.write_text("one\ntwo\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    fail_after_lines(1, monkeypatch, RuntimeError("boom"))

    argv = ["-k", KEY, "-c", str(cfg), "-o", "stdout", str(src)]
    assert sc.main(argv) == 1

    assert not (tmp_path / "stdout").exists()
    err = capsys.readouterr().err
    assert "removed output file" not in err


def test_a_reported_error_removes_the_outputs_written_so_far(
    tmp_path, monkeypatch, capsys
):
    # The second input cannot be opened, so error() stops the run; the output
    # of the first input is as much a partial result as after an interrupt.
    first = tmp_path / "a.txt"
    first.write_text("one\n")
    unreadable = tmp_path / "b.txt"
    unreadable.mkdir()  # a directory cannot be read as an input file
    cfg = tmp_path / "c.yml"
    cfg.write_text(RULES)
    silence_progress(monkeypatch)

    argv = ["-k", KEY, "-c", str(cfg), str(first), str(unreadable)]
    with pytest.raises(SystemExit) as excinfo:
        sc.main(argv)

    assert excinfo.value.code == 1  # error()'s own status is preserved
    assert not (tmp_path / "a.txt.scrm").exists()
    err = capsys.readouterr().err
    assert "cannot open input file" in err
    assert f"removed output file: {tmp_path / 'a.txt.scrm'}" in err


def test_cleanup_finishes_when_interrupted_again(tmp_path, monkeypatch):
    # A user hammering Ctrl+C must not leave the cleanup itself half done.
    first = tmp_path / "one.scrm"
    first.write_text("partial\n")
    second = tmp_path / "two.scrm"
    second.write_text("partial\n")
    sc.reset_run_outputs()
    sc.register_run_output(str(first))
    sc.register_run_output(str(second))

    real_remove = os.remove

    def remove(path):
        signal.raise_signal(signal.SIGINT)
        real_remove(path)

    monkeypatch.setattr(os, "remove", remove)

    try:
        removed = sc.remove_run_outputs()
    except KeyboardInterrupt:
        sc.reset_run_outputs()
        pytest.fail("a second Ctrl+C cut the cleanup short")

    assert sorted(removed) == [str(first), str(second)]
    assert not first.exists()
    assert not second.exists()


# --------------------------------------------------------------------------- #
# Version
# --------------------------------------------------------------------------- #


def test_refuses_to_overwrite_input(tmp_path, capsys):
    src = tmp_path / "in.txt"
    src.write_text("hello\n")
    cfg = tmp_path / "c.yml"
    cfg.write_text("r:\n  match-pattern: 'z'\n  scramble-prefix: 'Z-'\n")
    argv = ["-k", KEY, "-c", str(cfg), "-o", str(src), str(src)]
    with pytest.raises(SystemExit):
        sc.main(argv)
    assert "refusing to overwrite the input file" in capsys.readouterr().err
    assert src.read_text() == "hello\n"  # input left intact


def test_help_alone_succeeds(capsys):
    assert sc.main(["-h"]) == 0
    assert f"Usage: {sc.PROG}" in capsys.readouterr().out


def test_prog_is_the_command_name_when_imported_as_a_package():
    assert sc.PROG == "id_scrambler"


def test_version_alone_succeeds(capsys):
    assert sc.main(["-v"]) == 0
    assert "Version: 1.0.0" in capsys.readouterr().out


def test_help_and_version_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit):
        sc.main(["-h", "-v"])
    assert "-h/--help cannot be combined with -v/--version" in capsys.readouterr().err


def test_help_with_other_option_exits(capsys):
    with pytest.raises(SystemExit):
        sc.main(["-h", "-d"])
    assert "-h/--help cannot be combined with -d/--debug" in capsys.readouterr().err


def test_help_with_file_exits(capsys):
    with pytest.raises(SystemExit):
        sc.main(["-h", "foo.txt"])
    assert "-h/--help cannot be combined with FILE" in capsys.readouterr().err


def test_version_with_other_option_exits(capsys):
    with pytest.raises(SystemExit):
        sc.main(["-v", "-k", KEY])
    assert "-v/--version cannot be combined with -k/--key" in capsys.readouterr().err


def test_version_text_contains_fields():
    txt = sc.version_text()
    assert f"{sc.PROG}\n" in txt
    assert "Version: 1.0.0" in txt
    assert sc.COPYRIGHT in txt
    assert f"GitHub : {sc.SOURCE_URL}" in txt


def test_version_reports_the_file_name_when_run_as_a_script():
    module = pathlib.Path(sc.__file__).resolve().parent / "id_scrambler.py"
    proc = subprocess.run(
        [sys.executable, str(module), "-v"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.startswith("id_scrambler.py\n")


# --------------------------------------------------------------------------- #
# Shipped scrambler.yml: IPv6/IPv4 address rules
# --------------------------------------------------------------------------- #

# The rules file is shipped as package data inside the id_scrambler package.
SHIPPED_CONFIG = pathlib.Path(sc.__file__).resolve().parent / "sr_os_rules.yml"


def _shipped_rule(name):
    rules = sc.load_rules(str(SHIPPED_CONFIG), debug=False)
    for r in rules:
        if r.name == name:
            return r
    raise AssertionError(f"rule {name!r} not found in shipped config")


@pytest.mark.parametrize(
    "addr",
    [
        "2001:db8:0:0:0:0:0:1",
        "2001:db8::1",
        "fe80::a45c:1ff:fe01:5",  # regression: must not truncate to fe80::a45c
        "::1",
        "::",
        "1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6::8",
        "1:2:3:4:5::7:8",
        "1::6:7:8",
        "fe80::",
        "::ffff:192.0.2.128",
        "::192.0.2.128",
        "2001:db8::192.0.2.1",
        "1:2:3:4:5:6:192.0.2.1",
    ],
)
def test_ipv6_rule_matches_full_address(addr):
    rule = _shipped_rule("ipv6-address")
    m = rule.pattern.search(f"peer {addr} up")
    assert m is not None and m.group(0) == addr


@pytest.mark.parametrize(
    "token",
    [
        "fe80::a45c:1ff:fe01:5%eth0",  # standard % zone
        "fe80::a45c:1ff:fe01:5-eth0",  # legacy hyphen zone
        "fe80::a45c:1ff:fe01:5-base_int30",  # widened charset (underscore)
        'fe80::a45c:1ff:fe01:5-"base_int30"',  # quoted zone
    ],
)
def test_ipv6_rule_matches_zone_variants(token):
    rule = _shipped_rule("ipv6-address")
    m = rule.pattern.search(f"neighbor {token} down")
    assert m is not None and m.group(0) == token


def test_ipv6_quoted_zone_leaves_trailing_suffix():
    # A quoted zone stops at the closing quote; the trailing '.57400' must not
    # be swallowed into the match.
    rule = _shipped_rule("ipv6-address")
    line = 'neighbor fe80::a45c:1ff:fe01:5-"base_int30".57400 down'
    m = rule.pattern.search(line)
    assert m is not None
    assert m.group(0) == 'fe80::a45c:1ff:fe01:5-"base_int30"'


def test_ipv6_zone_stops_at_whitespace():
    rule = _shipped_rule("ipv6-address")
    m = rule.pattern.search("fe80::1-eth0 and more")
    assert m is not None and m.group(0) == "fe80::1-eth0"


@pytest.mark.parametrize(
    "text",
    [
        "18:24:24",  # HH:MM:SS timestamp
        "at 18:24:24 utc",  # timestamp inside a sentence
        "elapsed 1:02:03",  # H:MM:SS timestamp
        "12:34",  # HH:MM
        "cf3:",  # trailing-colon token
        "cf3:test.py",  # label followed by colon
        "name cf3: value",  # colon token inside a sentence
        "ab:cd:ef",  # three hex groups, no '::'
        "dead:beef:1234:5678",  # four hex groups, no '::'
        "00:11:22:33:44:55",  # MAC-like, six groups, no '::'
    ],
)
def test_ipv6_rule_ignores_timestamps_and_colon_tokens(text):
    # Timestamps and generic colon-separated tokens must NOT be scrambled:
    # a real address needs 8 hextet groups, '::' compression, or embedded IPv4.
    rule = _shipped_rule("ipv6-address")
    assert rule.pattern.search(text) is None


@pytest.mark.parametrize(
    "token",
    [
        "10.1.1.3",
        '192.168.0.1-"iface_1"',  # quoted zone + widened charset on IPv4 too
        "10.0.0.5%eth0",
    ],
)
def test_ipv4_rule_zone_variants(token):
    rule = _shipped_rule("ipv4-address")
    m = rule.pattern.search(f"addr {token} end")
    assert m is not None and m.group(0) == token


def test_ipv4_quoted_zone_leaves_trailing_suffix():
    rule = _shipped_rule("ipv4-address")
    m = rule.pattern.search('addr 192.168.0.1-"iface_1".10 end')
    assert m is not None
    assert m.group(0) == '192.168.0.1-"iface_1"'
