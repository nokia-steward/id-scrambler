#!/usr/bin/env python3
"""id_scrambler.py - cleartext scrambling tool.

© 2026 Nokia
Licensed under the BSD 3-Clause License
SPDX-License-Identifier: BSD-3-Clause

Reads cleartext input line by line, replaces substrings that match the
patterns defined in a YAML rule file with an HMAC-SHA256 scrambled string,
and writes cleartext output.
"""

from __future__ import annotations

import argparse
import bisect
import dataclasses
import glob
import hashlib
import hmac
import importlib
import os
import re
import secrets
import signal
import sys
import traceback
import unicodedata
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    NoReturn,
    Protocol,
    TextIO,
    TypeVar,
    cast,
)

from tqdm import tqdm

# Name the tool reports in its help text, version banner, argparse usage and
# error messages. Imported as a package (``pip install .`` console script or
# ``python -m id_scrambler``) it is the command name; with no package the file
# was run directly as a script, so use its file name.
PROG = "id_scrambler" if __package__ else "id_scrambler.py"

try:
    import yaml
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(f"{PROG}: PyYAML is required (pip install -r requirements.txt)\n")
    sys.exit(1)

if TYPE_CHECKING or __package__:
    from . import yangpattern
else:  # run directly as a script, not as part of the package
    import yangpattern

# Public API re-exported by the package's __init__. ``_strip_control_chars`` is
# intentionally included even though it is "private": the test-suite exercises
# it directly.
__all__ = [
    "ALLOWED_KEYS",
    "COPYRIGHT",
    "HASH_MIN_BODY",
    "KEY_MAX",
    "KEY_MIN",
    "PAD_ALPHABET",
    "PROG",
    "PYPI_URL",
    "RELEASE_DATE",
    "SOURCE_URL",
    "VERSION",
    "Rule",
    "Scrambler",
    "_escape_control_chars",
    "_strip_control_chars",
    "acquire_key",
    "build_parser",
    "discover_config",
    "error",
    "load_rules",
    "main",
    "output_path_for",
    "process_source",
    "register_run_output",
    "remove_run_outputs",
    "reset_run_outputs",
    "version_text",
]

VERSION = "1.0.0"
RELEASE_DATE = "2026-10-12"
SOURCE_URL = "https://github.com/nokia-steward/id-scrambler/"
PYPI_URL = "https://pypi.org/project/id-scrambler/"
COPYRIGHT = "© 2026 Nokia\nLicensed under the BSD 3-Clause License"

# Key length bounds, in bytes of the NFC-normalized key encoded as UTF-8.
KEY_MIN = 32
KEY_MAX = 128
HASH_MIN_BODY = 8
# Alphabet used to pad scrambled output beyond the 64-char hash: lowercase
# letters and digits.
PAD_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

ALLOWED_KEYS = {
    "description",
    "enabled",
    "match-pattern",
    "scramble-prefix",
    "scramble-suffix",
    "output-padding",
    "ignore-match-prefix",
    "scramble-group",
    "pattern-format",
}

HELP_TEXT = f"""\
Usage: {PROG} [OPTION]... [FILE]...
Scramble strings that match patterns in a cleartext file.

With no FILE, or when FILE is -, read standard input.

  -c, --config        the YAML configuration file, if not specified the file with
                      a ".yml" suffix in the current working directory is used
  -d, --debug         enable debug mode and send output to stderr
  -h, --help          display this help text and exit
  -k, --key           the key to be used in the hash, 32 to 128 bytes,
                      if not specified a random 32-byte key is generated
  -o, --output        the output file name, if not specified a ".scrm" suffix is
                      added to the input file name, if "stdout" then the output
                      is sent to stdout
  -v, --version       display version information and exit
"""


def error(message: str, code: int = 1) -> NoReturn:
    sys.stderr.write(f"{PROG}: {message}\n")
    sys.exit(code)


# --------------------------------------------------------------------------- #
# Version
# --------------------------------------------------------------------------- #


def version_text() -> str:
    return (
        f"{PROG}\n"
        f"{COPYRIGHT}\n"
        f"Version: {VERSION}\n"
        f"Date   : {RELEASE_DATE}\n"
        f"GitHub : {SOURCE_URL}\n"
        f"PyPi   : {PYPI_URL}\n"
    )


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #


def acquire_key(cli_key: str | None, debug: bool = False) -> str:
    if cli_key is None:
        # No key supplied on the command line: generate a cryptographically
        # strong random one. token_hex(16) yields 32 ASCII hex characters, i.e.
        # 32 UTF-8 bytes, which is within the [KEY_MIN, KEY_MAX] range.
        key = secrets.token_hex(16)
        if debug:
            sys.stderr.write(
                f"{PROG}: no key supplied, generated a random {len(key)}-byte key\n"
            )
        return key
    # A visually identical key can arrive as different code points (e.g. a
    # precomposed "é" versus "e" plus a combining accent); NFC makes both
    # produce the same bytes and therefore the same scrambles.
    key = unicodedata.normalize("NFC", cli_key)
    try:
        key_bytes = len(key.encode("utf-8"))
    except UnicodeEncodeError:
        # Undecodable command-line bytes on POSIX, or a lone UTF-16 surrogate
        # on Windows, surface as surrogate code points that UTF-8 rejects.
        error("key contains characters that cannot be encoded as UTF-8")
    if key_bytes < KEY_MIN:
        error(f"key must be a minimum of {KEY_MIN} bytes")
    if key_bytes > KEY_MAX:
        error(f"key must be a maximum of {KEY_MAX} bytes")
    if debug:
        sys.stderr.write(
            f"{PROG}: key supplied by user, using the {key_bytes}-byte key\n"
        )
    return key


# --------------------------------------------------------------------------- #
# Rules / configuration
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(eq=False)  # identity, so a rule can key its own cache
class Rule:
    name: str
    enabled: bool
    pattern: re.Pattern[str] | _LiteralTokenPattern
    # ``ignore`` rules keep matched text as cleartext; when False the match is
    # scrambled using ``scramble_prefix`` (possibly empty) and ``scramble_suffix``.
    ignore: bool
    scramble_prefix: str
    scramble_suffix: str
    padding: bool
    # If the match starts with this string, it is stripped before hashing (so
    # only the remainder is hashed) and preserved verbatim in the output.
    ignore_match_prefix: str = ""
    # When set, only this capture group of the match is scrambled; the rest of
    # the matched text is emitted verbatim. None => scramble the whole match.
    scramble_group: int | None = None


def discover_config() -> str:
    """Locate the YAML configuration file to use.

    Used only when no explicit ``-c/--config`` is given: the one ``*.yml`` file
    in the current directory. Anything else is an error prompting the user to
    say which file they mean. The rules files shipped with the package are never
    picked up implicitly, so a run always names the ruleset it applied.
    """
    candidates = sorted(glob.glob(os.path.join(".", "*.yml")))
    if len(candidates) > 1:
        error("multiple YAML files found, use -c to specify the file")
    if not candidates:
        error("no YAML file found, use -c to specify the file")
    return candidates[0]


class _DuplicateKey(yaml.constructor.ConstructorError):
    """A mapping in the rules file that gives the same key twice."""

    def __init__(self, key: Any, mapping: yaml.MappingNode, key_node: yaml.Node):
        self.key = key
        super().__init__(
            "while reading a mapping",
            mapping.start_mark,
            f"found a duplicate key {key!r}",
            key_node.start_mark,
        )


# The tag PyYAML gives the "<<" of a merge key. Such an entry is inheritance
# syntax rather than a key of the mapping, and a merged-in setting that the
# mapping also states itself is an intentional override, not a repeat.
_YAML_MERGE_TAG = "tag:yaml.org,2002:merge"


class _StrictLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses to accept a repeated mapping key.

    Plain YAML semantics keep the last of a repeated key and discard the rest,
    which in a rules file means a whole rule -- or one setting of a rule --
    vanishes without a word, and with it whatever it was meant to scramble.
    """

    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == _YAML_MERGE_TAG:
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError:
                continue  # unhashable key: SafeLoader reports it in its own words
            if duplicate:
                raise _DuplicateKey(key, node, key_node)
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_rules(path: str, debug: bool) -> list[Rule]:
    if not os.path.exists(path):
        error(f"cannot open configuration file: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.load(fh, Loader=_StrictLoader)
    except _DuplicateKey as exc:
        mark = exc.problem_mark
        where = "" if mark is None else f" (line {mark.line + 1})"
        error(f"configuration file {path}: duplicate key {exc.key!r}{where}")
    except (OSError, yaml.YAMLError) as exc:
        error(f"failed to read configuration file {path}: {exc}")

    if data is None:
        data = {}
    if not isinstance(data, dict):
        error(f"configuration file {path} must contain a mapping of rules")

    rules: list[Rule] = []
    seen_names: set[str] = set()
    for name, body in data.items():
        # Names are stringified for the Rule below, so keys YAML considers
        # distinct can still arrive at the same name (1 and "1", say). Two rules
        # answering to one name make the debug output ambiguous at best.
        label = str(name)
        if label in seen_names:
            error(f"rule {label!r}: defined more than once")
        seen_names.add(label)
        if not isinstance(body, dict):
            error(f"rule {name!r}: each rule must be a mapping of key/value pairs")
        unknown = set(body) - ALLOWED_KEYS
        if unknown:
            error(f"rule {name!r}: unrecognized key(s): {', '.join(sorted(unknown))}")

        enabled = body.get("enabled", True)
        if not isinstance(enabled, bool):
            error(f"rule {name!r}: 'enabled' must be true or false")
        padding = body.get("output-padding", False)
        if not isinstance(padding, bool):
            error(f"rule {name!r}: 'output-padding' must be true or false")
        # An omitted (or explicitly null) scramble-prefix marks an "ignore"
        # rule that keeps the match as cleartext. Otherwise the prefix is a
        # string, which may be empty.
        prefix = body.get("scramble-prefix")
        ignore = prefix is None
        prefix = "" if prefix is None else str(prefix)
        # Opt-in: absent (or explicitly null) means no suffix, i.e. "".
        suffix = body.get("scramble-suffix")
        suffix = "" if suffix is None else str(suffix)
        # Opt-in: a leading part of the match to strip before hashing.
        ignore_match_prefix = body.get("ignore-match-prefix")
        ignore_match_prefix = (
            "" if ignore_match_prefix is None else str(ignore_match_prefix)
        )

        match_pattern = body.get("match-pattern")
        if match_pattern is None:
            error(f"rule {name!r}: missing required 'match-pattern'")
        fmt = body.get("pattern-format", "yang")
        try:
            compiled = yangpattern.compile_pattern(str(match_pattern), str(fmt))
        except (ValueError, re.error) as exc:
            error(f"rule {name!r}: invalid match-pattern: {exc}")

        # Opt-in: scramble only a single capture group of the match.
        scramble_group = body.get("scramble-group")
        if scramble_group is not None:
            if ignore:
                error(
                    f"rule {name!r}: 'scramble-group' cannot be used on an ignore "
                    "rule (one without 'scramble-prefix')"
                )
            if isinstance(scramble_group, bool) or not isinstance(scramble_group, int):
                error(f"rule {name!r}: 'scramble-group' must be a positive integer")
            if scramble_group < 1:
                error(f"rule {name!r}: 'scramble-group' must be a positive integer")
            if scramble_group > compiled.groups:
                error(
                    f"rule {name!r}: 'scramble-group' {scramble_group} exceeds the "
                    f"{compiled.groups} capture group(s) in the match-pattern"
                )

        rules.append(
            Rule(
                name=str(name),
                enabled=enabled,
                pattern=compiled,
                ignore=ignore,
                scramble_prefix=prefix,
                scramble_suffix=suffix,
                padding=padding,
                ignore_match_prefix=ignore_match_prefix,
                scramble_group=scramble_group,
            )
        )

    # An empty file, a comment-only file and an explicit null all land here with
    # nothing to apply. Scrambling nothing is never what the user meant.
    if not rules:
        error(f"no rules are defined in {path}")

    if debug:
        sys.stderr.write(f"{PROG}: loaded {len(rules)} rule(s) from {path}\n")
        for r in rules:
            state = "enabled" if r.enabled else "disabled"
            kind = "ignore" if r.ignore else "scramble"
            sys.stderr.write(f"{PROG}:   rule {r.name!r} [{state}, {kind}]\n")
    return rules


# --------------------------------------------------------------------------- #
# Scramble engine
# --------------------------------------------------------------------------- #


_GRAM = 4
# Above this many short triggers, matching them against the line's own short
# slices beats testing each trigger with ``in``.
_SHORT_SCAN_LIMIT = 16

_T = TypeVar("_T")


_TOKEN_RUN = re.compile(r"[\w.:-]+")


class _LineView:
    """One input line plus the pieces the indexes look it up by.

    Each piece is computed on first use and then shared by every index.
    """

    __slots__ = ("_grams", "_short_subs", "_tokens", "line")

    def __init__(self, line: str) -> None:
        self.line = line
        self._grams: set[str] | None = None
        self._short_subs: set[str] | None = None
        self._tokens: set[str] | None = None

    def tokens(self) -> set[str]:
        """Every maximal run of token characters, plus each run minus a
        trailing colon, since a sentence-ending colon is not part of a token."""
        tokens = self._tokens
        if tokens is None:
            runs = _TOKEN_RUN.findall(self.line)
            tokens = set(runs)
            tokens.update([r[:-1] for r in runs if r[-1] == ":"])
            self._tokens = tokens
        return tokens

    def grams(self) -> set[str]:
        grams = self._grams
        if grams is None:
            line = self.line
            grams = {line[i : i + _GRAM] for i in range(len(line) - _GRAM + 1)}
            self._grams = grams
        return grams

    def short_subs(self) -> set[str]:
        subs = self._short_subs
        if subs is None:
            line = self.line
            n = len(line)
            subs = {
                line[i : i + w] for w in range(1, _GRAM) for i in range(n - w + 1)
            }
            self._short_subs = subs
        return subs


class _GramIndex(Generic[_T]):
    """Find the items whose trigger can be claimed as a token in a line.

    Callers only ever claim a trigger where ``_iter_literal_tokens`` finds it,
    so a lookup may skip occurrences that are not standalone tokens. A trigger
    made only of token characters can then only be claimed where it is one of
    the line's tokens, and is found by exact lookup. Any other trigger is
    filed under one of its own ``_GRAM``-character slices, picking the slice
    whose list is currently shortest, or matched whole when it is shorter.
    Results for those may include occurrences that are not tokens.
    """

    def __init__(self) -> None:
        self._by_token: dict[str, list[_T]] = {}
        self._by_gram: dict[str, list[tuple[str, _T]]] = {}
        self._short: dict[str, list[_T]] = {}

    def add(self, trigger: str, item: _T) -> None:
        if not trigger:
            return
        if _TOKEN_RUN.fullmatch(trigger):
            self._by_token.setdefault(trigger, []).append(item)
        elif len(trigger) >= _GRAM:
            key = self._index_key(trigger)
            self._by_gram.setdefault(key, []).append((trigger, item))
        else:
            self._short.setdefault(trigger, []).append(item)

    def _index_key(self, trigger: str) -> str:
        by_gram = self._by_gram
        best_len = -1
        tied: list[int] = []
        for i in range(len(trigger) - _GRAM + 1):
            glen = len(by_gram.get(trigger[i : i + _GRAM], ()))
            if best_len < 0 or glen < best_len:
                best_len = glen
                tied = [i]
            elif glen == best_len:
                tied.append(i)
        i = tied[0] if len(tied) == 1 else tied[_spread(trigger) % len(tied)]
        return trigger[i : i + _GRAM]

    def lookup(self, view: _LineView) -> list[_T]:
        """Items whose trigger may be a token in the line.

        An item may appear more than once.
        """
        found: list[_T] = []
        line = view.line
        # Intersect in C. A Python ``dict.get`` per piece spends its time on
        # the pieces that are not indexed.
        by_token = self._by_token
        if by_token:
            for token in by_token.keys() & view.tokens():
                found.extend(by_token[token])
        by_gram = self._by_gram
        if by_gram and len(line) >= _GRAM:
            for gram in by_gram.keys() & view.grams():
                for trigger, item in by_gram[gram]:
                    if trigger in line:
                        found.append(item)
        short = self._short
        if short and line:
            if len(short) <= _SHORT_SCAN_LIMIT:
                for trigger, items in short.items():
                    if trigger in line:
                        found.extend(items)
            else:
                for trigger in short.keys() & view.short_subs():
                    found.extend(short[trigger])
        return found


class _OwnedBucket:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._longest_first: list[str] = []
        self._rank: dict[str, tuple[int, int]] = {}
        self._seq = 0

    def __bool__(self) -> bool:
        return bool(self._values)

    def __contains__(self, value: str) -> bool:
        return value in self._values

    def __iter__(self) -> Iterator[str]:
        return iter(self._longest_first)

    def __getitem__(self, value: str) -> str:
        return self._values[value]

    def __setitem__(self, value: str, scramble: str) -> None:
        if value not in self._values:
            bisect.insort(self._longest_first, value, key=lambda v: -len(v))
            self._rank[value] = (-len(value), self._seq)
            self._seq += 1
        self._values[value] = scramble

    def rank(self, value: str) -> tuple[int, int]:
        """Sort key putting longer values first, then older ones."""
        return self._rank[value]


def _load_sre_parser() -> Any:
    try:
        return importlib.import_module("re._parser")  # Python 3.11+
    except ImportError:
        return importlib.import_module("sre_parse")


_sre_parser: Any = _load_sre_parser()


def _required_texts(pattern: re.Pattern[str] | _LiteralTokenPattern) -> tuple[str, ...]:
    """Return strings that every match of ``pattern`` contains.

    A line lacking any of them cannot match, so the rule can skip it. The
    first entry, when present, is the longest run of plain characters in the
    pattern's top-level sequence. The rest are single characters that every
    match needs somewhere (see ``_required_chars``). Returns an empty tuple
    when there is nothing safe to test.
    """
    if not isinstance(pattern, re.Pattern) or pattern.flags & re.IGNORECASE:
        return ()
    try:
        tree = _sre_parser.parse(pattern.pattern, pattern.flags)
        literal = _longest_top_level_literal(tree)
        chars = _required_chars(tree)
    except Exception:  # noqa: BLE001 - private module; a surprise disables the filter
        return ()
    texts = [literal] if literal else []
    texts.extend(sorted(c for c in chars if c not in literal))
    return tuple(texts)


def _op_name(op: Any) -> str:
    return getattr(op, "name", str(op))


def _longest_top_level_literal(tree: Any) -> str:
    best = ""
    run: list[str] = []
    for op, av in tree:
        if _op_name(op) == "LITERAL":
            run.append(chr(av))
            continue
        if len(run) > len(best):
            best = "".join(run)
        run = []
    if len(run) > len(best):
        best = "".join(run)
    return best


def _required_chars(tree: Any) -> set[str]:
    """Characters every match of the parsed ``tree`` must contain.

    Only counts what is certain: plain characters, the contents of groups
    and of repeats that must occur at least once, one-character classes, and
    characters common to every branch of an alternation. Anything else
    (lookarounds, backreferences, other classes, unknown nodes) adds nothing.
    """
    out: set[str] = set()
    for op, av in tree:
        name = _op_name(op)
        if name == "LITERAL":
            out.add(chr(av))
        elif name == "SUBPATTERN":
            add_flags, sub = av[1], av[3]
            if not add_flags & re.IGNORECASE:
                out |= _required_chars(sub)
        elif name == "ATOMIC_GROUP":
            out |= _required_chars(av)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            if av[0] >= 1:
                out |= _required_chars(av[2])
        elif name == "BRANCH":
            branches = [_required_chars(b) for b in av[1]]
            if branches:
                out |= set.intersection(*branches)
        elif name == "IN" and len(av) == 1 and _op_name(av[0][0]) == "LITERAL":
            out.add(chr(av[0][1]))
    return out


def _spread(value: str) -> int:
    h = 0
    for ch in value:
        h = (h * 33 + ord(ch)) & 0xFFFFFFFF
    return h


class Scrambler:
    def __init__(self, key: str, rules: list[Rule], debug: bool = False):
        self.key = key
        self.rules = rules
        self.debug = debug
        self._hash_cache: dict[str, str] = {}
        self._body_len: dict[str, int] = {}
        # (prefix, body) -> originating value, used for collision detection
        self._scramble_index: dict[tuple[str, str], str] = {}
        # cleartext value -> finished scramble string: every value this run has
        # scrambled, whichever rule did it.
        self.registry: dict[str, str] = {}
        # The same entries grouped by the rule that produced them, longest value
        # first. A group is replayed right after its own rule (see
        # ``process_line``), so a value keeps the form its rule gave it even
        # where a later rule matches it too.
        self._owned: dict[Rule, _OwnedBucket] = {}
        # Every owned value across all rules, so a line finds the values it
        # contains with one lookup rather than one per rule.
        self._reuse_index: _GramIndex[tuple[Rule, str]] = _GramIndex()
        # Values each rule has owned since the current line started. They are
        # not in that line's lookup, but its rule still replays them.
        self._fresh: dict[Rule, list[str]] = {}
        # Strings each configured rule's pattern cannot match without; empty
        # when there is nothing to test for.
        self._required: dict[Rule, tuple[str, ...]] = {}
        # Dedup key (value, prefix, suffix, padding) for rules dynamically
        # spawned by ``ignore-match-prefix`` matches, so each cropped value
        # produces at most one runtime rule.
        self._dynamic_rule_keys: set[tuple[str, str, str, bool]] = set()
        # Spawned rules in spawn order. They sit at the end of ``rules``, so a
        # line visits them after every configured rule. Each one only matches
        # its own literal, so the index lets a line skip the rest.
        self._dynamic_rules: list[Rule] = []
        self._dynamic_index: _GramIndex[int] = _GramIndex()
        # Number of individual strings replaced, counted per substitution
        # rather than per line. One Scrambler is shared across all inputs, so
        # ``process_source`` clears this before each file.
        self.scrambled_count = 0

    def reset_scrambled_count(self) -> None:
        self.scrambled_count = 0

    # -- hashing -------------------------------------------------------------
    def _hmac(self, message: str) -> bytes:
        return hmac.new(
            self.key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def _full_hash(self, value: str) -> str:
        cached = self._hash_cache.get(value)
        if cached is None:
            cached = self._hmac(value).hex()
            self._hash_cache[value] = cached
        return cached

    def _unique_body_len(self, value: str, prefix: str, full: str) -> int:
        existing = self._body_len.get(value)
        if existing is not None:
            return existing
        blen = HASH_MIN_BODY
        while blen < len(full):
            key = (prefix, full[:blen])
            owner = self._scramble_index.get(key)
            if owner is None or owner == value:
                break
            blen += 1  # collision with a different value -> lengthen suffix
        self._scramble_index[(prefix, full[:blen])] = value
        self._body_len[value] = blen
        return blen

    def _pad_chars(self, value: str, n: int) -> str:
        # Deterministic (keyed) lowercase-alphanumeric filler so repeated
        # occurrences of the same value always pad identically.
        out: list[str] = []
        counter = 0
        while len(out) < n:
            block = self._hmac(f"{value}#pad{counter}")
            for b in block:
                out.append(PAD_ALPHABET[b % len(PAD_ALPHABET)])
                if len(out) >= n:
                    break
            counter += 1
        return "".join(out)

    def scramble(
        self,
        matched: str,
        prefix: str,
        suffix: str,
        padding: bool,
        ignore_match_prefix: str = "",
        owner: Rule | None = None,
    ) -> str:
        # Strip a known leading part so only the remainder is hashed; the
        # stripped part is preserved verbatim at the start of the output.
        if ignore_match_prefix and matched.startswith(ignore_match_prefix):
            kept = ignore_match_prefix
            value = matched[len(ignore_match_prefix) :]
        else:
            kept = ""
            value = matched
        full = self._full_hash(value)
        blen = self._unique_body_len(value, prefix, full)
        if padding:
            # Fill the body with the hash first (capped at its 64 chars), then
            # extend with random-looking lowercase alphanumeric padding so the
            # output width matches the original token even when it is longer
            # than the hash. The kept prefix, scramble prefix, and suffix all
            # count toward the target width.
            inner_target = max(
                blen, len(matched) - len(kept) - len(prefix) - len(suffix)
            )
            body = full[: min(inner_target, len(full))]
            pad_len = len(matched) - len(kept) - len(prefix) - len(body) - len(suffix)
            if pad_len > 0:
                body += self._pad_chars(value, pad_len)
            result = kept + prefix + body + suffix
        else:
            result = kept + prefix + full[:blen] + suffix
        self._register(matched, result, owner)
        self.scrambled_count += 1
        return result

    def _register(self, matched: str, scramble: str, owner: Rule | None = None) -> None:
        self.registry[matched] = scramble
        # ``owner`` is absent only when scramble() is called directly rather than
        # from a rule match, which leaves nothing to replay the value later.
        if owner is not None:
            self._own(owner, matched, scramble, replace=True)
        # Allow unquoted occurrences of a quoted value to reuse the scramble.
        if len(matched) >= 2 and matched[0] == matched[-1] and matched[0] in ("'", '"'):
            inner = matched[1:-1]
            if inner:
                self.registry.setdefault(inner, scramble)
                if owner is not None:
                    self._own(owner, inner, scramble, replace=False)

    def _own(self, owner: Rule, value: str, scramble: str, replace: bool) -> None:
        bucket = self._owned.get(owner)
        if bucket is None:
            bucket = self._owned[owner] = _OwnedBucket()
        if value in bucket:
            if replace:
                bucket[value] = scramble
            return
        bucket[value] = scramble
        self._reuse_index.add(value, (owner, value))
        self._fresh.setdefault(owner, []).append(value)

    def _spawn_dynamic_rule(self, parent: Rule, value: str) -> Rule | None:
        """Build a runtime-only rule matching ``value`` exactly (as a token).

        Triggered when a rule with ``ignore-match-prefix`` matches: the cropped
        remainder becomes its own literal rule so the bare value is scrambled
        consistently wherever it later appears. The rule is in-memory only and
        is never written back to the YAML configuration. Returns ``None`` when
        an equivalent rule was already spawned.
        """
        key = (value, parent.scramble_prefix, parent.scramble_suffix, parent.padding)
        if key in self._dynamic_rule_keys:
            return None
        self._dynamic_rule_keys.add(key)
        # Same boundary guard as the reuse pass so the literal is matched as a
        # standalone token, not inside a larger token (e.g. "12345" in "123456").
        pattern = _LiteralTokenPattern(value)
        return Rule(
            name=f"{parent.name} (dynamic)",
            enabled=True,
            pattern=pattern,
            ignore=False,
            scramble_prefix=parent.scramble_prefix,
            scramble_suffix=parent.scramble_suffix,
            padding=parent.padding,
            ignore_match_prefix="",
        )

    # -- line processing -----------------------------------------------------
    def process_line(self, line: str) -> str:
        # claimed spans: list of (start, end, replacement_text)
        claims: list[tuple[int, int, str]] = []
        occupied: list[tuple[int, int]] = []
        match_log: list[str] = []  # per-rule debug lines, emitted only if changed
        # Rules spawned by ignore-match-prefix matches on this line, with the
        # literal each one matches. They are appended to self.rules only after
        # the line is processed, so they affect subsequent lines but not the
        # current one.
        spawned: list[tuple[Rule, str]] = []
        view = _LineView(line)
        # Owned values already in this line, per rule. Values a rule owns while
        # the line is processed are collected in ``_fresh`` instead.
        cached: dict[Rule, list[str]] = {}
        for owner, value in self._reuse_index.lookup(view):
            cached.setdefault(owner, []).append(value)
        fresh = self._fresh
        fresh.clear()

        rules = self.rules
        dynamic = self._dynamic_rules
        required = self._required
        for rule in rules[: len(rules) - len(dynamic)]:
            if not rule.enabled:
                continue
            need = required.get(rule)
            if need is None:
                need = required[rule] = _required_texts(rule.pattern)
            for text in need:
                if text not in line:
                    break
            else:
                self._match_rule(rule, line, claims, occupied, match_log, spawned)
            if rule in cached or rule in fresh:
                self._reuse_claims(
                    view, rule, cached.get(rule), claims, occupied, match_log
                )
        if dynamic:
            # A dynamic rule whose literal is absent can neither match nor
            # replay anything, so visiting only the hits in spawn order gives
            # the same claims as walking all of them.
            for i in sorted(set(self._dynamic_index.lookup(view))):
                rule = dynamic[i]
                self._match_rule(rule, line, claims, occupied, match_log, spawned)
                if rule in cached or rule in fresh:
                    self._reuse_claims(
                        view, rule, cached.get(rule), claims, occupied, match_log
                    )

        # Stitch the claimed spans back together with the cleartext between them.
        result = "".join(_segments(line, claims))
        # Emit when the line changed, or when a rule matched at all (so that
        # ignore rules, which keep text cleartext, still surface in debug).
        if self.debug and (result != line or match_log):
            # cleartext first, then the per-rule matches, then the scrambled line.
            width = max(len("CLEARTEXT"), len("SCRAMBLED"))
            sys.stderr.write(f"{'CLEARTEXT':<{width}} : {line}\n")
            for entry in match_log:
                sys.stderr.write(entry + "\n")
            sys.stderr.write(f"{'SCRAMBLED':<{width}} : {result}\n")

        # Register spawned rules now (after the current line) so they only take
        # effect from the next line onward.
        for dyn, value in spawned:
            self._add_dynamic_rule(dyn, value)
        return result

    def _add_dynamic_rule(self, rule: Rule, value: str) -> None:
        idx = len(self._dynamic_rules)
        self._dynamic_rules.append(rule)
        self.rules.append(rule)
        # The rule matches ``value`` and, when that is quoted, replays the
        # unquoted inner text too (see ``_register``), so index it under both.
        self._dynamic_index.add(value, idx)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            inner = value[1:-1]
            if inner:
                self._dynamic_index.add(inner, idx)

    def _match_rule(
        self,
        rule: Rule,
        line: str,
        claims: list[tuple[int, int, str]],
        occupied: list[tuple[int, int]],
        match_log: list[str],
        spawned: list[tuple[Rule, str]],
    ) -> None:
        for m in rule.pattern.finditer(line):
            s, e = m.start(), m.end()
            if e == s:
                continue
            if _overlaps(occupied, s, e):
                continue
            matched = m.group(0)
            if rule.ignore:
                claims.append((s, e, matched))  # ignore: keep cleartext
                occupied.append((s, e))
                if self.debug:
                    match_log.append(
                        f"RULE: {rule.name} MATCHED: '{matched}' "
                        f"IGNORED (kept cleartext)"
                    )
            else:
                if rule.scramble_group is None:
                    scr = self.scramble(
                        matched,
                        rule.scramble_prefix,
                        rule.scramble_suffix,
                        rule.padding,
                        rule.ignore_match_prefix,
                        owner=rule,
                    )
                else:
                    # Scramble only the requested capture group, keeping the
                    # surrounding matched text verbatim. If the group did not
                    # participate in the match, leave the match untouched.
                    gtext = m.group(rule.scramble_group)
                    if gtext:
                        gs, ge = m.span(rule.scramble_group)
                        inner = self.scramble(
                            gtext,
                            rule.scramble_prefix,
                            rule.scramble_suffix,
                            rule.padding,
                            rule.ignore_match_prefix,
                            owner=rule,
                        )
                        scr = matched[: gs - s] + inner + matched[ge - s :]
                    else:
                        scr = matched
                claims.append((s, e, scr))
                occupied.append((s, e))
                if self.debug:
                    match_log.append(
                        f"RULE: {rule.name} MATCHED: '{matched}' "
                        f"REPLACED WITH: '{scr}'"
                    )
                # If a prefix was cropped, spawn a runtime rule that matches
                # the bare remainder so it scrambles consistently elsewhere.
                if rule.ignore_match_prefix and matched.startswith(
                    rule.ignore_match_prefix
                ):
                    value = matched[len(rule.ignore_match_prefix) :]
                    dyn = self._spawn_dynamic_rule(rule, value) if value else None
                    if dyn is not None:
                        spawned.append((dyn, value))
                        if self.debug:
                            match_log.append(
                                f"RULE: {rule.name} SPAWNED DYNAMIC RULE "
                                f"matching '{value}' exactly"
                            )

    def _reuse_claims(
        self,
        view: _LineView,
        rule: Rule,
        cached: list[str] | None,
        claims: list[tuple[int, int, str]],
        occupied: list[tuple[int, int]],
        match_log: list[str],
    ) -> None:
        """Claim any further occurrence of a value ``rule`` scrambled before.

        Runs right after the rule's own matches, before any later rule can
        claim the values for itself. Claims spans rather than rewriting text,
        exactly as matching does, so that a value reappearing on its own keeps
        the form its rule gave it and the rules still to come see the span as
        taken. ``cached`` holds the rule's values found in the line up front.
        """
        bucket = self._owned.get(rule)
        if not bucket:
            return
        line = view.line
        values = list(cached) if cached else []
        new = self._fresh.get(rule)
        if new:
            values.extend(v for v in new if v in line)
        if len(values) > 1:
            # Longest first, so the most specific cached value wins.
            values.sort(key=bucket.rank)
        for value in values:
            scramble = bucket[value]
            if value in scramble:
                continue  # avoid rescrambling our own output
            for s, e in _iter_literal_tokens(line, value):
                if e == s or _overlaps(occupied, s, e):
                    continue
                claims.append((s, e, scramble))
                occupied.append((s, e))
                self.scrambled_count += 1
                if self.debug:
                    match_log.append(
                        f"EXISTING MATCH: '{value}' REPLACED WITH: '{scramble}'"
                    )


def _is_token_char(ch: str) -> bool:
    """Whether ``ch`` is in the token class ``[\\w.:-]``."""
    return ch.isalnum() or ch in "_.:-"


def _iter_literal_tokens(line: str, value: str) -> Iterator[tuple[int, int]]:
    """Spans where ``value`` stands alone as a token.

    A token is not flush against ``[\\w.:-]``. A trailing colon still counts as
    a boundary when it ends the line or is followed by whitespace, so a
    sentence-ending colon is left in place.
    """
    if not value:
        return
    n = len(value)
    start = 0
    line_len = len(line)
    while True:
        i = line.find(value, start)
        if i < 0:
            return
        end = i + n
        left_ok = i == 0 or not _is_token_char(line[i - 1])
        if left_ok and _right_token_boundary(line, end, line_len):
            yield i, end
            start = end
        else:
            start = i + 1


def _right_token_boundary(line: str, end: int, line_len: int) -> bool:
    if end >= line_len:
        return True
    nxt = line[end]
    if not _is_token_char(nxt):
        return True
    return nxt == ":" and (end + 1 >= line_len or line[end + 1].isspace())


class _LiteralMatch:
    __slots__ = ("_end", "_start", "_text")

    def __init__(self, start: int, end: int, text: str) -> None:
        self._start = start
        self._end = end
        self._text = text

    def start(self, group: int = 0) -> int:
        return self._start

    def end(self, group: int = 0) -> int:
        return self._end

    def span(self, group: int = 0) -> tuple[int, int]:
        return self._start, self._end

    def group(self, group: int = 0) -> str:
        # A literal token has no capture groups. Group 0 is the whole match.
        if group != 0:
            return ""
        return self._text


class _LiteralTokenPattern:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def finditer(self, line: str) -> Iterator[_LiteralMatch]:
        text = self._value
        for start, end in _iter_literal_tokens(line, text):
            yield _LiteralMatch(start, end, text)


def _overlaps(spans: list[tuple[int, int]], s: int, e: int) -> bool:
    for a, b in spans:
        if s < b and a < e:
            return True
    return False


def _segments(line: str, claims: list[tuple[int, int, str]]) -> list[str]:
    """Return ``line`` in order, with each claimed span replaced by its text.

    The gaps between claims are the original cleartext: nothing claimed a span
    there, so nothing is entitled to change it.
    """
    if not claims:
        return [line]
    ordered = sorted(claims, key=lambda c: c[0])
    pieces: list[str] = []
    i = 0
    for s, e, text in ordered:
        if s < i:  # defensive: skip overlaps that slipped through
            continue
        if i < s:
            pieces.append(line[i:s])
        pieces.append(text)
        i = e
    if i < len(line):
        pieces.append(line[i:])
    return pieces


# --------------------------------------------------------------------------- #
# I/O
# --------------------------------------------------------------------------- #


def output_path_for(input_name: str | None) -> str:
    if input_name is None or input_name == "-":
        return "stdin.scrm"
    return input_name + ".scrm"


# Output files this run has opened for writing, in the order they were opened.
# A run that stops early leaves truncated, unusable results behind, so ``main``
# deletes exactly these paths whenever it aborts. Output files of earlier runs
# are never registered here and are therefore never touched, even when they sit
# next to the ones this run produced.
_run_outputs: list[str] = []


def reset_run_outputs() -> None:
    """Forget the output files of a previous run (called once per run)."""
    _run_outputs.clear()


def register_run_output(path: str) -> None:
    """Record ``path`` as an output file produced by the current run."""
    if path not in _run_outputs:
        _run_outputs.append(path)


@contextmanager
def _hold_interrupts() -> Iterator[None]:
    """Ignore Ctrl+C for the duration of a critical section.

    Cleaning up after an aborted run must not itself be left half finished by
    a further Ctrl+C from a user hammering the key. The process is on its way
    out either way, so the extra signal has nothing useful left to interrupt.
    """
    try:
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:  # signals can only be installed from the main thread
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def remove_run_outputs() -> list[str]:
    """Delete every output file recorded for the current run.

    Returns the paths that were removed, most recently written first. A file
    that has already vanished is ignored and one that cannot be deleted is
    reported and skipped: the caller is aborting anyway, so a failed cleanup
    must not replace the original reason for stopping.
    """
    removed: list[str] = []
    with _hold_interrupts():
        for path in reversed(_run_outputs):
            try:
                os.remove(path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                sys.stderr.write(f"{PROG}: cannot remove output file {path}: {exc}\n")
                continue
            removed.append(path)
        _run_outputs.clear()
    return removed


def _discard_run_outputs() -> None:
    """Remove this run's output files and report each deletion on stderr."""
    for path in remove_run_outputs():
        sys.stderr.write(f"{PROG}: removed output file: {path}\n")


def _exception_detail(exc: BaseException) -> str:
    """One-line description of a failure, for users who did not ask for -d."""
    text = str(exc).strip()
    name = type(exc).__name__
    return f"{name}: {text}" if text else name


# Control characters stripped from every input line. Covers the C0 range and
# DEL, but deliberately keeps TAB (\x09); newline (\x0a) never reaches this
# since lines are already split on it. This removes stray junk such as a
# carriage return (^M, \x0d) -- whether mid-line or from a CRLF ending -- or a
# BEL (^G, \x07) that would otherwise corrupt the output.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _strip_control_chars(text: str) -> str:
    return _CONTROL_CHARS_RE.sub("", text)


def _escape_control_chars(text: str) -> str:
    pieces: list[str] = []
    for ch in text:
        if ch.isprintable():
            pieces.append(ch)
            continue
        code = ord(ch)
        if code == 0x7F:
            pieces.append("^?")
        elif code < 0x20:
            pieces.append("^" + chr(code + 0x40))
        elif code <= 0xFFFF:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(f"\\U{code:08x}")
    return "".join(pieces)


class _ReconfigurableTextIO(Protocol):
    def reconfigure(self, *, newline: str) -> None: ...


def _reconfigure_newline(stream: TextIO, newline: str) -> None:
    try:
        cast(_ReconfigurableTextIO, stream).reconfigure(newline=newline)
    except (AttributeError, ValueError):
        pass


def _source_label(input_name: str | None) -> str:
    """Display name for an input in the progress bar and the summary line."""
    if input_name is None or input_name == "-":
        return "stdin"
    return _escape_control_chars(os.path.basename(input_name))


def process_source(
    scrambler: Scrambler,
    input_name: str | None,
    output_name: str,
    show_progress: bool = False,
    progress_name_width: int | None = None,
) -> None:
    # The literal "stdout" writes results to standard output instead of a file.
    to_stdout = output_name == "stdout"

    if (
        not to_stdout
        and input_name is not None
        and input_name != "-"
        and os.path.exists(input_name)
        and os.path.exists(output_name)
        and (os.path.abspath(input_name) == os.path.abspath(output_name))
    ):
        error(f"refusing to overwrite the input file: {input_name}")

    # Split lines only on "\n" (newline="\n") so a lone CR (^M) and other
    # control characters are not treated as line terminators. Any carriage
    # return (a lone mid-line ^M or the CR of a CRLF ending) is then stripped
    # as a control character, normalizing output to LF line endings.
    with ExitStack() as stack:
        if input_name is None or input_name == "-":
            infh = sys.stdin
            _reconfigure_newline(infh, "\n")
        else:
            try:
                infh = stack.enter_context(
                    open(input_name, "r", encoding="utf-8", newline="\n")
                )
            except OSError as exc:
                error(f"cannot open input file {input_name}: {exc}")

        # newline="" on output: write the computed "\n" line endings verbatim,
        # with no platform translation.
        if to_stdout:
            outfh = sys.stdout
            _reconfigure_newline(outfh, "")
        else:
            try:
                outfh = stack.enter_context(
                    open(output_name, "w", encoding="utf-8", newline="")
                )
            except OSError as exc:
                error(f"cannot open output file {output_name}: {exc}")
            # Opening for writing created the file, or discarded the contents of
            # an existing one; either way it now holds nothing but this run's
            # output, so record it as ours to clean up if the run is interrupted.
            register_run_output(output_name)

        # Labels the progress bar and the tally below, padded so the inputs of a
        # multi-file run line up.
        source_name = _source_label(input_name)
        source_desc = source_name.ljust((progress_name_width or len(source_name)) + 1)

        progress = None
        if show_progress and not to_stdout:
            total_lines = None
            if infh.seekable():
                total_lines = sum(1 for _ in infh)
                infh.seek(0)
            progress = tqdm(
                total=total_lines,
                desc=source_desc,
                unit="line",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} lines",
                ascii=" .",
            )

        # The scrambler is reused across inputs, so the tally reported below
        # covers this file alone.
        scrambler.reset_scrambled_count()

        try:
            for raw in infh:
                if raw.endswith("\n"):
                    body, eol = raw[:-1], "\n"
                else:
                    body, eol = raw, ""
                # Strip stray control characters, including carriage returns:
                # a trailing CR from a CRLF ending or a lone mid-line ^M is
                # removed, so output line endings are normalized to LF.
                body = _strip_control_chars(body)
                outfh.write(scrambler.process_line(body) + eol)
                if progress is not None:
                    progress.update(1)
        finally:
            # Close before the summary so tqdm's final redraw of the bar cannot
            # land on top of it.
            if progress is not None:
                progress.close()

        outfh.flush()
        count = scrambler.scrambled_count
        noun = "string" if count == 1 else "strings"
        sys.stderr.write(f"{source_desc}: Scrambled {count} {noun}\n")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, add_help=False)
    parser.add_argument("-c", "--config")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-k", "--key")
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--version", action="store_true")
    parser.add_argument("files", nargs="*")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # -h/--help, -v/--version, and normal scrambling are mutually exclusive
    # modes. The terminal flags must be issued on their own.
    terminal = []
    if args.help:
        terminal.append("-h/--help")
    if args.version:
        terminal.append("-v/--version")

    if terminal:
        others = []
        if args.config is not None:
            others.append("-c/--config")
        if args.debug:
            others.append("-d/--debug")
        if args.key is not None:
            others.append("-k/--key")
        if args.output is not None:
            others.append("-o/--output")
        if args.files:
            others.append("FILE")
        conflicts = terminal[1:] + others
        if conflicts:
            error(f"{terminal[0]} cannot be combined with {', '.join(conflicts)}")
        if args.help:
            sys.stdout.write(HELP_TEXT)
            return 0
        sys.stdout.write(version_text())
        return 0

    config_path = args.config or discover_config()

    files = args.files or [None]  # None => stdin
    # stdin ("-") cannot be mixed with named files (or a second "-").
    if "-" in args.files and len(args.files) > 1:
        error("cannot combine stdin (-) with other input files")
    if args.output and len([f for f in files]) > 1:
        error("-o/--output cannot be used with multiple input files")

    rules = load_rules(config_path, args.debug)
    key = acquire_key(args.key, args.debug)
    scrambler = Scrambler(key, rules, debug=args.debug)
    progress_name_width = max(
        (len(_source_label(name)) for name in args.files if name != "-"),
        default=0,
    )

    reset_run_outputs()
    current_input: str | None = None
    completed = False
    try:
        for input_name in files:
            current_input = input_name
            out_name = args.output or output_path_for(input_name)
            process_source(
                scrambler,
                input_name,
                out_name,
                show_progress=input_name not in (None, "-") and not args.debug,
                progress_name_width=progress_name_width,
            )
        completed = True
    except KeyboardInterrupt:
        # Ctrl+C: whatever has been written is a partial scramble of the input,
        # so the file is discarded below rather than left looking complete. 130
        # is the conventional shell status for SIGINT.
        sys.stderr.write(f"\n{PROG}: interrupted\n")
        return 130
    except Exception as exc:  # noqa: BLE001 - a CLI's last line of defence
        # Every way a run can fail mid-file -- a UnicodeDecodeError on input
        # that is not valid UTF-8, a full disk, a bug in a rule -- ends in the
        # same unusable partial output, and none of them should reach the user
        # as a traceback. The traceback is what -d adds.
        sys.stderr.write(
            f"{PROG}: error while scrambling {_source_label(current_input)}: "
            f"{_exception_detail(exc)}\n"
        )
        if args.debug:
            traceback.print_exc()
        return 1
    finally:
        # Runs on every way out of the loop, so the aborts with no handler of
        # their own -- the SystemExit behind an error() report, anything raised
        # from outside the Exception hierarchy -- discard their output as well.
        if not completed:
            _discard_run_outputs()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\n")
        sys.exit(130)
