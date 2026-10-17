#!/usr/bin/env python
"""Anonymize a Logseq/Tine graph for sharing (e.g. reporting a performance bug)
while keeping it structurally realistic: same page count, same block tree per
page, same block ids, same markdown formatting/links/tags — only prose text,
page names, and asset contents are replaced.

Usage:
    python anonymize_graph.py anonymize <source_graph_dir> <output_dir>
    python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --n 50
    python anonymize_graph.py lookup "dstack"

Determinism: every replacement is HMAC(salt, original_string) -> deterministic
fake text. Same input string always maps to the same fake output (so a page
referenced from 40 blocks gets the same fake name everywhere), but changing
even one character produces a completely different hash and thus a totally
different fake string (no partial-similarity leakage). The salt is generated
once and cached in --seed-file so re-running the tool reproduces the same
mapping; delete that file to get a fresh, unrelated mapping.
"""
import argparse
import hashlib
import logging
import logging.handlers
import math
import os
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

__version__ = "0.2.0"

LOG = logging.getLogger("anonymize_graph")

CONSONANTS = "bcdfghjklmnprstvz"
VOWELS = "aeiou"

# Logseq encodes '/' in namespaced page filenames. Both conventions are seen
# in the wild depending on Logseq version/config; we round-trip whichever the
# source file uses.
NAMESPACE_ENCODINGS = ["%2F", "___"]

ASSET_STUBS = {
    ".png": bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
        "1f15c4890000000a49444154789c6360000002000100ffff03000006"
        "00057cd7c40000000049454e44ae426082"
    ),
    ".jpg": b"\xff\xd8\xff\xd9",  # smallest well-formed JPEG (SOI+EOI, no data)
    ".jpeg": b"\xff\xd8\xff\xd9",
    ".pdf": b"%PDF-1.4\n%%EOF\n",
}
DEFAULT_STUB = b"stub\n"

# Discrete placeholder-image side lengths (px): fine-grained at the tiny end
# (icons/favicons), coarser doubling above 64px up to the hard cap. Generic
# progression, not tuned to any particular graph's asset sizes.
MAX_IMAGE_DIM = 8192


def size_buckets() -> list:
    buckets = list(range(1, 5))  # 1, 2, 3, 4 — step 1
    buckets += list(range(16, 65, 16))  # 16, 32, 48, 64 — step 16
    b = buckets[-1]
    while b < MAX_IMAGE_DIM:
        b *= 2
        buckets.append(b)
    return buckets


# Generic assumed byte-size range for real images, tiny icon to high-res
# photo — used to log-scale a file's byte size onto SIZE_BUCKETS. Not derived
# from any specific graph; files outside this range just clamp to the
# smallest/largest bucket.
ASSUMED_MIN_IMAGE_BYTES = 32
ASSUMED_MAX_IMAGE_BYTES = 8 * 1024 * 1024


def bucket_for_bytes(byte_size: int, buckets: list) -> int:
    clamped = min(max(byte_size, ASSUMED_MIN_IMAGE_BYTES), ASSUMED_MAX_IMAGE_BYTES)
    span = math.log2(ASSUMED_MAX_IMAGE_BYTES / ASSUMED_MIN_IMAGE_BYTES)
    frac = math.log2(clamped / ASSUMED_MIN_IMAGE_BYTES) / span
    return buckets[round(frac * (len(buckets) - 1))]


def real_image_aspect(path: Path) -> float:
    """width/height of the real asset, so the placeholder isn't square when
    the original wasn't (e.g. a 16:9 screenshot). Falls back to square (1.0)
    if the file can't be read as an image — never fatal, just less faithful."""
    from PIL import Image  # lazy: only --include-anonymized-assets needs Pillow

    try:
        with Image.open(path) as im:
            w, h = im.size
        if w > 0 and h > 0:
            return w / h
    except Exception as exc:
        LOG.warning("could not read image dimensions for %s (%s) — using square placeholder", path, exc)
    return 1.0


def placeholder_dims(byte_size: int, aspect: float, buckets: list) -> tuple:
    """Long side comes from the byte-size bucket; short side is derived from
    the real aspect ratio and snapped to the same bucket list, so dimensions
    stay visually 'chunky' like the buckets rather than arbitrary pixels."""
    long_side = bucket_for_bytes(byte_size, buckets)
    ratio = max(aspect, 1 / aspect) if aspect > 0 else 1.0
    short_side = min(buckets, key=lambda b: abs(b - long_side / ratio))
    short_side = min(short_side, long_side)
    return (long_side, short_side) if aspect >= 1 else (short_side, long_side)


def make_checkerboard(width: int, height: int, out_path: Path) -> None:
    import numpy as np  # lazy: only --include-anonymized-assets needs numpy
    from PIL import Image

    cell = max(1, min(width, height, 16))
    yy, xx = np.indices((height, width))
    pattern = (((xx // cell) + (yy // cell)) % 2 * 255).astype("uint8")
    Image.fromarray(pattern, mode="L").save(out_path, optimize=True)


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_dir / "anonymize.log", maxBytes=10_000_000, backupCount=20, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)


def rng_for(salt: bytes, text: str) -> random.Random:
    """Deterministic RNG seeded from HMAC-SHA256(salt, text) — the single
    mechanism behind both guarantees: same text -> same seed -> same output;
    a one-character change in text -> unrelated hash -> unrelated output."""
    digest = hashlib.sha256(salt + text.encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest, "big"))


def fake_syllables(rng: random.Random, target_len: int) -> str:
    out = ""
    while len(out) < target_len:
        syll = rng.choice(CONSONANTS) + rng.choice(VOWELS)
        if rng.random() < 0.35:
            syll += rng.choice(CONSONANTS)
        out += syll
    return out[: max(target_len, 2)]


class UniqueFakes:
    """One run's real -> fake mapping for names that must stay distinct (page
    names, property keys). Short names have a tiny fake space (3 letters for a
    3-letter page name), so two real names can hash to one fake and their
    links would merge. A fake already taken by another real name is re-rolled
    with an attempt counter. Compared case-insensitively, matching Logseq and
    case-insensitive filesystems."""

    def __init__(self):
        self.by_real = {}
        self.taken = set()

    def get(self, real: str, make, is_reserved=lambda fake: False) -> str:
        key = real.lower()
        if key not in self.by_real:
            for attempt in range(1000):
                fake = make(key if attempt == 0 else f"{key}#{attempt}")
                if fake.lower() not in self.taken and not is_reserved(fake.lower()):
                    break
            else:
                sys.exit(f"Could not generate a unique fake for {real!r}")
            self.by_real[key] = fake
            self.taken.add(fake.lower())
        return self.by_real[key]


PAGE_NAME_FAKES = UniqueFakes()


def fake_name(salt: bytes, text: str) -> str:
    """For page names / tags / link labels: 1-3 human-readable fake words,
    length roughly matched to the original so page-size-in-kb stays close.
    Hashed case-insensitively — Logseq treats #Project and [[project]] as the
    same page, so they must map to the same fake name."""
    def make(seed: str) -> str:
        rng = rng_for(salt, seed)
        n_words = 1 if len(text) < 8 else rng.randint(1, 3)
        target = max(len(text), 3)
        per_word = max(target // n_words, 3)
        return " ".join(fake_syllables(rng, per_word).capitalize() for _ in range(n_words))

    return PAGE_NAME_FAKES.get(text, make)


def fake_prose(salt: bytes, text: str) -> str:
    """Replace a run of plain prose with synthetic words of ~matching total
    character length, preserving a trailing sentence-punctuation mark if any
    (cheap realism, not required by spec but harmless)."""
    stripped = text.strip()
    # Skip only true ASCII-punctuation-only runs (e.g. a lone "." between tokens).
    # Emoji/symbols are also non-alnum but must NOT take this early return, or an
    # emoji-only line (no letters/digits at all) would leak through verbatim.
    if not stripped or all(not c.isalnum() and ord(c) < 128 for c in stripped):
        return text
    trailing = stripped[-1] if stripped[-1] in ".!?,:;" else ""
    rng = rng_for(salt, text)
    target = len(stripped)
    out_words = []
    produced = 0
    while produced < target:
        w = fake_syllables(rng, rng.randint(3, 8))
        out_words.append(w)
        produced += len(w) + 1
    body = " ".join(out_words)
    if out_words:
        body = body[0].upper() + body[1:]
    leading_ws = text[: len(text) - len(text.lstrip())]
    trailing_ws = text[len(text.rstrip()):]
    return leading_ws + body + trailing + trailing_ws


def fake_asset_filename(salt: bytes, filename: str) -> str:
    """Keyed on the bare filename only (not its path) so the same physical
    asset gets the same fake name no matter which page references it, or how
    many '../' segments separate that page from assets/ — Logseq assets are
    conventionally a single flat folder, so filenames are assumed unique."""
    stem, ext = os.path.splitext(filename)
    return fake_syllables(rng_for(salt, filename), max(len(stem), 6)) + ext.lower()


FILE_EXTENSIONS = {
    "pdf", "png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "md", "txt", "org", "edn", "csv", "json",
    "html", "htm", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "epub", "zip",
    "mp3", "mp4", "m4a", "wav", "mov", "webm", "py", "js", "ts", "excalidraw",
}


def anonymize_link_url(salt: bytes, url: str) -> str:
    """Web links keep looking like web links ('.example' is an IANA-reserved
    TLD that will never resolve, so fake web links are inert). A path through
    an assets/ folder keeps its directory prefix verbatim (structural, not
    sensitive) and only fakes the filename, matching how the real asset file
    gets renamed on disk. Any other local path fakes every segment."""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        rng = rng_for(salt, url)
        domain = fake_syllables(rng, 8)
        path = fake_syllables(rng, 6)
        return f"https://{domain}.example/{path}"
    if "assets/" in url.replace("\\", "/"):
        dir_part, _, filename = url.replace("\\", "/").rpartition("/")
        return dir_part + "/" + fake_asset_filename(salt, filename)
    m = re.match(r"^((?:\.\./|\./)*)(.*)$", url)
    prefix, rest = m.group(1), m.group(2)
    parts = rest.split("/")
    ext = ""
    if "." in parts[-1]:
        stem, candidate = parts[-1].rsplit(".", 1)
        # Only a known file type survives: "site.dk" or "[a.com] - title"
        # would otherwise leak their tail as a fake "extension".
        if candidate.lower() in FILE_EXTENSIONS:
            parts[-1], ext = stem, "." + candidate
    new_parts = [fake_syllables(rng_for(salt, p), max(len(p), 3)) for p in parts if p]
    return prefix + "/".join(new_parts) + ext


def anonymize_page_ref(salt: bytes, name: str) -> str:
    """Namespaced pages (parent/child) get each segment anonymized
    independently and rejoined, so the namespace hierarchy still works in
    the output graph — a link to the child still nests under the same
    (now-fake) parent name everywhere it's referenced."""
    if "/" in name:
        return "/".join(fake_name(salt, seg) if seg else seg for seg in name.split("/"))
    return fake_name(salt, name)


# --- inline markdown tokenizer -------------------------------------------
# Order matters: earlier alternatives win on overlapping matches.
INLINE_RE = re.compile(
    r"(?P<blockref>\(\([0-9a-fA-F-]{8,}\)\))"
    r"|(?P<code>`[^`\n]+`)"
    r"|(?P<image>!\[(?P<ialt>[^\]]*)\]\((?P<isrc>\(\([0-9a-fA-F-]{8,}\)\)|[^)]+)\))"
    r"|(?P<link>\[(?P<llabel>[^\]]*)\]\((?P<lurl>\(\([0-9a-fA-F-]{8,}\)\)|[^)]+)\))"
    r"|(?P<bareurl>[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\]\)]+)"
    r"|(?P<macro>\{\{(?P<mname>[a-zA-Z0-9_-]+)(?P<mbody>[^{}]*)\}\})"
    r"|(?P<wikitag>\#\[\[(?P<wtname>[^\]]+)\]\])"
    r"|(?P<wikilink>\[\[(?P<wname>[^\]]+)\]\])"
    r"|(?P<tag>(?<![\w#])\#(?P<tname>[\w/-]+))"
    r"|(?P<bold>\*\*(?P<bcontent>.+?)\*\*)"
    r"|(?P<italic>(?<!\*)\*(?P<icontent>[^*\n]+)\*(?!\*))"
    r"|(?P<underscore>_(?P<ucontent>[^_\n]+)_)"
    r"|(?P<strike>~~(?P<scontent>.+?)~~)"
)


def anonymize_inline(salt: bytes, text: str, keep_code: bool) -> str:
    out = []
    pos = 0
    for m in INLINE_RE.finditer(text):
        out.append(fake_prose(salt, text[pos:m.start()]))
        kind = m.lastgroup
        if kind == "blockref":
            out.append(m.group(0))  # block ids are retained verbatim
        elif kind == "code":
            out.append(m.group(0) if keep_code else "`" + fake_prose(salt, m.group(0)[1:-1]) + "`")
        elif kind == "image":
            alt, src = m.group("ialt"), m.group("isrc")
            rendered_src = src if src.startswith("((") else anonymize_link_url(salt, src)
            out.append(f"![{fake_prose(salt, alt) if alt else alt}]({rendered_src})")
        elif kind == "link":
            label, url = m.group("llabel"), m.group("lurl")
            # A link target can itself be a block ref, "[label](((id)))" — keep
            # the id verbatim like any other blockref instead of hashing it as
            # a URL, or the id inside is destroyed.
            rendered_url = url if url.startswith("((") else anonymize_link_url(salt, url)
            out.append(f"[{fake_prose(salt, label) if label else label}]({rendered_url})")
        elif kind == "bareurl":
            out.append(anonymize_link_url(salt, m.group(0)))
        elif kind == "macro":
            out.append("{{" + m.group("mname") + anonymize_inline(salt, m.group("mbody"), keep_code) + "}}")
        elif kind == "wikitag":
            out.append("#[[" + anonymize_page_ref(salt, m.group("wtname")) + "]]")
        elif kind == "wikilink":
            out.append("[[" + anonymize_page_ref(salt, m.group("wname")) + "]]")
        elif kind == "tag":
            out.append("#" + anonymize_page_ref(salt, m.group("tname")))
        elif kind == "bold":
            out.append("**" + anonymize_inline(salt, m.group("bcontent"), keep_code) + "**")
        elif kind == "italic":
            out.append("*" + anonymize_inline(salt, m.group("icontent"), keep_code) + "*")
        elif kind == "underscore":
            out.append("_" + anonymize_inline(salt, m.group("ucontent"), keep_code) + "_")
        elif kind == "strike":
            out.append("~~" + anonymize_inline(salt, m.group("scontent"), keep_code) + "~~")
        pos = m.end()
    out.append(fake_prose(salt, text[pos:]))
    return "".join(out)


PROPERTY_RE = re.compile(r"^(\s*)([A-Za-z][\w.-]*)::\s?(.*)$")
CODE_FENCE_RE = re.compile(r"^(\s*)```")
BULLET_RE = re.compile(r"^(\s*)(-\s+)(.*)$")
BLOCKREF_VALUE_RE = re.compile(r"^\(\([0-9a-fA-F-]{8,}\)\)$")

# alias::/tags:: (comma-separated real page names) and title:: (a page-name
# override) are known text/list properties whose *entire* value is a bare
# page name, not wrapped in [[ ]] — handled specially below. Source: tine's
# PAGE_PROP_SPECS in src/editor/properties.ts.
PAGE_REF_LIST_PROPERTIES = {"alias", "tags"}
PAGE_REF_TEXT_PROPERTIES = {"title"}

# Keys whose value references other property keys: query-properties:: holds an
# EDN vector of :keywords, query-sort-by:: a single key. page/block are
# Logseq's own query-table columns.
KEY_REFERENCE_PROPERTIES = {"query-properties", "query-sort-by"}
QUERY_COLUMNS = {"page", "block"}
QUERY_KEYWORD_RE = re.compile(r"(?<![\w-]):?([A-Za-z_][\w.-]*)")

# Tine table config whose values reference field names, which are property
# keys. Source: PARTICIPATING_KEYS and FORMULA_PREFIX in tine
# src/sheet/renameField.ts, BUILTIN_FIELDS in src/sheet/config.ts.
TINE_FIELDS = "tine.fields"
TINE_GROUP_BY = "tine.group-by"
TINE_AGGREGATES = "tine.col-aggregates"
TINE_FILTER = "tine.filter"
TINE_FORMULA_PREFIX = "tine.formula."
TINE_BUILTIN_FIELDS = {"state", "priority", "scheduled", "deadline", "tags", "page"}
FORMULA_RESERVED = {"true", "false", "null", "formula"}
FORMULA_TOKEN_RE = re.compile(
    r"(?P<string>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
    r"|(?P<number>\d[\w.]*)"
    r"|(?P<ident>[A-Za-z_][A-Za-z0-9_-]*)"
)
FIELD_ID_RE = re.compile(r"^(\s*)(prop|formula):(.+?)(\s*)$")

# Keys with their own value syntax, handled in code: they keep their name
# whatever the config says.
STRUCTURED_KEYS = (PAGE_REF_LIST_PROPERTIES | PAGE_REF_TEXT_PROPERTIES | KEY_REFERENCE_PROPERTIES
                   | {TINE_FIELDS, TINE_GROUP_BY, TINE_AGGREGATES, TINE_FILTER})

# Any value is real content unless the config allows it or it is a bare
# literal carrying nothing identifying: boolean, number (optionally with a
# short unit: 323px, 14d), uuid, ISO date/datetime (SRS card-* dates, ...).
SAFE_LITERAL_RE = re.compile(
    r"^(?:true|false"
    r"|-?\d+(?:\.\d+)?(?:[a-z]{1,3}|%)?"
    r"|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?)$",
    re.IGNORECASE,
)
# A value that is just a path into assets/ (banner::, file-path::) is faked
# like an image src, so it still points at the renamed asset file.
ASSET_PATH_VALUE_RE = re.compile(r"^(?:\.\.?/)*assets/\S+$")
PATH_PROPERTIES = {"file-path"}

# Kept values can still embed a real [[Page]] link, #tag, or ((blockref)) —
# these get caught and anonymized wherever they appear.
PAGE_REF_TOKEN_RE = re.compile(
    r"(?P<blockref>\(\([0-9a-fA-F-]{8,}\)\))"
    r"|(?P<wikitag>\#\[\[(?P<wtname>[^\]]+)\]\])"
    r"|(?P<wikilink>\[\[(?P<wname>[^\]]+)\]\])"
    r"|(?P<tag>(?<![\w#])\#(?P<tname>[\w/-]+))"
)


def anonymize_page_ref_value(salt: bytes, value: str) -> str:
    """Same as anonymize_page_ref, except a value that's itself a block ref
    (tags::/alias:: can point at a block, not just a page) is kept verbatim —
    otherwise the id gets hashed as if it were a page name and destroyed."""
    if BLOCKREF_VALUE_RE.match(value):
        return value
    return anonymize_page_ref(salt, value)


def anonymize_property_value_refs(salt: bytes, value: str) -> str:
    """Scan any property value for embedded [[Page]] links / #tags /
    ((blockrefs)) and anonymize just those spans, leaving everything else in
    the value (numbers, booleans, enum strings, plain text) untouched."""
    out = []
    pos = 0
    for m in PAGE_REF_TOKEN_RE.finditer(value):
        out.append(value[pos:m.start()])
        kind = m.lastgroup
        if kind == "blockref":
            out.append(m.group(0))
        elif kind == "wikitag":
            out.append("#[[" + anonymize_page_ref(salt, m.group("wtname")) + "]]")
        elif kind == "wikilink":
            out.append("[[" + anonymize_page_ref(salt, m.group("wname")) + "]]")
        elif kind == "tag":
            out.append("#" + anonymize_page_ref(salt, m.group("tname")))
        pos = m.end()
    out.append(value[pos:])
    return "".join(out)


PROPERTY_KEY_FAKES = UniqueFakes()

CONFIG_SCHEMA_VERSION = "1.0.0"
CONFIG_LAYERS = ["config.default.yaml", "config.yaml", "config.local.yaml"]


@dataclass(frozen=True)
class PropertyPolicy:
    """Which property keys keep their real name, and which of their values
    stay real. keep maps a lowercased key to None (every value stays) or to
    the lowercased set of allowed values."""
    keep: dict

    def keeps_key(self, key_lower: str) -> bool:
        return (key_lower in self.keep or key_lower in STRUCTURED_KEYS
                or key_lower.startswith(TINE_FORMULA_PREFIX))

    def allows_value(self, key_lower: str, value: str) -> bool:
        if key_lower not in self.keep:
            return False
        allowed = self.keep[key_lower]
        return allowed is None or value.lower() in allowed

    def allowed_anywhere(self, value: str) -> bool:
        return any(allowed and value.lower() in allowed for allowed in self.keep.values())


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        out[key] = deep_merge(out[key], value) if isinstance(out.get(key), dict) and isinstance(value, dict) else value
    return out


def check_schema_version(found, source: Path) -> None:
    """First number differs: the file cannot be read, exit. Second differs:
    the file may use options this version ignores or lacks, warn loudly."""
    got, want = str(found).split("."), CONFIG_SCHEMA_VERSION.split(".")
    if len(got) != 3 or got[0] != want[0]:
        sys.exit(f"{source}: schema_version {found!r} is incompatible with this tool's {CONFIG_SCHEMA_VERSION}")
    if got[1] != want[1]:
        msg = f"WARNING: {source}: schema_version {found} differs from this tool's {CONFIG_SCHEMA_VERSION}"
        print(msg, file=sys.stderr, flush=True)
        LOG.warning(msg)


def load_property_policy(extra_config: Path = None) -> PropertyPolicy:
    """Deep-merge the config layers next to this script (missing optional
    layers skipped), then an explicit --config file, into a PropertyPolicy."""
    paths = [Path(__file__).parent / name for name in CONFIG_LAYERS]
    if not paths[0].exists():
        sys.exit(f"Missing {paths[0]} — it ships with the tool and lists the properties kept real.")
    if extra_config is not None:
        if not extra_config.exists():
            sys.exit(f"--config file {extra_config} does not exist.")
        paths.append(extra_config)
    merged = {}
    for path in paths:
        if not path.exists():
            continue
        layer = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if "schema_version" not in layer:
            sys.exit(f"{path}: missing schema_version (this tool reads {CONFIG_SCHEMA_VERSION}).")
        check_schema_version(layer["schema_version"], path)
        merged = deep_merge(merged, layer)

    keep = {}
    for key, rule in (merged.get("keep_properties") or {}).items():
        if rule is None:
            continue
        if rule == "any":
            keep[str(key).lower()] = None
        elif isinstance(rule, list):
            keep[str(key).lower()] = frozenset(str(v).lower() for v in rule)
        else:
            sys.exit(f"keep_properties.{key}: expected 'any', a list of values, or null, got {rule!r}")
    return PropertyPolicy(keep)


def fake_property_key(salt: bytes, key: str, policy: PropertyPolicy) -> str:
    """Property keys are names too (companies::, skills::). A key the policy
    keeps stays; any other gets a fake one. Lowercase, because Logseq treats
    Src:: and src:: as one key. Each -/_/. segment is faked on its own so the
    key's shape survives. Re-rolled if it lands on a reserved name."""
    key_lower = key.lower()
    if policy.keeps_key(key_lower):
        return key
    parts = re.split(r"([-_.])", key_lower)

    def make(seed: str) -> str:
        attempt = seed.rpartition("#")[2] if "#" in seed else "0"
        return "".join(
            p if p in {"-", "_", "."} or not p else fake_syllables(rng_for(salt, f"key:{attempt}:{p}"), max(len(p), 3))
            for p in parts
        )

    def is_reserved(fake: str) -> bool:
        return (policy.keeps_key(fake) or fake in TINE_BUILTIN_FIELDS or fake in FORMULA_RESERVED
                or fake in QUERY_COLUMNS or fake.startswith("tine."))

    return PROPERTY_KEY_FAKES.get(key_lower, make, is_reserved)


def fake_field_name(salt: bytes, name: str, policy: PropertyPolicy) -> str:
    """A Tine field name is a property key, except Tine's own built-in columns."""
    return name if name.lower() in TINE_BUILTIN_FIELDS else fake_property_key(salt, name, policy)


def anonymize_property_value(salt: bytes, key: str, value: str, policy: PropertyPolicy, keep_code: bool) -> str:
    """Every property value counts as content, except values the policy allows
    for this key and bare non-identifying literals: those stay (refs inside
    still anonymized). Everything else goes through the same inline anonymizer
    as block prose, so links, URLs, refs and plain text in it are faked exactly
    as they would be in a block."""
    key_lower = key.lower()
    stripped = value.strip()
    if not stripped or SAFE_LITERAL_RE.match(stripped) or policy.allows_value(key_lower, stripped):
        return anonymize_property_value_refs(salt, value)
    if key_lower in PATH_PROPERTIES or ASSET_PATH_VALUE_RE.match(stripped):
        return anonymize_link_url(salt, stripped)
    return anonymize_inline(salt, stripped, keep_code)


def anonymize_tine_expression(salt: bytes, expr: str, policy: PropertyPolicy) -> str:
    """Tine formula/filter language: bare identifiers are fields (property
    keys), `name(` is a function, `x.name` a member, `formula.name` a formula
    ref. Field and formula names get faked like keys; "quoted" strings like
    values, unless the config allows them under some key."""
    out = []
    pos = 0
    for m in FORMULA_TOKEN_RE.finditer(expr):
        out.append(expr[pos:m.start()])
        text = m.group(0)
        if m.lastgroup == "string":
            inner = text[1:-1]
            keep = not inner or SAFE_LITERAL_RE.match(inner) or policy.allowed_anywhere(inner)
            out.append(text if keep else text[0] + fake_prose(salt, inner) + text[0])
        elif m.lastgroup == "ident":
            before, after = expr[:m.start()].rstrip(), expr[m.end():].lstrip()
            if text in FORMULA_RESERVED or after.startswith("("):
                out.append(text)
            elif before.endswith("."):
                is_formula_ref = re.search(r"(?<![\w-])formula\s*\.$", before)
                out.append(fake_property_key(salt, text, policy) if is_formula_ref else text)
            else:
                out.append(fake_field_name(salt, text, policy))
        else:
            out.append(text)
        pos = m.end()
    out.append(expr[pos:])
    return "".join(out)


def anonymize_field_id(salt: bytes, field_id: str, policy: PropertyPolicy) -> str:
    """A Tine column id: prop:<key>, formula:<name>, a built-in field, or a
    column index. Only the first two carry a name."""
    m = FIELD_ID_RE.match(field_id)
    if not m:
        return field_id
    lead, kind, name, trail = m.groups()
    return f"{lead}{kind}:{fake_field_name(salt, name, policy)}{trail}"


def anonymize_tine_fields(salt: bytes, value: str, policy: PropertyPolicy, keep_code: bool) -> str:
    """tine.fields:: name=type;name=enum:a,b,c — field names faked like keys,
    enum options faked like that key's values so they still match the rows."""
    out = []
    for segment in value.split(";"):
        name, eq, token = segment.partition("=")
        if not eq:
            out.append(fake_prose(salt, segment) if segment.strip() else segment)
            continue
        bare = name.strip()
        new_name = name.replace(bare, fake_field_name(salt, bare, policy), 1) if bare else name
        type_token = token.strip()
        if type_token.startswith("enum:"):
            options = [o.strip() for o in type_token[len("enum:"):].split(",")]
            faked = ",".join(anonymize_property_value(salt, bare, o, policy, keep_code) if o else o for o in options)
            token = token.replace(type_token, "enum:" + faked, 1)
        out.append(f"{new_name}={token}")
    return ";".join(out)


def anonymize_property_line(salt: bytes, line: str, policy: PropertyPolicy, keep_code: bool) -> str:
    """One `key:: value` line: the key through the policy, the value through
    whichever syntax that key's value has. Returns the line byte-for-byte when
    nothing changed (id::, collapsed::, ...)."""
    indent, key, value = PROPERTY_RE.match(line).groups()
    key_lower = key.lower()
    new_key = fake_property_key(salt, key, policy)
    if key_lower in PAGE_REF_LIST_PROPERTIES:
        new_value = ", ".join(anonymize_page_ref_value(salt, v.strip()) for v in value.split(",") if v.strip())
    elif key_lower in PAGE_REF_TEXT_PROPERTIES:
        new_value = anonymize_page_ref_value(salt, value.strip()) if value.strip() else value
    elif key_lower in KEY_REFERENCE_PROPERTIES:
        new_value = QUERY_KEYWORD_RE.sub(
            lambda m: m.group(0) if m.group(1).lower() in QUERY_COLUMNS
            else m.group(0)[: -len(m.group(1))] + fake_property_key(salt, m.group(1), policy),
            value,
        )
    elif key_lower == TINE_FIELDS:
        new_value = anonymize_tine_fields(salt, value, policy, keep_code)
    elif key_lower == TINE_GROUP_BY:
        new_value = anonymize_field_id(salt, value, policy)
    elif key_lower == TINE_AGGREGATES:
        new_value = ";".join(
            anonymize_field_id(salt, seg.partition("=")[0], policy) + "".join(seg.partition("=")[1:])
            for seg in value.split(";")
        )
    elif key_lower == TINE_FILTER or key_lower.startswith(TINE_FORMULA_PREFIX):
        new_value = anonymize_tine_expression(salt, value, policy)
        if key_lower.startswith(TINE_FORMULA_PREFIX):
            new_key = key[: len(TINE_FORMULA_PREFIX)] + fake_property_key(salt, key[len(TINE_FORMULA_PREFIX):], policy)
    else:
        new_value = anonymize_property_value(salt, key, value, policy, keep_code)
    if new_key == key and new_value == value:
        return line
    return f"{indent}{new_key}:: {new_value}"


def anonymize_page_body(salt: bytes, text: str, keep_code: bool, policy: PropertyPolicy) -> str:
    lines = text.split("\n")
    out_lines = []
    in_fence = False
    for line in lines:
        # A fence can open on the same physical line as the bullet dash
        # ("- ```rust"), not just on its own line — check the post-dash
        # content too, or the opener is missed and in_fence desyncs for
        # the rest of the page (later real content gets misread as code).
        bullet_for_fence = BULLET_RE.match(line)
        fence_probe = bullet_for_fence.group(3) if bullet_for_fence else line
        if CODE_FENCE_RE.match(fence_probe):
            in_fence = not in_fence
            out_lines.append(line)
            continue
        if in_fence:
            out_lines.append(line if keep_code else fake_prose(salt, line))
            continue
        if PROPERTY_RE.match(line):
            out_lines.append(anonymize_property_line(salt, line, policy, keep_code))
            continue
        bullet_m = BULLET_RE.match(line)
        if bullet_m:
            indent, dash, rest = bullet_m.groups()
            # "- key:: value" opens a properties-only block
            if PROPERTY_RE.match(rest):
                out_lines.append(indent + dash + anonymize_property_line(salt, rest, policy, keep_code))
            else:
                out_lines.append(indent + dash + anonymize_inline(salt, rest, keep_code))
            continue
        # non-bulleted continuation line: keep leading whitespace, fake the rest
        stripped = line.lstrip(" \t")
        leading = line[: len(line) - len(stripped)]
        out_lines.append(leading + anonymize_inline(salt, stripped, keep_code))
    return "\n".join(out_lines)


def decode_page_filename(stem: str) -> str:
    for enc in NAMESPACE_ENCODINGS:
        if enc in stem:
            return stem.replace(enc, "/")
    return stem


def encode_page_filename(name: str, encoding: str) -> str:
    return name.replace("/", encoding)


def detect_namespace_encoding(stem: str) -> str:
    for enc in NAMESPACE_ENCODINGS:
        if enc in stem:
            return enc
    return NAMESPACE_ENCODINGS[0]


def sample_by_size(files: list, n: int, rng: random.Random) -> list:
    """Pick n files spread evenly across the sorted-by-size distribution, one
    random pick per bucket — so a quick test run sees small, medium and huge
    pages alike instead of a plain random N, which (in a real graph, mostly
    tiny pages) would almost always miss the large ones that matter for a
    performance check."""
    if n >= len(files):
        return files
    ranked = sorted(files, key=lambda f: f.stat().st_size)
    total = len(ranked)
    picks = []
    for i in range(n):
        lo = i * total // n
        hi = max((i + 1) * total // n, lo + 1)
        picks.append(rng.choice(ranked[lo:hi]))
    return picks


def referenced_asset_names(files: list) -> set:
    ref_re = re.compile(r"!\[[^\]]*\]\(([^)]+)\)")
    names = set()
    for f in files:
        for m in ref_re.finditer(f.read_text(encoding="utf-8")):
            names.add(Path(m.group(1).replace("\\", "/")).name)
    return names


EDN_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
EDN_FAVORITES_RE = re.compile(r"(:favorites\s*\[)([^\]]*)(\])")
EDN_DEFAULT_HOME_RE = re.compile(r'(:default-home\s*\{[^}]*?:page\s*")((?:\\.|[^"\\])*)(")')
# Config sets of property keys, e.g. :block-hidden-properties #{:hidden}
EDN_KEY_SET_RE = re.compile(r"(:(?:block-hidden-properties|property-pages/excludelist)\s*#\{)([^}]*)(\})")
EDN_KEYWORD_RE = re.compile(r":([A-Za-z_][\w.-]*)")


def strip_edn_comments(text: str) -> str:
    """Drop every `;` comment (to end of line) that sits outside a string."""
    out = []
    in_string = escaped = in_comment = False
    for ch in text:
        if in_comment:
            if ch == "\n":
                in_comment = False
                out.append(ch)
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ";":
            in_comment = True
            continue
        out.append(ch)
    return "".join(out)


def scrub_config_edn(salt: bytes, text: str, policy: PropertyPolicy) -> str:
    """config.edn is app config, but :favorites and :default-home name real
    pages, key sets like :block-hidden-properties name real property keys, and
    comments can hold anything. Names get the same fakes as in the pages, so
    they still resolve, and every comment is dropped."""
    def fake_strings(segment: str) -> str:
        return EDN_STRING_RE.sub(lambda s: '"' + anonymize_page_ref(salt, s.group(1)) + '"', segment)

    def fake_keywords(segment: str) -> str:
        return EDN_KEYWORD_RE.sub(lambda k: ":" + fake_property_key(salt, k.group(1), policy), segment)

    text = strip_edn_comments(text)
    text = EDN_FAVORITES_RE.sub(lambda m: m.group(1) + fake_strings(m.group(2)) + m.group(3), text)
    text = EDN_KEY_SET_RE.sub(lambda m: m.group(1) + fake_keywords(m.group(2)) + m.group(3), text)
    return EDN_DEFAULT_HOME_RE.sub(lambda m: m.group(1) + anonymize_page_ref(salt, m.group(2)) + m.group(3), text)


IMAGE_EXTS = {".png", ".jpg", ".jpeg"}  # PDFs and everything else keep the plain stub

# App/theme config living in logseq/ (not graph content, so not swept up by
# CONTENT_DIRS) but needed to reproduce a graph's look/behavior when opened.
CONFIG_FILES = {"config.edn", "custom.css", "custom.js", "export.css"}


def anonymize_graph(
    source: Path,
    dest: Path,
    salt: bytes,
    keep_code: bool,
    force: bool,
    n: int = None,
    sample_seed: int = None,
    include_anonymized_assets: bool = False,
    include_assets: bool = False,
    policy: PropertyPolicy = None,
) -> None:
    policy = policy or load_property_policy()
    # Assets are excluded by default (no assets/ folder at all) — a graph's
    # images are usually the least anonymize-able and most identifying part of
    # a share, so opt-in is the safer default. Either --include-assets (plain
    # stub) or --include-anonymized-assets (checkerboard) turns writing them
    # back on; the latter implies the former.
    exclude_assets = not (include_assets or include_anonymized_assets)
    if dest.exists() and any(dest.iterdir()) and not force:
        sys.exit(f"Output dir {dest} exists and is not empty. Use --force or pick an empty dir.")
    dest.mkdir(parents=True, exist_ok=True)

    # Only pages/ and journals/ are live graph content. logseq/ is internal
    # config+backups (logseq/bak/ holds old timestamped copies of every edited
    # page); pages-archive/ holds pages the user themselves archived out of
    # the graph, so it's excluded too.
    CONTENT_DIRS = {"pages", "journals"}
    md_files = [f for f in source.rglob("*.md") if f.relative_to(source).parts[0] in CONTENT_DIRS]
    asset_files = [] if exclude_assets else list(source.rglob("assets/*"))
    if not md_files:
        sys.exit(f"No .md files found under {source} — wrong graph path?")

    if n is not None:
        sampled = sample_by_size(md_files, n, random.Random(sample_seed))
        print(f"Sampling {len(sampled)}/{len(md_files)} files across the size "
              f"distribution (seed={sample_seed})", flush=True)
        LOG.info("sampled %d/%d files, seed=%s", len(sampled), len(md_files), sample_seed)
        md_files = sampled
        wanted = referenced_asset_names(md_files)
        asset_files = [a for a in asset_files if a.name in wanted]

    page_count = 0
    total = len(md_files)
    for i, f in enumerate(md_files, 1):
        rel = f.relative_to(source)
        parts = list(rel.parts)
        is_journal = "journals" in parts
        text = f.read_text(encoding="utf-8")

        if is_journal:
            new_rel = rel  # journal dates are not treated as identifying content
        else:
            stem = rel.stem
            encoding = detect_namespace_encoding(stem)
            real_name = decode_page_filename(stem)
            fake_full_name = anonymize_page_ref(salt, real_name)
            new_stem = encode_page_filename(fake_full_name, encoding)
            new_rel = rel.with_name(new_stem + rel.suffix)
            page_count += 1

        print(f"[{i}/{total}] {rel} -> {new_rel}", flush=True)
        LOG.info("processing %s -> %s", rel, new_rel)

        out_path = dest / new_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            anonymize_page_body(salt, text, keep_code, policy), encoding="utf-8"
        )

    LOG.info("writing %d assets (excluded: %s, checkerboard placeholders: %s)",
              len(asset_files), exclude_assets, include_anonymized_assets)
    buckets = size_buckets() if include_anonymized_assets else None
    for asset in asset_files:
        rel = asset.relative_to(source)
        new_rel = rel.with_name(fake_asset_filename(salt, rel.name))
        out_path = dest / new_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        ext = asset.suffix.lower()
        if include_anonymized_assets and ext in IMAGE_EXTS:
            byte_size = asset.stat().st_size
            aspect = real_image_aspect(asset)
            width, height = placeholder_dims(byte_size, aspect, buckets)
            make_checkerboard(width, height, out_path)
        else:
            out_path.write_bytes(ASSET_STUBS.get(ext, DEFAULT_STUB))

    # App config, not graph content: copied byte-for-byte, never anonymized (see
    # README caveats — a custom.css selector or config.edn setting that embeds a
    # real page name would leak it verbatim).
    config_copied = 0
    for name in CONFIG_FILES:
        src_config = source / "logseq" / name
        if src_config.exists():
            out_path = dest / "logseq" / name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            if name == "config.edn":
                out_path.write_text(scrub_config_edn(salt, src_config.read_text(encoding="utf-8"), policy), encoding="utf-8")
            else:
                out_path.write_bytes(src_config.read_bytes())
            config_copied += 1
            LOG.info("copied config file verbatim: logseq/%s", name)

    print(f"Anonymized {page_count} pages, {len(asset_files)} assets, "
          f"copied {config_copied} config files -> {dest}")
    LOG.info("done: %d pages, %d assets, %d config files -> %s",
              page_count, len(asset_files), config_copied, dest)


def cmd_lookup(name: str, seed_file: Path) -> None:
    """Forward-only lookup: what does a real page/tag name anonymize to, using
    the same salt an earlier `anonymize` run used? Does not reverse fake ->
    real; it just re-runs the same deterministic fake_name() so you can find
    your own page in an already-anonymized graph."""
    if not seed_file.exists():
        sys.exit(f"No salt at {seed_file} — run 'anonymize' at least once first, it creates the salt.")
    salt = seed_file.read_bytes()
    fake = anonymize_page_ref(salt, name)
    print(f"{name}  ->  {fake}")
    print(f"filename: {encode_page_filename(fake, NAMESPACE_ENCODINGS[0])}.md")


def cmd_reverse_guess(dest: Path, guesses: list, seed_file: Path) -> None:
    """Demonstrates the exact risk documented in the README: with the salt,
    fake -> real is a dictionary attack, not a hard problem. For each guessed
    real name, recompute its fake filename (both namespace encodings, since we
    don't know which the original page used) and check whether that filename
    actually exists in the anonymized output. No slow hashing here to slow an
    attacker down — HMAC-SHA256 has no work factor, so this runs at wordlist
    speed. Never share salt.bin."""
    if not seed_file.exists():
        sys.exit(f"No salt at {seed_file} — nothing to test against.")
    if not guesses:
        sys.exit("No guesses given — pass --guess NAME (repeatable) and/or --wordlist FILE.")
    pages_dir = dest / "pages"
    if not pages_dir.exists():
        sys.exit(f"No pages/ folder under {dest} — wrong anonymized output path?")
    salt = seed_file.read_bytes()
    real_names = {f.name for f in pages_dir.rglob("*.md")}

    hits = 0
    for guess in guesses:
        fake_full = anonymize_page_ref(salt, guess)
        candidates = sorted({encode_page_filename(fake_full, enc) + ".md" for enc in NAMESPACE_ENCODINGS})
        match = next((c for c in candidates if c in real_names), None)
        if match:
            hits += 1
            print(f"MATCH     {guess!r:30} -> {match}")
        else:
            print(f"no match  {guess!r:30} (tried {', '.join(candidates)})")
    print(f"\n{hits}/{len(guesses)} guesses matched a real page in {dest}")


def main():
    p = argparse.ArgumentParser(
        description="Anonymize a Logseq/Tine graph, keeping structure/formatting/links intact.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    p_anon = sub.add_parser(
        "anonymize",
        help="Anonymize a graph (or a size-sampled subset of it)",
        epilog="Examples:\n"
               "  python anonymize_graph.py anonymize ~/notes ./anon-notes\n"
               "  python anonymize_graph.py anonymize ~/notes ./anon-test --n 50\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_anon.add_argument("source", type=Path, help="Path to the real Logseq/Tine graph folder")
    p_anon.add_argument("dest", type=Path, help="Output folder for the anonymized graph (must not exist or be empty)")
    p_anon.add_argument("--seed-file", type=Path, default=Path(__file__).parent / "salt.bin",
                         help="Where to cache the random salt (default: salt.bin next to this script). "
                              "NEVER commit or share this file — sharing it lets someone reverse the mapping "
                              "against known/guessed inputs.")
    p_anon.add_argument("--config", type=Path, default=None,
                         help="Extra YAML layer merged on top of config.default.yaml / config.yaml / "
                              "config.local.yaml, e.g. to keep more property keys or values real. "
                              "Example: --config my-props.yaml with\n"
                              "  schema_version: \"1.0.0\"\n"
                              "  keep_properties: {status: [todo, doing, done]}")
    p_anon.add_argument("--keep-code", action="store_true",
                         help="Leave inline `code` and fenced code blocks verbatim instead of anonymizing them")
    p_anon.add_argument("--force", action="store_true", help="Allow writing into a non-empty dest dir")
    p_anon.add_argument("--n", type=int, default=None,
                         help="Only process N files, sampled across the full file-size distribution "
                              "(small/medium/large alike, not just the first N or a plain random N) — "
                              "for a quick check before running the whole graph. Example: --n 50")
    p_anon.add_argument("--random-seed", default="42",
                         help="Seed for which file --n picks within each size bucket. Fixed by default "
                              "(42) so repeated test runs sample the same files. Pass 'random' for a "
                              "fresh, non-deterministic sample each run. This does not affect the "
                              "anonymization itself, which is always salt-based. Example: --random-seed random")
    p_anon.add_argument("--include-assets", action="store_true",
                         help="Write an assets/ folder (default: excluded entirely — image references in "
                              "page text are still rewritten to fake filenames either way, this only "
                              "controls whether the files themselves get copied). Each file becomes a tiny "
                              "fixed stub with no size/shape information. Example: --include-assets")
    p_anon.add_argument("--include-anonymized-assets", action="store_true",
                         help="Like --include-assets, but replace images (.png/.jpg/.jpeg — PDFs and other "
                              "types still get the plain stub) with deterministic black/white checkerboard "
                              "placeholders sized off the real file's byte size and aspect ratio. Requires "
                              "Pillow+numpy (pip install -r requirements.txt).")

    p_lookup = sub.add_parser(
        "lookup",
        help="Show what a real page/tag name anonymizes to, using an existing salt",
        epilog="Example: python anonymize_graph.py lookup dstack\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_lookup.add_argument("name", help="Real page or tag name, e.g. dstack")
    p_lookup.add_argument("--seed-file", type=Path, default=Path(__file__).parent / "salt.bin",
                           help="Salt file from the 'anonymize' run you're looking up against")

    p_reverse = sub.add_parser(
        "reverse-guess",
        help="Test whether guessed real page names can be found in an anonymized output (needs the salt)",
        epilog="Examples:\n"
               "  python anonymize_graph.py reverse-guess ./anon-test --guess dstack --guess \"Q3 plan\"\n"
               "  python anonymize_graph.py reverse-guess ./anon-test --wordlist candidates.txt\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_reverse.add_argument("dest", type=Path, help="Path to an already-anonymized output folder")
    p_reverse.add_argument("--guess", action="append", default=[], metavar="NAME",
                            help="A candidate real page/tag name to test. Repeatable.")
    p_reverse.add_argument("--wordlist", type=Path, default=None,
                            help="File with one candidate name per line, added to any --guess values")
    p_reverse.add_argument("--seed-file", type=Path, default=Path(__file__).parent / "salt.bin",
                            help="Salt file from the 'anonymize' run that produced dest")

    args = p.parse_args()

    if args.command == "lookup":
        cmd_lookup(args.name, args.seed_file)
        return

    if args.command == "reverse-guess":
        guesses = list(args.guess)
        if args.wordlist:
            guesses += [line.strip() for line in args.wordlist.read_text(encoding="utf-8").splitlines() if line.strip()]
        cmd_reverse_guess(args.dest, guesses, args.seed_file)
        return

    setup_logging(Path(__file__).parent / "logs")

    if args.seed_file.exists():
        salt = args.seed_file.read_bytes()
    else:
        salt = os.urandom(32)
        args.seed_file.write_bytes(salt)
        print(f"Generated new salt at {args.seed_file} (keep this private, delete it for a fresh mapping)")

    policy = load_property_policy(args.config)
    sample_seed = int.from_bytes(os.urandom(8), "big") if args.random_seed == "random" else int(args.random_seed)
    anonymize_graph(args.source, args.dest, salt, args.keep_code, args.force, args.n, sample_seed,
                     args.include_anonymized_assets, args.include_assets, policy)


if __name__ == "__main__":
    main()
