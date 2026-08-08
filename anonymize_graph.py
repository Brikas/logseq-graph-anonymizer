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
from pathlib import Path

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


def fake_name(salt: bytes, text: str) -> str:
    """For page names / tags / link labels: 1-3 human-readable fake words,
    length roughly matched to the original so page-size-in-kb stays close.
    Hashed case-insensitively — Logseq treats #Project and [[project]] as the
    same page, so they must map to the same fake name."""
    rng = rng_for(salt, text.lower())
    n_words = 1 if len(text) < 8 else rng.randint(1, 3)
    target = max(len(text), 3)
    per_word = max(target // n_words, 3)
    words = [fake_syllables(rng, per_word).capitalize() for _ in range(n_words)]
    return " ".join(words)


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
        parts[-1], ext = parts[-1].rsplit(".", 1)
        ext = "." + ext
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

# Most Logseq/Tine built-in properties (id::, collapsed::, logseq.order-list-type::,
# any tine.*:: view/layout config) are structural, not user content, so they're
# kept verbatim below. A few carry real page names/titles and must be anonymized
# like any other page reference — comma-separated lists (alias, tags point to
# other real pages) vs. a single override string (title stands in for the page
# name itself). Source: tine's PAGE_PROP_SPECS in src/editor/properties.ts.
PAGE_REF_LIST_PROPERTIES = {"alias", "tags"}
PAGE_REF_TEXT_PROPERTIES = {"title"}


def anonymize_page_ref_value(salt: bytes, value: str) -> str:
    """Same as anonymize_page_ref, except a value that's itself a block ref
    (tags::/alias:: can point at a block, not just a page) is kept verbatim —
    otherwise the id gets hashed as if it were a page name and destroyed."""
    if BLOCKREF_VALUE_RE.match(value):
        return value
    return anonymize_page_ref(salt, value)


def anonymize_page_body(salt: bytes, text: str, keep_code: bool) -> str:
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
        prop_m = PROPERTY_RE.match(line)
        if prop_m:
            indent, key, value = prop_m.groups()
            key_lower = key.lower()
            if key_lower in PAGE_REF_LIST_PROPERTIES:
                names = [anonymize_page_ref_value(salt, v.strip()) for v in value.split(",") if v.strip()]
                out_lines.append(f"{indent}{key}:: {', '.join(names)}")
            elif key_lower in PAGE_REF_TEXT_PROPERTIES and value.strip():
                out_lines.append(f"{indent}{key}:: {anonymize_page_ref_value(salt, value.strip())}")
            else:
                out_lines.append(line)  # structural properties (default + Tine-custom) retained verbatim, incl. id::
            continue
        bullet_m = BULLET_RE.match(line)
        if bullet_m:
            indent, dash, rest = bullet_m.groups()
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
) -> None:
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
            anonymize_page_body(salt, text, keep_code), encoding="utf-8"
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

    sample_seed = int.from_bytes(os.urandom(8), "big") if args.random_seed == "random" else int(args.random_seed)
    anonymize_graph(args.source, args.dest, salt, args.keep_code, args.force, args.n, sample_seed,
                     args.include_anonymized_assets, args.include_assets)


if __name__ == "__main__":
    main()
