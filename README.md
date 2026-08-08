# logseq-graph-anonymizer

Anonymize a Logseq/Tine graph before sharing it (e.g. reporting a performance bug), keeping it structurally realistic so the bug still reproduces:

- Retained: page count, exact block tree per page, block ids, `((refs))`, all `key:: value` properties (default and Tine-custom), markdown formatting (bold/italic/code/links), journal filenames (dates aren't sensitive).
- Replaced: page names, tags, block prose, markdown link labels + URLs (including bare pasted URLs, not just `[label](url)`), and asset file contents.

Only `pages/` and `journals/` are treated as graph content. Logseq's own `logseq/` folder (config, `bak/` auto-backups, recycle bin) and `pages-archive/` (pages the user archived out of the graph) are skipped entirely.

Born from [tine#294](https://github.com/martinkoutecky/tine/discussions/294) — no existing tool covered this.

## Usage

```
python anonymize_graph.py anonymize <source_graph_dir> <output_dir>
python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --n 50
python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --include-anonymized-assets  # include anonymized (checkerboard) images
python anonymize_graph.py lookup "Books"
python anonymize_graph.py reverse-guess ./anon-test --guess "Movies" --wordlist candidates.txt
```

Never writes into `source_graph_dir`. Refuses a non-empty `dest` unless `--force`.

### Sampling a subset first (`--n`)

Real graphs run into the thousands of files — `--n 50` anonymizes only 50, picked to span the full file-size distribution (small/medium/large pages alike, not just the first 50 or a plain random 50) so a quick test run still exercises tiny and huge pages both. Assets referenced only by non-sampled pages are skipped too.

`--random-seed` controls which file gets picked within each size bucket. Fixed at `42` by default. Pass `--random-seed random` for anon-deterministic sample each time. This seed only affects *which pages get sampled*; the anonymization output itself is always salt-based (see below) regardless of this seed.

### Finding your own pages afterward (`lookup`)

```
python anonymize_graph.py lookup "dstack"
# dstack  ->  Fake Name
# filename: Fake Name.md
```

Re-runs the same deterministic mapping an earlier `anonymize` run used (reads its `salt.bin`) to show what a real page/tag name resolves to — handy for finding your own page in the anonymized output without reversing anything. Case-insensitive, matching how Logseq itself treats page/tag names.

### Reverse-mapping a fake name back to the real one (`reverse-guess`)

```
python anonymize_graph.py reverse-guess ./anon-test --guess "dstack" --guess "Q3 plan"
python anonymize_graph.py reverse-guess ./anon-test --wordlist candidates.txt
```

For when you spot something in your anonymized output and want to check what it really was: give it candidate real names (`--guess`, repeatable, and/or one-per-line in a `--wordlist` file) plus the `salt.bin` from the run that produced `dest`, and it tells you which candidates match a page actually in there. Under the hood this is a brute-force dictionary check — `HMAC-SHA256` has no work factor, so with the salt and a candidate list, checking is instant — which is also why `salt.bin` must never leak.

## How the anonymization works

Every replacement is `HMAC-SHA256(salt, original_string)` fed into a deterministic word generator. Same input string -> same fake output everywhere it appears (so a page linked from 40 blocks gets one consistent fake name); one changed character -> an unrelated hash -> a completely different fake string. The salt is generated once per install and cached in `salt.bin` (gitignored) so re-runs reproduce the same mapping — delete it for a fresh, unrelated one.

**Never share or commit `salt.bin`.** Anyone who has it can test guesses ("was the real page named X?") against your anonymized output.

## Asset handling

By default no `assets/` folder is written at all — images are the least anonymize-able and most identifying part of a graph, so opt-in is the safer default. Image references in page text (`![alt](assets/x.png)`) still get rewritten to fake filenames either way, whether or not the file itself gets copied.

Pass `--include-assets` to copy every asset in as a tiny fixed stub instead — no size or shape information survives, smallest possible output.

Pass `--include-anonymized-assets` to copy images in (`.png`/`.jpg`/`.jpeg` — PDFs and other types still get the plain stub) as a deterministic black/white checkerboard placeholder that approximates the real file's shape:

- **Size**: the real file's byte size is log-scaled onto a fixed set of buckets (`1, 2, 3, 4, 16, 32, 48, 64, 128, 256, ...` doubling up to a `8192`px cap) — a generic tiny-icon-to-high-res-photo range, not tuned to any particular graph.
- **Aspect ratio**: read from the real image (so a 16:9 screenshot doesn't come out square) and snapped to the same bucket list — approximate, not exact, by design.
- Output stays tiny regardless of bucket (a few KB at most): flat-color checkerboard blocks compress extremely well.

Requires Pillow + numpy: `pip install -r requirements.txt`. Not needed otherwise.

`logseq/config.edn`, `custom.css`, `custom.js` and `export.css` are always copied byte-for-byte into the output, untouched — see caveats below.

## Known assumptions / limitations

- Property *values* (`key:: value`) are left fully verbatim, except `alias::`/`tags::` (comma-separated real page names, each anonymized like any other page reference) and `title::` (a page-name override, anonymized the same way) — the rest (`id::`, `collapsed::`, `icon::`, `public::`, `tine.*` view/layout config, etc.) are structural, not user content, so this wasn't worth the extra parsing complexity. Flag it if some other property in your graph carries real content.
- Emoji in prose are swept up into the surrounding fake text like everything else, so they don't survive as themselves. `icon::` is the one place an emoji is kept verbatim on purpose — it's a single decorative character, not identifying.
- Journal file dates are passed through unchanged (not treated as identifying).
- Code (inline and fenced) is anonymized by default like any other content; pass `--keep-code` to preserve it verbatim instead.
- Asset filenames are assumed unique across the whole graph (Logseq's normal flat `assets/` folder convention) — the fake name is keyed on the filename alone, not its path, so every reference to the same asset resolves to the same fake filename regardless of how many `../` separate the page from it.
- `config.edn`/`custom.css`/`custom.js`/`export.css` are copied verbatim, not anonymized — if yours embeds real content (a custom.css selector targeting a specific page name, a config.edn default-home page, a saved query filter), it'll leak as-is. Check them by hand before sharing, or delete them from the output.

## License

[MIT](LICENSE)

---

Coded using Claude Sonnet 5.
