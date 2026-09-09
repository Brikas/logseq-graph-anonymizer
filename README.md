# logseq-graph-anonymizer

Scrub PII from a Logseq/Tine graph (Markdown format) so you can hand it to someone, typically as an attachment on a bug report. The structure survives intact, so the bug still reproduces.

- Retained
  - Page count
  - Exact block tree per page
  - Block ids
  - `((refs))`
  - All `key:: value` properties, default and Tine-custom
  - Markdown formatting: bold, italic, code, links
  - Journal filenames (dates count as non-identifying)
- Replaced
  - Page names
  - Tags
  - Block prose
  - Markdown link labels
  - URLs inside markdown links
  - Bare pasted URLs
  - Asset file contents

Only `pages/` and `journals/` are treated as graph content. Logseq's own `logseq/` folder (config, `bak/`, recycle bin) and `pages-archive/` are skipped entirely.

Written to answer [tine#294](https://github.com/martinkoutecky/tine/discussions/294), where the hunt for an existing tool came up empty.

## Example

A page with properties, nested blocks, refs, an embed, a code fence and an asset:

````markdown
title:: Q3 Migration
alias:: Postgres Cutover
tags:: Infrastructure, Acme Corp

- Kickoff with [[Priya Raman]] and the [[Acme Corp]] platform team #q3-planning
  id:: 64f1a1a0-2222-4a22-9a22-000000000001
  collapsed:: true
	- Decision: move the billing cluster off RDS before the [[Acme Corp/Renewal]] date.
	  id:: 64f1a1a0-2222-4a22-9a22-000000000002
	- Priya owns the schema diff, I own the replication lag dashboards.
	  Deadline is the last Friday of the quarter, no slip allowed.
- **Open risks** #risk
  id:: 64f1a1a0-2222-4a22-9a22-000000000003
	- *Replication lag spikes* when the nightly `ANALYZE` runs on the `invoices` table.
		- Mitigation: pin `autovacuum_analyze_scale_factor` per-table, see ((64f1a1a0-2222-4a22-9a22-000000000002))
		  tine.owner:: me
		  priority:: high
	- Connection pooler still points at the old writer — [runbook](https://wiki.acme-corp.example/runbooks/pgbouncer-failover)
	  id:: 64f1a1a0-2222-4a22-9a22-000000000004
	- Legal hasn't signed off on the new region https://acme-corp.example/legal/dpa-2026
- Migration script we settled on
  id:: 64f1a1a0-2222-4a22-9a22-000000000005
	- ```bash
	  pg_dump --schema-only billing_prod | psql -h aurora-billing.internal
	  ```
- Architecture sketch from the whiteboard ![cutover diagram](../assets/cutover-whiteboard.png)
  id:: 64f1a1a0-2222-4a22-9a22-000000000006
- {{embed ((64f1a1a0-2222-4a22-9a22-000000000003))}}
- Related: [[Postgres]], [[Priya Raman]], [[Q3 Migration/Rollback Plan]]
  id:: 64f1a1a0-2222-4a22-9a22-000000000007
  tine.status:: in-progress
````

Becomes `pages/Firnuh Gimehf.md`:

````markdown
title:: Firnuh Gimehf
alias:: Zasrikje Vunejira
tags:: Gavo Tude Vims, Nahe Jomk

- Zemasuk jih [[Bamib Dacas]] Mor mozne [[Nahe Jomk]] Dusfises fubiref #Muzluveltuf
  id:: 64f1a1a0-2222-4a22-9a22-000000000001
  collapsed:: true
	- Pojev caza fabgak kibim jabocu maceti liha put tisoze [[Nahe Jomk/Zohfovs]] Cer viteji.
	  id:: 64f1a1a0-2222-4a22-9a22-000000000002
	- Torgifki tocgo kedagub pegivac kajdinba seztej cejug cekokfo nis.
	  Golutuh rehaha pehmojig basti dumires baduc tih pogef kemitev.
- **Misidaf piz** #Ruge
  id:: 64f1a1a0-2222-4a22-9a22-000000000003
	- *Pip cefulbul kesusi kazopoku* Difgor pamono hudell `Nocurul` Cipd gofazev `Dij safl` Doha cibk.
		- Focopage coceki `Hevujd jahamhan samifagu veknamup` Vojaf zarilola ((64f1a1a0-2222-4a22-9a22-000000000002))
		  tine.owner:: me
		  priority:: high
	- Kebedene kihomme lil numidkic jure sohodci jovhunr [Kule cucrus](https://cebfabel.example/ragpuj)
	  id:: 64f1a1a0-2222-4a22-9a22-000000000004
	- Lovefo heti rohde cobarifo dagizoza vofeplag https://gipardov.example/pekmof
- Vudp rihep sujalolz luluhomo vagumc
  id:: 64f1a1a0-2222-4a22-9a22-000000000005
	- ```bash
	  Fucro molaheju galjum zacv cozovig cij bajcoje cazapvu kopd culah mosmojp
	  ```
- Zecocag sopti befik dutdifu hahd kitija ![Birecef hizhufir](../assets/pizcajohohizumumpo.png)
  id:: 64f1a1a0-2222-4a22-9a22-000000000006
- {{embed ((64f1a1a0-2222-4a22-9a22-000000000003))}}
- Voherob: [[Gurojafe]], [[Bamib Dacas]], [[Firnuh Gimehf/Henj Radi Hovc]]
  id:: 64f1a1a0-2222-4a22-9a22-000000000007
  tine.status:: in-progress
````

The tree, the block ids, the refs and the properties all came through untouched. `[[Acme Corp]]` became `[[Nahe Jomk]]` on the tags line and again in the body, because one real name maps to exactly one fake name across the whole graph. Your own run generates a different vocabulary, since the words come from your `salt.bin`.

## Usage

```
python anonymize_graph.py anonymize <source_graph_dir> <output_dir>
python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --n 50
python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --include-anonymized-assets
python anonymize_graph.py lookup "Books"
python anonymize_graph.py reverse-guess ./anon-test --guess "Movies" --wordlist candidates.txt
```

Never writes into `source_graph_dir`. Refuses a non-empty `dest` unless `--force`.

### Sampling a subset with `--n`

Real graphs run into thousands of files. `--n 50` anonymizes 50 of them, picked to span the full file-size distribution, so a quick test run exercises tiny and huge pages both. Assets referenced only by non-sampled pages get skipped too.

`--random-seed` controls which file gets picked inside each size bucket, and defaults to `42`. Pass `random` for a different sample every time. The seed affects *sampling* only, never the anonymization itself, which is always driven by the salt.

### Finding your own page with `lookup`

```
python anonymize_graph.py lookup "dstack"
# dstack  ->  Fake Name
# filename: Fake Name.md
```

Re-runs an earlier run's mapping (reads its `salt.bin`) to show what a real page/tag name resolved to. Case-insensitive, matching how Logseq treats page/tag names.

### Checking what a fake name really was with `reverse-guess`

```
python anonymize_graph.py reverse-guess ./anon-test --guess "dstack" --guess "Q3 plan"
python anonymize_graph.py reverse-guess ./anon-test --wordlist candidates.txt
```

Give it candidate real names (`--guess`, repeatable, and/or one-per-line in `--wordlist`) plus the `salt.bin` from the run that produced `dest`, and it reports which candidates match a page actually in there. Under the hood that's a brute-force dictionary check. `HMAC-SHA256` has no work factor, so with the salt and a candidate list, checking is instant. Which is also why `salt.bin` must never leak.

## How it works

Every replacement is `HMAC-SHA256(salt, original_string)` fed into a deterministic word generator. The same input string yields the same fake output everywhere it appears, so a page linked from 40 blocks gets one consistent fake name. Change a single character and the hash is unrelated, so the fake string is too. The salt is generated once per install and cached in `salt.bin` (gitignored), which is what makes re-runs reproduce the mapping. Delete it for a fresh one.

**Never share or commit `salt.bin`.** Anyone who has it can test guesses ("was the real page named X?") against your anonymized output.

## Assets

By default no `assets/` folder gets written at all. Images are the hardest part of a graph to anonymize and the most identifying, so copying them is opt-in. Image references in page text get rewritten to fake filenames either way.

`--include-assets` copies every asset in as a tiny fixed stub: no size or shape information survives, smallest possible output.

`--include-anonymized-assets` copies images in as a deterministic black/white checkerboard. It handles `.png`/`.jpg`/`.jpeg`, and every other type falls back to the plain stub. The checkerboard approximates the real file's shape:

- **Size**: the real byte size is log-scaled onto fixed buckets (`1, 2, 3, 4, 16, 32, 48, 64, 128, 256, ...` doubling up to `8192`px), a generic range covering tiny icons through high-res photos.
- **Aspect ratio**: read from the real image, so a 16:9 screenshot stays 16:9, then snapped to the same buckets. It lands near the original without matching it.
- Output stays a few KB at most: flat-colour checkerboards compress extremely well.

Requires Pillow + numpy: `pip install -r requirements.txt`.

## Known assumptions / limitations

- Property *values* are left verbatim, with two exceptions: `alias::`/`tags::`/`title::` (the whole value is a real page name, anonymized like any other reference), and any `[[Page]]` / `#tag` / `((blockref))` embedded inside any other property's value. Numbers, booleans, enum strings and plain text stay untouched. Flag it if some property in your graph carries real content another way.
- Journal file dates pass through unchanged, counted as non-identifying.
- Code (inline and fenced) is anonymized by default. `--keep-code` preserves it verbatim.
- Asset filenames are assumed unique across the graph, following Logseq's flat `assets/` convention. The fake name is keyed on the filename alone, so every reference to one asset resolves to the same fake filename however many `../` separate the page from it.
- `logseq/config.edn`, `custom.css`, `custom.js` and `export.css` are copied byte-for-byte, untouched. If yours embeds real content (a CSS selector targeting a page name, a `config.edn` default-home page, a saved query filter) it leaks as-is. Check them by hand, or delete them from the output.
- Markdown graphs only: `*.md` files are processed, so Org-mode graphs are out of scope.

## License

[MIT](LICENSE)

---

Coded using Claude Sonnet 5.
