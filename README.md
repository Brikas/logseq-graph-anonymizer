# logseq-graph-anonymizer

Scrub PII from a Logseq/Tine graph (Markdown format) so you can hand it to someone, typically as an attachment on a bug report. The structure survives intact, so the bug still reproduces.

- Retained
  - Page count
  - Exact block tree per page
  - Block ids
  - `((refs))`
  - Logseq and Tine property keys, with their keyword values, as listed in [config.default.yaml](config.default.yaml)
  - Bare booleans, numbers, uuids and dates under any key
  - Markdown formatting: bold, italic, code, links
  - Journal filenames (dates count as non-identifying)
- Replaced
  - Page names
  - Tags
  - Block prose
  - Every other property key (`src::`, `companies::`), consistently across the graph
  - Every other property value, anonymized like block prose
  - Tine table config (`tine.fields::`, formulas, filters) rewritten to the fake keys and values, so tables still line up
  - Page names in `config.edn` (`:favorites`, `:default-home`), and its comments are dropped
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
		  owner:: [[Priya Raman]]
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
  status:: in-progress
````

Becomes `pages/Vucati Zekafu.md`:

````markdown
title:: Vucati Zekafu
alias:: Lulilekidefuvobu
tags:: Muncisavejapaj, Heb Zos Jiv

- Coz sezesi camnodu [[Bebto Bafes]] Nifhaclo [[Heb Zos Jiv]] Gohik zazinijd #Nal Pel Lad
  id:: 64f1a1a0-2222-4a22-9a22-000000000001
  collapsed:: true
	- Cebatfo goj hohav pamopajl vipepsu muzinac hatotib kobammo [[Heb Zos Jiv/Jafimel]] Kivmenoj.
	  id:: 64f1a1a0-2222-4a22-9a22-000000000002
	- Bit dejo cite kared ruz gopuf kifhiln fodezsom bocacil nacketi kidrer.
	  Famaco dare bedhahu masjimfi lobka gikudal cine ruphural kub.
- **Lujuheks mozjusz** #Hadi
  id:: 64f1a1a0-2222-4a22-9a22-000000000003
	- *Zav giducece mishetad* Muhita vol vanofama `Kolbedic` Takepakv hacvi `Jor micevumu` Jitamfe.
		- Jarvus rasedij `Humetelr parethi havab hilenfis` Sujrife kela tatovobe ((64f1a1a0-2222-4a22-9a22-000000000002))
		  razbo:: [[Bebto Bafes]]
		  priority:: high
	- Sag femacl fathuz pejozu sop faz kufac cebocki gedsuj [Gejaz girfi](https://jozosoci.example/civasb)
	  id:: 64f1a1a0-2222-4a22-9a22-000000000004
	- Fohre rocudm dub jekce repehobz panap rurensiz https://hecajekl.example/tivnab
- Fedbeh pumnuz zeluhol vica rufjac
  id:: 64f1a1a0-2222-4a22-9a22-000000000005
	- ```bash
	  Vuc zuf dejov sej binos supre kif besisa dush kezbaj sajukje ditf kosen
	  ```
- Sicala gikogali hugafa renbidu kodapd vit ![Felalami zov kib](../assets/hidutahvifoneskeho.png)
  id:: 64f1a1a0-2222-4a22-9a22-000000000006
- {{embed ((64f1a1a0-2222-4a22-9a22-000000000003))}}
- Zog falizfup: [[Nef Nil Jac]], [[Bebto Bafes]], [[Vucati Zekafu/Gikefduguvuci]]
  id:: 64f1a1a0-2222-4a22-9a22-000000000007
  laziro:: Volakuv pokrepi
````

The tree, the block ids, the refs and the keyword properties (`collapsed::`, `priority:: high`) all came through untouched. The custom keys `owner::` and `status::` became `razbo::` and `laziro::`, and their values got faked. `[[Acme Corp]]` became `[[Heb Zos Jiv]]` on the tags line and again in the body, because one real name maps to exactly one fake name across the whole graph. `[[Priya Raman]]` became `[[Bebto Bafes]]` in the body and inside the `owner::` value alike. Your own run generates a different vocabulary, since the words come from your `salt.bin`.

## Usage

```
pip install -r requirements.txt
python anonymize_graph.py anonymize <source_graph_dir> <output_dir>
python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --n 50
python anonymize_graph.py anonymize ~/graphs/my-notes ./anon-test --config my-props.yaml
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

Uses Pillow + numpy from `requirements.txt`.

## Known assumptions / limitations

- Property keys and values count as content unless [config.default.yaml](config.default.yaml) keeps them. To keep more (a `status::` key with `todo, doing, done` values), add a `config.local.yaml` or pass `--config`. The file's header explains the layers and value rules.
- Two real names never share a fake name within a run. When a short name's fake is already taken, it gets re-rolled, so `lookup` can show a different fake than the run used for that name.
- Journal file dates pass through unchanged, counted as non-identifying.
- Code (inline and fenced) is anonymized by default. `--keep-code` preserves it verbatim.
- Asset filenames are assumed unique across the graph, following Logseq's flat `assets/` convention. The fake name is keyed on the filename alone, so every reference to one asset resolves to the same fake filename however many `../` separate the page from it.
- `custom.css`, `custom.js` and `export.css` are copied byte-for-byte. `config.edn` gets its page names faked and its comments dropped, while the rest (macros, default queries) is copied as-is. If yours embeds real content there (a CSS selector targeting a page name, a saved query filter), it leaks. Check them by hand, or delete them from the output.
- `{{query}}` macros in block text get their arguments faked like prose, so queries in the output return nothing.
- Markdown graphs only: `*.md` files are processed, so Org-mode graphs are out of scope.

## License

[MIT](LICENSE)

---

Coded using Claude Sonnet 5.
