# HydraX remediation engine ("the brain")

For every finding the platform produces — from a scan, or from an event
POSTed to `/api/brain/resolve` — the brain returns an analyst work-up: what the
finding is, how sure we are, how urgent it is, how to fix it at each layer, and
how to verify the fix. It is **deterministic** (same input → same report),
driven entirely by a curated knowledge base, and makes **no network calls**.

| Piece | Location |
|---|---|
| Knowledge base (data) | `config/remediation_kb.yaml` |
| Loader + schema validation + append helper | `webapp/services/remediation_kb.py` |
| Resolver, scoring, triage, correlation, unresolved store | `webapp/services/remediation_service.py` |
| Live-input endpoint | `webapp/routers/brain.py` (`POST /api/brain/resolve`) |
| Surfaced in | `GET /api/scans/{id}`, per-scan HTML/JSON reports, org technical report, scanner UI |

## Guardrails

The brain is a **defensive triage and remediation system**.

- KB entries contain secure patterns, recognition guidance, and non-destructive
  verification steps only — never working exploit code, payloads, or
  step-by-step attack instructions. Detection signals refer to benign markers.
- It makes no outbound connections (tested: `/api/brain/resolve` succeeds with
  all socket connections blocked) and starts no agents.
- It runs only on findings from the operator's authorized scans and on events
  the operator POSTs about their own systems; scans themselves remain subject to
  the platform's target verification, scope, rate limiting and SSRF guard.

## Knowledge base

### Schema

`config/remediation_kb.yaml` holds `schema_version: 1` and an `entries:` list.
The file header documents every field; the loader rejects the **whole file** if
any entry is malformed, listing every problem.

| Field | Rule |
|---|---|
| `key` | `<category>.<slug>`, lowercase, unique |
| `kind` | `vulnerability` or `signal` (informational/recon observations: verify/monitor steps, no code fixes, P3/P4) |
| `aliases` | exact finding-type strings the scanners emit; matched case-insensitively; **unique across the KB** |
| `category` | scanner key from `config/settings.py` `SCANNER_CATEGORIES`, or `local_tools` |
| `cwe` | the most specific `CWE-###` for this type |
| `owasp` | `A##:2021-…` |
| `severity_guidance` | starts with `Critical`/`High`/`Medium`/`Low`/`Info` (used as the fallback severity), then when to raise/lower |
| `exploitability` | starts with `High`/`Medium`/`Low` (used by scoring), then why |
| `business_impact`, `why_it_matters`, `detection_signal`, `false_positive_check` | analyst text |
| `triage_priority` | `P1`–`P4` (curated default; the computed priority is what reports show) |
| `remediation` | `immediate_mitigation`, `short_term_fix`, `long_term_hardening` (non-empty), `code_fix_examples`, `config_examples` (stack/platform → guidance; may be `{}`) |
| `compensating_controls`, `references` (https only), `tags` | non-empty lists |
| `verification` | how to retest safely |

Coverage today: **106 entries, 114 aliases** — every finding type in the
Stage 0 inventory (`tests/test_kb_coverage.py`).

### Adding or extending an entry

1. Copy the unresolved draft (see below) or an existing entry of the same
   `kind` and fill every field. Keep secure patterns only.
2. Either append it with the helper, which validates first and rolls back on
   any failure:

   ```python
   from webapp.services import remediation_service
   remediation_service.add_kb_entry(entry_dict)   # also dismisses covered unresolved signatures
   ```

   or edit `config/remediation_kb.yaml` by hand (two-space indent under
   `entries:`; use `>-` folded blocks for any text containing `: `).
3. To make a new scanner string map to an **existing** entry, add it to that
   entry's `aliases` instead of creating a new entry (an alias may appear only
   once in the whole KB).
4. If a scanner starts emitting a new finding type, add the string to
   `STAGE0_FINDING_TYPES` in `tests/test_kb_coverage.py` as well.
5. Run `python -m pytest tests/test_remediation_kb.py tests/test_kb_coverage.py`.
   The running app caches the KB; restart it (or call
   `remediation_kb.get_kb.cache_clear()`) to pick up hand edits.

`tests/test_kb_coverage.py` runs on every test run: every Stage 0 type must
resolve **by alias**. It was gated behind `HYDRAX_KB_COMPLETE=1` while the KB
was being filled; that variable is no longer read.

## Resolver

`remediation_service.resolve(finding, context=None)` takes the normalized
finding dict the scan pipeline produces (`type`, `severity`, `confidence`, and
optionally `category`, `cwe`). Matching is case-insensitive; **the first hit
wins**:

1. **alias** — the finding's `type` equals an entry alias
2. **synonym** — after normalization and synonym canonicalization (below),
   the title's word *set* equals an alias's. Order-insensitive but exact;
   never overrides rule 1
3. **key** — the `type` (or an explicit `key`) equals a canonical entry key
4. **category** — the finding's scanner category; best entry = most keyword
   overlap with the title, ties by key order (see "No guessing")
5. **cwe** — same pick rule within entries of that CWE
6. **keyword** — title words (≥3 chars, minus stopwords, synonym-expanded)
   vs. each entry's aliases/key/tags; needs **at least 2** shared words
7. no match → a safe **generic** entry for the category, `unresolved: true`,
   and the signature is recorded in the unresolved store

`resolve()` never raises: bad input, or a KB file that fails validation,
degrades to generic guidance so scans and reports keep working.

The report records which rule matched in `resolved_by`
(`alias`/`synonym`/`key`/`category`/`cwe`/`keyword`/`generic`).

### Normalization and synonyms

Before rules 2 and 6, a title is normalized: lowercased, punctuation turned
into spaces, whitespace collapsed. Synonym phrases are then canonicalized
using `SYNONYM_GROUPS` in `remediation_service.py`:

| Canonical | Also matches |
|---|---|
| `xss` | cross site scripting |
| `sqli` | sql injection |
| `csrf` | xsrf, cross site request forgery |
| `ssrf` | server side request forgery |
| `xxe` | xml external entity / entities |
| `ssti` | server side template injection, template injection |
| `idor` | insecure direct object reference(s) |
| `cors` | cross origin resource sharing |
| `jwt` | json web token(s) |
| `mfa` | 2fa, two factor, multi factor |
| `clickjacking` | ui redress(ing) |
| `redirect` | unvalidated redirect, open redirection |
| `dos` | ddos, denial of service |
| `rce` | remote code execution |

So `Cross-Site Scripting (Stored)` matches `Stored XSS` and
`SQLi (union based)` matches `Union-based SQL Injection` by the synonym rule.
If two entries would share the same canonical identity, the rule is not
used for it. For keyword matching, a synonym anywhere adds its whole group's
words, so `sqli` and `SQL injection` overlap fully in both directions.
To add a group, append a tuple: canonical token first, phrases in normalized
(lowercase, space-separated) form.

### No guessing: zero overlap falls through

Rules 4 (category) and 5 (CWE) require **at least one shared word** with
the title whenever the finding has one. With zero overlap the pick would only
be the first entry in key order — e.g. "Exposed Grafana Dashboard" in
`sec_misconfig` used to receive CORS advice. Such findings now fall through;
if nothing else matches they get the generic report and are **recorded as
unresolved**, which feeds the learn loop. Findings with no title (category or
CWE only) still match by category/CWE.

## Scoring model

```
base          = {Critical: 90, High: 70, Medium: 45, Low: 20, Info: 5}[severity]
exploit_mod   = {High: +10, Medium: 0, Low: -10}[entry exploitability]
confidence_mod= {confirmed: +5, needs_verification: -10, unknown: -5}[finding confidence]
exposure_mod  = {internet_facing: +5, internal: -5, unknown: 0}[context exposure]

risk_score = clamp(0, 100, base + exploit_mod + confidence_mod + exposure_mod)
priority   = P1 if score >= 85, P2 if >= 60, P3 if >= 35, else P4
signals (kind: signal) are capped at P3
```

- `severity` is the finding's own severity when valid, otherwise the leading
  word of the entry's `severity_guidance`.
- Unknown values fall back to neutral (`Medium`, `Medium`, `unknown`, `unknown`).
- Web scans pass `exposure: internet_facing` (web assets are internet-facing by
  construction — the same rule as `db.ASSET_TYPE_EXPOSURE`); other scan types
  pass `unknown`.
- `rationale` names every factor, e.g.
  `Critical severity (90) · exploitability High (+10) · confidence confirmed (+5) · exposure internet_facing (+5) = 100 → P1`.

## Triage

Each report carries the entry's `false_positive_check` and a `triage_note`:

- `confidence == needs_verification` **and** the FP check is non-trivial
  (≥ 12 words) → `Likely FP — verify: <check>`
- `confirmed` → `Confirmed by the scanner's evidence.`
- otherwise → `Confidence <x>; check: <check>`

## Correlation

`correlate(findings)` resolves each finding and groups related ones into
higher-level issues (priority = highest child; risk = max child):

| Issue | Rule |
|---|---|
| HTTP Security Hardening Gap | ≥ 3 findings resolving to missing-header / server-info / technology-disclosure entries |
| Insecure Cookie Configuration | ≥ 2 cookie-flag findings (HttpOnly / Secure / SameSite / Insecure Cookie) |
| Information Exposure (review) | ≥ 2 signal findings in `info_disclosure`, `recon` or `local_tools` |

`analyze_scan()` adds **Top Priorities**: findings sorted by `risk_score`
(desc, ties keep scan order), capped at 10, followed by the correlated issues.
This is what `GET /api/scans/{id}` (`analyst_summary`) and the reports show.

## Analyst report shape

```
key, title, kind, category, cwe, owasp, severity, priority, risk_score,
rationale, confidence, triage_note, false_positive_check, what_it_is,
why_it_matters, business_impact,
remediation{immediate, short_term, long_term, code_examples{}, config_examples{}},
compensating_controls[], verification, references[], tags[],
resolved_by, unresolved, feedback{correct, incorrect, score}
```

All API/report fields were **added** alongside existing ones; nothing existing
was renamed or removed. The org technical CSV appends `priority`,
`analyst_risk_score`, `kb_key`, `remediation_immediate/short_term/long_term`
and `verification` after its original columns; its existing DB `risk_score`
column is unchanged.

## Learn loop

Deterministic throughout: no model, no network. Learning data lives in
`webapp/data/brain/` (gitignored). Nothing reaches the KB YAML until an
analyst promotes a reviewed entry.

### 1. Capture: unresolved store and auto-drafts

Every finding/event that falls back to generic is recorded in
`webapp/data/brain/unresolved.json`, one record per signature
`<category>|<type lowercased>`:

```json
{"signature": "-|kubernetes dashboard exposed publicly",
 "type": "Kubernetes dashboard exposed publicly", "category": "", "cwe": "",
 "count": 3, "first_seen": "…", "last_seen": "…",
 "nearest": [{"key": "cloud.kubernetes_api_exposure", "overlap": 1}],
 "draft_source": "cloud.kubernetes_api_exposure",
 "draft": { …full entry schema… }}
```

- `nearest` — the top-3 KB entries by keyword overlap, refreshed on every
  sighting (the KB may have grown). These are completion hints.
- `draft` — if the nearest entry is an **unambiguous leader** (strictly more
  overlap than the runner-up), the draft takes its category, CWE, OWASP,
  kind and references as guesses and copies its remediation text prefixed
  `DRAFT — review before use (copied from <key>): …`; `draft_source` names
  it. On a tie (typically one generic word shared by several entries) it
  copies nothing and leaves only the hints, since the choice would be
  arbitrary. Analyst fields stay blank either way.
- **Drafts can never be appended by accident:** `validate_entry` rejects any
  entry still tagged `draft` or still containing the `DRAFT — review before
  use` marker anywhere, on top of the blank-field checks.

Writes are atomic; a corrupt or unwritable store is logged and never breaks
`resolve()`.

### 2. Review queue

```
python scripts/brain_review.py [--sort frequency|recent|signature] [--limit N]
```

Read-only. Prints what the brain keeps seeing but cannot yet solve, with
counts, first/last seen, nearest-KB hints and whether each draft was
pre-filled. In code: `list_unresolved(sort="frequency" | "recent" |
"signature")` and `format_review_queue(limit, sort)`.

### 3. Promotion

```python
remediation_service.promote_unresolved(signature, completed_entry)
```

One step: validates the completed entry, appends it to the KB through
`add_kb_entry` (duplicate key/alias checks; the file is re-loaded after
writing and restored on any failure) and clears the signature. If the
analyst left the signature's original type string out of `aliases`, it is
added, so that finding resolves **by alias** afterwards. An unknown signature
raises `KeyError`; an invalid entry raises `KBValidationError` and changes
nothing. `add_kb_entry(entry)` (append any entry and dismiss the signatures
it covers), `dismiss_unresolved(signature)` and `clear_unresolved()` remain
available.

### 4. Feedback

```python
remediation_service.record_feedback(kb_key, correct: bool, finding_type="")
remediation_service.get_feedback(kb_key)   # {correct, incorrect, score, by_type}
```

Analysts mark a resolution right or wrong. Counts are kept per KB entry and
per finding type in `webapp/data/brain/feedback.json` — **never in the KB
YAML**. `score = correct / (correct + incorrect)`, and `None` until the first
vote, so "no feedback yet" is never shown as 0 %. Only real KB entries
accept feedback (`KeyError` otherwise). Every analyst report carries
`feedback: {correct, incorrect, score}`. Feedback informs review; it does not
change matching or scoring.

`scripts/brain_demo.py` walks through the whole loop against a temporary copy
of the KB and temporary stores.

## `POST /api/brain/resolve`

The clean input for describing a detected event from the operator's **own**
monitored systems.

- **Auth:** bearer token; roles admin / security_manager / security_analyst
  (viewers get 403 — the call writes to the unresolved store).
- **Rate limit:** 60 requests per minute per user → 429.
- **Body** (at least one of `type`, `category`, `cwe`, `signal`; else 422):

  ```json
  {"type": "Stored XSS", "category": "xss", "cwe": "CWE-79",
   "signal": "free-text description, matched like a title if no type",
   "confidence": "confirmed | needs_verification",
   "context": {"exposure": "internet_facing | internal | unknown", "asset": "shop-web-01"}}
  ```

  `cwe` must look like `CWE-123`; text fields are length-limited; invalid
  values → 422.
- **Response:** the analyst report above. Unknown input returns the generic
  report with `unresolved: true` and is recorded in the store.

## Honest scope note

The brain detects-and-solves by **matching** findings and described events
against the knowledge base. It does not watch production systems itself.
True real-time detection on a live production server additionally needs a
log/telemetry feed or agent on that server that turns observations into events
and POSTs them to `/api/brain/resolve`. That pipeline is **out of scope** here
and is the next piece to build.
