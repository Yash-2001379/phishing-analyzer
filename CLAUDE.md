# CLAUDE.md, Phishing Email Analyzer

Read this whole file before doing anything. It explains what this project is, who it's for,
how the code works, what has already been decided, and the rules you must follow.

Last checked against the code: 2026-10-27.

---

## 1. What this project is

A command line tool written in Python that reads email files (`.eml`), looks for signs of
phishing, gives each email a risk score, and produces a clear report plus an IOC file.

It is a **portfolio project** for SOC (Security Operations Center) analyst internship
applications. That shapes everything:

- The owner must be able to **explain every line in a job interview**. Clever code they
  can't explain is worse than simple code they can.
- Measured results matter (how many phishing emails caught, how many false positives),
  because they become resume bullet points.
- The README and screenshots will be looked at by recruiters, so output should look clean
  and professional.

---

## 2. Who you are working with

- A university CS student. Comfortable with Python, basic C. Learning security tooling.
- Holds CompTIA Security+. Knows the theory (SPF, DKIM, DMARC, IOCs, phishing tactics),
  is still building hands-on experience.
- Uses **Windows**, **PowerShell** in VS Code's terminal, **GitHub Desktop** for commits.
- Types fast and informally with typos. Read for meaning, don't correct spelling.

### How to communicate

- **Plain, simple English.** Short sentences. No jargon without a one-line explanation.
- Use real-world analogies for abstract ideas (example: "the repo is the address on the
  envelope, your login is the key to the mailbox").
- Use tables when comparing options.
- Give **steps in batches** (all the steps for one task at once, numbered), not one tiny
  step per message.
- When something is uncertain or untested, **say so honestly**. Don't oversell results.
- Push back if the owner asks for something that's a bad idea. Explain why, offer a
  better option. They respond well to honest assessments.

### How to make changes

1. **Explain first.** Before editing, say in 1 to 3 plain sentences what you'll change and why.
2. **Small changes.** One logical change at a time. Don't rewrite files that don't need it.
3. **Ask before** installing anything, deleting files, renaming files, or touching git.
4. **Test after.** Run the tool on `samples/` after every change to scoring or parsing,
   and report the before vs after results.
5. **Teach.** After a change, give a short "what this does" so the owner can explain it.
   Occasionally offer a quick self-test question.

---

## 3. Hard rules (never break these)

### Security rules

- **Zero third-party dependencies.** Python standard library only. Reason: supply chain
  risk. Every pip package is a stranger's code running on the user's machine. This is a
  deliberate design decision and a talking point for interviews. Do not add `requests`,
  `rich`, `colorama`, `python-dotenv`, or anything else. Use `urllib.request`, `json`,
  `os`, `re`, `email`, `html`, `hashlib`, etc.
  - Exception later: the ML phase may need `scikit-learn` and `pandas`. **Ask first.**
- **Nothing opens or pops up on its own.** No `webbrowser.open`, no launching apps, no
  auto-opening files. A security tool that pops windows is suspicious behaviour.
- **No HTML reports.** Rendering attacker-written content as a web page is a risk. This
  was considered and rejected.
- **Never render or trust email content.** Everything from an email (subject, sender name,
  body, URLs, filenames) is attacker-controlled. Always:
  - Strip control characters before printing to the terminal (`clean()` in report.py).
    Attackers can hide terminal escape codes in subjects.
  - Escape it before writing Markdown (`md()` in report.py): HTML-escape, then escape
    markdown symbols `| \` * _ [ ]`.
  - **Defang** URLs in saved reports: `https://` becomes `hxxps://`, `www.` becomes
    `www[.]`. In the IOC CSV, `.` becomes `[.]` and `@` becomes `[@]`. This is standard
    SOC practice so nothing is clickable.
  - Protect CSV cells from formula injection (`csv_safe()` in report.py).
- **Never click, fetch, or open URLs found in emails.** Only send domains to VirusTotal's
  API for lookup (never visit them directly).
- **Never execute or open attachments.** Only hash them (SHA256).

### Privacy rules

- `samples/` contains the owner's **personal Gmail emails** and real phishing samples.
  Never commit it, never copy its contents into code, docs, tests, or commit messages.
  That includes subjects and sender addresses from those emails.
- `reports/` contains data from those emails. Never commit it.
- `.env` holds the VirusTotal API key. Never commit it, never print the key.
- `vt_cache.json` holds lookup results. Never commit it.
- This repo is **public**. Don't put personal info (real names, email addresses, student
  details) anywhere in committed files. Use made-up examples like `support@paypal-help.com`.

### Git rules

- Don't run git commands unless asked. The owner commits and pushes through GitHub Desktop.
- Never push. The owner pushes from GitHub Desktop.
- Before suggesting a commit, check `git status` and confirm none of these appear:
  `samples/`, `reports/`, `.env`, `vt_cache.json`, `__pycache__/`, `.claude/settings.local.json`.
- Suggest short, clear commit messages like `add brand lookalike detection`.
- **No Claude attribution in commits or PRs.** No `Co-Authored-By: Claude` or
  `Claude-Session:` lines. This is turned off in `.claude/settings.local.json` with
  `"attribution": {"commit": "", "pr": "", "sessionUrl": false}`. Past commits were
  cleaned on 2026-10-27, and the old history is kept on the `backup-before-cleanup` branch.

### Code style rules

- Plain Python, easy to read. Prefer simple loops over clever one-liners.
- Every function gets a one-line docstring in plain English.
- Short comments that explain **why**, not what.
- Keep functions small and named clearly.
- Settings that might be tweaked (word lists, domains, thresholds) live as constants at the
  top of the file, not buried in functions.
- When giving the owner a file to replace, always give the **whole updated file**, never
  just a snippet to paste in.

---

## 4. Project layout

```
phishing-analyzer/
├── CLAUDE.md                     this file
├── README.md                     public project description (still a 2-line placeholder)
├── .gitignore                    Python template + project lines at the bottom
├── .env                          VT_API_KEY=... (gitignored)
├── .claude/settings.local.json   turns off Claude commit attribution (excluded via .git/info/exclude)
├── vt_cache.json                 saved VirusTotal answers (gitignored)
├── src/
│   ├── parser.py      reads .eml files, extracts headers, URLs, attachments
│   ├── report.py      scoring, terminal report, markdown report, IOC CSV (main entry point)
│   ├── vt_client.py   VirusTotal lookups, standard library only, connected via --vt
│   └── measure.py     detection rate and false positive rate on labeled folders
├── tests/
│   ├── test_brand_check.py   unittest tests for rule 5 (standard library only)
│   └── emails/               made-up .eml files used by the tests (never real samples)
├── samples/           test emails (gitignored)
│   ├── phishing/      known phishing
│   └── legit/         known legit
└── reports/           generated report_<timestamp>.md and iocs_<timestamp>.csv (gitignored)
```

Run the tests with `python -m unittest discover tests -v`. Test emails use the reserved
`.example` domain ending so they can never point at a real site.

### .gitignore must end with

```
# Phishing analyzer
vt_cache.json
samples/
reports/
```
(`.env` and `__pycache__/` are already covered by the Python template above it.)

---

## 5. How to run

From the project root in PowerShell:

```
python src/report.py samples                  # scan every email in the folder and subfolders
python src/report.py samples/legit/file.eml   # scan one email
python src/report.py samples --vt             # also check VirusTotal
python src/measure.py samples/phishing samples/legit         # numbers only
python src/measure.py samples/phishing samples/legit --vt    # numbers with VirusTotal
```

- Folder mode walks subfolders and finds emails **by content, not filename**. It reads the
  first 4KB and looks for `from:`, `received:`, `subject:`, or `return-path:`. Any name,
  any extension works. Hidden files and folders (starting with `.`) are skipped.
- `.msg` (Outlook format) is skipped with a message telling the user to save as `.eml`.
- Non-email files are skipped with a reason.
- A broken email is skipped, the rest of the scan continues. Never let one bad file crash
  the whole run.
- If the scanned folder contains both `phishing/` and `legit/`, `report.py` also prints the
  detection results from `measure.py` at the end.
- Output: colored cards in the terminal, a summary table, a saved
  `reports/report_<timestamp>.md`, and `reports/iocs_<timestamp>.csv` if any email is
  MEDIUM or HIGH. User opens the report in VS Code with `Ctrl+Shift+V`.
- `--vt` needs `VT_API_KEY=...` in `.env` (or as an environment variable).

---

## 6. How the code works

### parser.py

| Function | What it does |
|---|---|
| `load_email(path)` | Opens the file in binary and parses it with `email.parser.BytesParser(policy=policy.default)` |
| `get_headers(msg)` | Returns dict: subject, from_name, from_addr, reply_to, return_path (addresses lowercased), auth_results (the `Authentication-Results` header), received_hops |
| `get_body_and_urls(msg)` | Joins text/plain and text/html parts into one string, finds URLs with `URL_REGEX`, returns (text, sorted unique urls) |
| `get_attachments(msg)` | For each attachment: filename, content_type, size_bytes, sha256 |
| `domain_of(addr)` | `user@x.com` becomes `x.com`, empty string if there's no `@` |
| `red_flags()`, `analyze()` | **Old Phase 1 logic.** Superseded by report.py scoring. Kept for reference. Don't build on them. |

Running `python src/parser.py file.eml` prints raw JSON. That's a debugging view only.
None of the parser functions have docstrings yet.

### report.py

**Constants at the top** (tweak these, not the functions)

| Constant | Used for |
|---|---|
| `JUNK_DOMAINS`, `IMAGE_EXTS` | Links ignored when summarizing (w3.org boilerplate, images) |
| `RISKY_EXTS` | Dangerous attachment endings (.exe, .js, .iso, .zip, .html, .docm, ...) |
| `DECOY_EXTS`, `RTLO_CHAR` | Disguised attachment checks (invoice.pdf.exe, right-to-left override) |
| `URL_SHORTENERS`, `FREE_HOSTING`, `RISKY_TLDS` | Risky link groups |
| `URGENT_WORDS`, `LURE_WORDS` | Pressure and bait language (English only) |
| `BRANDS` | Brand name to its real sending domains. Includes Canadian banks, couriers, and crypto wallets |
| `FREE_TENANT_DOMAINS`, `FREE_WEBMAIL` | onmicrosoft.com, and free inboxes like gmail.com |
| `LOOKALIKE_SWAPS`, `LOOKALIKE_MIN_LEN` | Character swaps (0 to o, rn to m, ...) and minimum brand length (5) for lookalike checks |
| `VT_MIN_VENDORS` (2), `VT_STRONG_VENDORS` (5), `VT_MAX_LINK_DOMAINS` (3), `VT_SKIP_DOMAINS` | VirusTotal thresholds and quota savers |
| `ATTACK_NAMES`, `VT_LABEL_TAGS` | MITRE ATT&CK technique names, and which technique a VT hit maps to |
| `TWO_PART_TLDS` | Endings like co.uk for `root_domain` |

**Helpers**

| Function | What it does |
|---|---|
| `root_domain(domain)` | `accounts.brain.fm` becomes `brain.fm`. Handles two-part endings like `co.uk` using `TWO_PART_TLDS`. Simple approach, not a full public suffix list. |
| `lookalike_brand(root)` | Undoes swaps (`1` as both `l` and `i`, plus `LOOKALIKE_SWAPS`), removes hyphens, and returns the brand if the name contains a brand of 5+ letters but isn't that brand's real domain. `paypa1.com` and `paypal-help.com` both return `paypal` |
| `auth_status(header)` | Pulls `spf=`, `dkim=`, `dmarc=` values out of Authentication-Results. Returns the value found (`pass`, `fail`, `softfail`, `none`, ...) or `missing` |
| `summarize_links(urls)` | Collapses URLs into unique hostnames with counts. Ignores `JUNK_DOMAINS` and image files. Returns (domains dict, raw IP urls) |
| `host_matches(host, suffixes)` | True if host is one of the domains or a subdomain of one |
| `risky_link_groups(link_domains)` | Sorts hosts into shorteners, free hosting, and cheap TLD sites (cheap ones listed once per root domain) |
| `disguised_attachment(filename)` | Returns (why, ATT&CK tag) for an RTLO character or a decoy-then-risky double extension, else None |

**Scoring**

| Function | What it does |
|---|---|
| `verdict_for(total)` | `>= 6` HIGH, `>= 3` MEDIUM, otherwise LOW |
| `score_email(path)` | Runs every rule below. Returns dict: file, path, headers, auth, from_root, link_domains, total_urls, attachments, findings (list of (points, reason, ATT&CK ID)), score, verdict, authenticated, scam_domain |

"Authenticated" means DMARC pass, or SPF pass and DKIM pass together.

| # | Rule | Points | ATT&CK |
|---|---|---|---|
| 1 | No sender address | +3 | T1672 |
| 1 | Sender address has no `@` domain | +2 | T1672 |
| 1 | Sender domain has no dot (fake, like `@pot`) | +2 | T1672 |
| 1 | Sent from `onmicrosoft.com` | +2 | T1585.002 |
| 2 | SPF fail or softfail | +2 | T1672 |
| 2 | DKIM fail | +2 | T1672 |
| 2 | DMARC fail | +3 | T1672 |
| 2 | DKIM none/missing AND DMARC not pass | +2 | T1672 |
| 3 | Reply-To root differs from From, and is a free webmail inbox | +3 | T1672 |
| 3 | Reply-To root differs, different company domain, email authenticated | +1 | T1672 |
| 3 | Reply-To root differs, different company domain, not authenticated | +3 | T1672 |
| 4 | Return-Path root differs from From, **only if DMARC didn't pass** | +1 | T1672 |
| 5 | Sender name contains a brand, domain isn't that brand's | +3 | T1656 |
| 5 | Subject contains a brand, domain isn't theirs, DMARC not pass | +2 | T1656 |
| 5b | Sender domain is a lookalike of a brand (`lookalike_brand`) | +3 | T1583.001 |
| 6 | Link to a raw IP address | +3 per unique IP | T1566.002 |
| 6b | Any link shortener | +2 once | T1566.002 |
| 6b | Any link on free hosting | +2 once | T1583.006 |
| 6b | Any link with a risky TLD | +1 once | T1583.001 |
| 7 | Any `URGENT_WORDS` in subject or body | +1 once | T1566 |
| 7 | Any `LURE_WORDS` in subject or body | +1 once | T1566 |
| 8 | Attachment with an extension in `RISKY_EXTS` | +3 each | T1566.001 |
| 8 | Disguised attachment (RTLO or double extension) | +3 each | T1036.002 / T1036.007 |
| VT | VirusTotal: 2+ vendors flag sender, reply-to, link domain, or attachment | +3 each | from `VT_LABEL_TAGS` |
| VT | Same, but email passes DMARC and fewer than 5 vendors flag it | +1 each | from `VT_LABEL_TAGS` |

Notes on the rules:
- Rule 5 checks the sender name against every brand first. Only if no name matches does
  it check the subject. One brand finding per email at most.
- A file like `invoice.pdf.exe` gets both rule 8 findings (+6).
- `scam_domain` is True when the sender domain is a lookalike or uses a risky TLD. It
  decides whether the sender domain is safe to block and goes into the IOC file.

**Recommended actions**

| Function | What it does |
|---|---|
| `spoofed(auth)` | True only if a check actually failed. `none`/`missing` means no checks are set up, which is different |
| `recommended_actions(r)` | LOW gets nothing. MEDIUM gets "hold for review, don't click". HIGH gets a block decision (fake address, scam domain, free webmail address, hacked authenticated account, spoofed real domain, or unverified domain) plus link blocking, mailbox search, and what to do if someone clicked, opened, or replied |

**VirusTotal in report.py (only with `--vt`)**

| Function | What it does |
|---|---|
| `vt_targets(r)` | Picks what to look up: sender domain, reply-to domain, top 3 busiest link domains (skipping `VT_SKIP_DOMAINS`), attachment hashes. No duplicates |
| `add_vt_findings(r, cache, api_key)` | Looks them up, adds findings using the VT rows above, records counts in `r["vt"]`, recalculates score and verdict |
| `techniques(r)` | Sorted unique ATT&CK IDs for one email |
| `vt_summary(vt)` | One line like `4 checked, 1 flagged, 1 unknown to VirusTotal` |

**Output**

| Function | What it does |
|---|---|
| `c(text, code)` | Wraps text in ANSI color codes. Off when output isn't a terminal or `NO_COLOR` is set. `os.system("")` enables colors on older Windows terminals |
| `clean(text, limit)` | Removes non-printable characters, optionally truncates with `…` |
| `label(name)` | Grey field label padded to 12 characters (pad first, then color) |
| `auth_badge(name, status)` | ✓ green for pass, ✗ red for fail/softfail, ? amber otherwise |
| `print_card(r)` | One boxed card per email: verdict, score, subject, from, reply-to, auth badges, VT line, reasons with ATT&CK IDs, next steps, top 5 link domains, attachments |
| `print_summary(...)` | Counts per verdict, sorted list, skipped files, paths to saved report and IOC file |
| `md(text)` | Safe markdown: clean, HTML escape (`quote=False`), escape markdown symbols, defang links |
| `build_markdown(results, skipped)` | Full report: summary table, then per email the details, reasons, MITRE ATT&CK list, recommended actions, link destinations, attachments, with 🔴🟠🟢 icons |
| `save_markdown(text, stamp)` | Writes `reports/report_<stamp>.md` |

**IOC export**

| Function | What it does |
|---|---|
| `defang(value)` | `evil.com` becomes `evil[.]com`, `@` becomes `[@]` |
| `csv_safe(value)` | Cleans text and puts `'` in front of anything starting with `= + - @` so Excel won't run it as a formula |
| `collect_iocs(results)` | From MEDIUM and HIGH emails only: sender address, sender domain (only if `scam_domain`), reply-to address if a different domain, link domains and IPs, attachment hashes. Includes VT vendor counts when available |
| `save_iocs(rows, stamp)` | Writes `reports/iocs_<stamp>.csv` with columns type, value_defanged, source_email, verdict, vt_malicious_vendors, note. Skips if empty |

**Main**

| Function | What it does |
|---|---|
| `looks_like_email(path)`, `find_emails(folder)` | Content-based detection described in section 5 |
| `main()` | Sets stdout to UTF-8 (needed on Windows for ✓ and emoji), parses `--vt`, scores, runs VT, prints, saves report and IOCs, shows measure results if `phishing/` and `legit/` exist |
| `in_folder(path, folder)` | True if a path is inside a folder |

Docstrings are still missing on `score_email`, `c`, `auth_badge`, `print_card`,
`print_summary`, `md`, and `build_markdown`.

### vt_client.py (connected, standard library only)

| Function | What it does |
|---|---|
| `VTError` | Lookup failed. `fatal=True` means stop all lookups (bad key or quota used up) |
| `load_api_key()` | Reads `VT_API_KEY` from the environment, or from `.env` by hand (no python-dotenv). Uses `utf-8-sig` to skip the Windows BOM |
| `load_cache()`, `save_cache(cache)` | Read and write `vt_cache.json`. A broken cache just means lookups happen again |
| `is_cached(cache, endpoint)` | True if a lookup won't use quota |
| `vt_get(endpoint, cache, api_key)` | One lookup with `urllib.request`. Cache first, then waits `RATE_DELAY` (15s) between live calls. Returns found with malicious/suspicious/harmless/undetected counts, or not_found on 404. 401/403 and 429 are fatal |
| `domain_endpoint(domain)`, `file_endpoint(sha256)` | Build `domains/<d>` or `files/<hash>` paths. Values are checked against strict regexes first, because email content is attacker-controlled. Return None if they don't match |

- Only domains and file hashes are looked up. Full URLs are not.
- Nothing is uploaded or visited. We only ask VT what it already knows.
- **Free tier limit is 4 requests per minute and 500 per day.** Respect this.
- Debug: `python src/vt_client.py example.com` or `python src/vt_client.py <sha256>`.

### measure.py

| Function | What it does |
|---|---|
| `file_hash(path)` | SHA256 of a file, to spot the same email saved twice |
| `score_folder(folder, cache, api_key)` | Scores every unique email in a folder (with VT if a key is given). Returns (results, duplicates, failed) |
| `pct(part, whole)` | Percent text, `n/a` when whole is 0 |
| `main()` | Takes a phishing folder and a legit folder, optional `--vt` |
| `print_results(phish, legit, use_vt)` | Detection rate, false positive rate, precision, verdict counts, and lists of misses and false alarms |

"Flagged" means MEDIUM or HIGH.

---

## 7. Decisions already made (don't reopen without a good reason)

| Decision | Why |
|---|---|
| Zero dependencies | Supply chain risk, and it's an interview talking point |
| Terminal output + markdown file + IOC CSV | Looks professional, nothing auto-opens, no attacker content rendered as HTML, CSV imports into any SIEM |
| HTML report rejected | Pop-ups are bad behaviour for a security tool, rendering attacker content is risky |
| `rich` library rejected | Dependency |
| Detect emails by content, not filename | Real users won't rename files, tool must handle messy input |
| Compare root domains, not full domains | Subdomains of one company were flagged as mismatches |
| Return-Path only counts without DMARC pass | Newsletters legitimately bounce through mail services |
| Subject brand check only without DMARC pass | Legit newsletters mention other brands |
| Reply-To to another company counts only +1 when authenticated | Big companies use sister domains for replies |
| Lookalike check only for brands of 5+ letters | Short names like "bmo" hide inside normal words |
| VT needs 2+ vendors, and under 5 vendors on a DMARC-pass email is only +1 | One vendor alone is often a false alarm. A game company's own shortener got 2 flags |
| VT checks at most 3 link domains per email, never full URLs | Saves the 500/day quota |
| Sender domain only goes in IOCs when the scammer owns it | Blocking a spoofed real domain would cut off a real company |
| "Spoofed" means a check failed, not just missing | Missing checks prove nothing either way |
| Every finding has a MITRE ATT&CK ID | Common language SOC teams use |
| Defang links in reports and IOCs | Standard SOC practice |
| Public test data from `rf-peixoto/phishing_pot` | Owner's Gmail has little spam, and these are real phishing samples |
| No Claude attribution lines in commits | Owner's choice, set in `.claude/settings.local.json` |

---

## 8. Current results

Measured on 2026-10-27 with `python src/measure.py samples/phishing samples/legit`.

| | Rules only | With `--vt` |
|---|---|---|
| Phishing emails tested | 55 | 55 |
| Legit emails tested | 22 | 22 |
| Detection rate (MEDIUM or HIGH) | 42/55, 76.4% | 44/55, 80.0% |
| False positive rate | 0/22, 0.0% | 0/22, 0.0% |
| Precision | 100% | 100% |
| Phishing HIGH / MEDIUM / LOW | 21 / 21 / 13 | 23 / 21 / 11 |

**Be honest about this:**
- 22 legit emails is a small set. 0 false positives on 22 does not prove the real false
  positive rate is 0.
- Missed phishing (rules only) scored 0 to 2. Most are non-English (German, Portuguese,
  Persian) or marketing-spam style, where the English word lists don't help and the
  headers look normal.
- The `--vt` numbers depend on what VirusTotal knew on the day. They can change.
- Never quote sample subjects or addresses in committed files.

History worth keeping for the README:
- First version caught 3/5 as MEDIUM, 0 as HIGH, and gave the legit newsletter 2 false
  positive flags (subdomain mismatch).
- Fixed by comparing root domains, adding sender, authentication, brand, and bait rules.
  That reached 5/5 on the first small set.
- Then added lookalike domains, risky links, disguised attachments, VirusTotal, ATT&CK tags,
  recommended actions, IOC export, and measure.py, and grew the test set to 55 + 22.

---

## 9. Known gaps

1. **Small legit set.** 22 emails. Need about 50 for a believable false positive rate.
2. **Word lists are English only.** This is the main cause of missed phishing.
3. **Link text vs real destination** isn't checked (text says paypal.com, link goes
   elsewhere). Good future rule.
4. **Lookalike check only looks at the sender domain**, not link domains or Reply-To. It
   also misses brands under 5 letters and swaps not in `LOOKALIKE_SWAPS`.
5. **`root_domain` is simple.** It doesn't know every two-part ending. Fine for now,
   mention it as a limitation.
6. **Few tests.** `tests/` only covers rule 5 so far. Add made-up emails for the other
   rules. Never use real samples in tests.
7. **Missing docstrings** in parser.py and some report.py functions (listed in section 6).
8. **README is a placeholder.**

---

## 10. Current status

**Done**
- Parsing, scoring with 8 rule groups, verdicts
- Lookalike domain detection (digit and letter swaps, hyphenated brand names)
- Risky link groups (shorteners, free hosting, cheap TLDs) and disguised attachments
- VirusTotal with zero dependencies, cache, rate limit, quota savers, `--vt` flag
- MITRE ATT&CK tag on every finding
- Recommended next steps for MEDIUM and HIGH
- Defanged IOC CSV with CSV injection protection
- `measure.py` with detection rate, false positive rate, precision, duplicate skipping
- Measured on 55 phishing + 22 legit (section 8)
- Claude attribution removed from history and turned off for future commits
- Rule 5 fixed so a subject brand can't hide a faked sender name, with tests

**Not done**
- 50 legit emails (have 22)
- Non-English or language-neutral detection
- Link text vs destination rule
- Tests for rules other than rule 5
- README with screenshot, scoring explanation, results, limitations
- ML classifier

**Exact next step**
Owner adds about 28 more legit emails to `samples/legit/` (different kinds: banks,
school, shopping receipts, small senders, personal mail). Then run
`python src/measure.py samples/phishing samples/legit` and `--vt`. Any legit email at
MEDIUM or HIGH is a false positive. Explain the cause, propose the smallest fix, re-run
both folders, and update section 8.

---

## 11. Roadmap

Work in this order unless the owner says otherwise.

1. **Grow the legit set to ~50** (the next step above).
2. **Look at the 13 rules-only misses.** Find a language-neutral signal before adding
   word lists in other languages. Don't overfit to these exact samples.
3. **Link text vs destination rule** (gap 3).
4. **More tests** in `tests/` with made-up emails for each remaining rule.
5. **README.** What it does, why zero dependencies, screenshot of terminal output, how
   scoring works, measured results, limitations. Written in a human tone, not AI-sounding.
6. **ML classifier.** Train on Nazario phishing corpus vs Enron legit emails using
   scikit-learn. Compare against the rule-based score. **Ask before adding dependencies.**

---

## 12. Things NOT to do

- Don't add packages.
- Don't open browsers or create HTML.
- Don't visit URLs from emails.
- Don't commit or read out contents of `samples/` beyond what's needed to debug scoring.
- Don't rewrite working code just to restyle it.
- Don't make big multi-file changes in one go.
- Don't claim results that weren't measured. If you didn't run it, say so.
- Don't push.
- Don't use em dashes, semicolons, or colons in prose written for the README or resume
  bullets. The owner wants those to sound human-written, using periods and commas.
