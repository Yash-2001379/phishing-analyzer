w# CLAUDE.md, Phishing Email Analyzer

Read this whole file before doing anything. It explains what this project is, who it's for,
how the code works, what has already been decided, and the rules you must follow.

---

## 1. What this project is

A command line tool written in Python that reads email files (`.eml`), looks for signs of
phishing, gives each email a risk score, and produces a clear report.

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
    `www[.]`. This is standard SOC practice so nothing is clickable.
- **Never click, fetch, or open URLs found in emails.** Only send them to VirusTotal's API
  for lookup (never visit them directly).
- **Never execute or open attachments.** Only hash them (SHA256).

### Privacy rules

- `samples/` contains the owner's **personal Gmail emails** and real phishing samples.
  Never commit it, never copy its contents into code, docs, tests, or commit messages.
- `reports/` contains data from those emails. Never commit it.
- `.env` holds the VirusTotal API key. Never commit it, never print the key.
- `vt_cache.json` holds lookup results. Never commit it.
- This repo is **public**. Don't put personal info (real names, email addresses, student
  details) anywhere in committed files. Use made-up examples like `support@paypal-help.com`.

### Git rules

- Don't run git commands unless asked. The owner commits and pushes through GitHub Desktop.
- Before suggesting a commit, check `git status` and confirm none of these appear:
  `samples/`, `reports/`, `.env`, `vt_cache.json`, `__pycache__/`.
- Suggest short, clear commit messages like `add brand lookalike detection`.

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
├── CLAUDE.md          this file
├── README.md          public project description (needs writing properly)
├── .gitignore         Python template + project lines at the bottom
├── .env               VT_API_KEY=... (gitignored, may not exist yet)
├── src/
│   ├── parser.py      reads .eml files, extracts headers, URLs, attachments
│   ├── report.py      scoring + terminal report + markdown report (main entry point)
│   └── vt_client.py   VirusTotal lookups (NOT yet connected to report.py)
├── samples/           test emails (gitignored)
└── reports/           generated markdown reports (gitignored)
```

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
python src/report.py samples              # scan every email in the folder
python src/report.py samples/file.eml     # scan one email
```

- Folder mode finds emails **by content, not filename**. It reads the first 4KB and looks
  for `from:`, `received:`, `subject:`, or `return-path:`. Any name, any extension works.
- `.msg` (Outlook format) is skipped with a message telling the user to save as `.eml`.
- Non-email files are skipped with a reason.
- A broken email is skipped, the rest of the scan continues. Never let one bad file crash
  the whole run.
- Output: colored cards in the terminal, a summary table, and a saved
  `reports/report_<timestamp>.md`. User opens it in VS Code with `Ctrl+Shift+V`.

---

## 6. How the code works

### parser.py

| Function | What it does |
|---|---|
| `load_email(path)` | Opens the file in binary and parses it with `email.parser.BytesParser(policy=policy.default)` |
| `get_headers(msg)` | Returns dict: subject, from_name, from_addr, reply_to, return_path, auth_results (the `Authentication-Results` header), received_hops |
| `get_body_and_urls(msg)` | Joins text/plain and text/html parts into one string, finds URLs with a regex, returns (text, sorted unique urls) |
| `get_attachments(msg)` | For each attachment: filename, content_type, size_bytes, sha256 |
| `domain_of(addr)` | `user@x.com` becomes `x.com` |
| `red_flags()`, `analyze()` | **Old Phase 1 logic.** Superseded by report.py scoring. Kept for reference. Don't build on them. |

Running `python src/parser.py file.eml` prints raw JSON. That's a debugging view only.

### report.py

**Helpers**

| Function | What it does |
|---|---|
| `root_domain(domain)` | `accounts.brain.fm` becomes `brain.fm`. Handles two-part endings like `co.uk` using `TWO_PART_TLDS`. This fixed a false positive where subdomains of the same company looked like different senders. It's a simple approach, not a full public suffix list. |
| `auth_status(header)` | Pulls `spf=`, `dkim=`, `dmarc=` values out of Authentication-Results. Returns `pass`, `fail`, `softfail`, `none`, `temperror`, `permerror`, or `missing` |
| `summarize_links(urls)` | Collapses many URLs into unique hostnames with counts. Ignores `JUNK_DOMAINS` (like w3.org HTML boilerplate) and image files. Returns (domains dict, raw IP urls) |

**Scoring, `score_email(path)`**

Each rule adds points with a plain English reason. Total decides the verdict.

| # | Rule | Points | Notes |
|---|---|---|---|
| 1 | No sender address | +3 | |
| 1 | Sender domain has no dot (fake, like `@pot`) | +2 | |
| 1 | Sent from `onmicrosoft.com` | +2 | Free Microsoft trial domains, heavily abused |
| 2 | SPF fail or softfail | +2 | |
| 2 | DKIM fail | +2 | |
| 2 | DMARC fail | +3 | Strongest signal, domain owner disowns the email |
| 2 | DKIM none/missing AND DMARC not pass | +2 | "Nothing proves who sent this" |
| 3 | Reply-To root domain differs from From | +3 | Message says "free inbox" if it's gmail/outlook/etc |
| 4 | Return-Path root differs from From | +1 | **Only if DMARC didn't pass.** Newsletters use SendGrid etc legitimately |
| 5 | Sender name contains a brand, domain isn't that brand's | +3 | Uses `BRANDS` dict of real domains |
| 5 | Subject contains a brand, domain isn't theirs, DMARC not pass | +2 | DMARC condition stops legit newsletters mentioning brands from being flagged |
| 6 | Link to a raw IP address | +3 each | |
| 7 | Any `URGENT_WORDS` in subject or body | +1 | Once total, not per word |
| 7 | Any `LURE_WORDS` in subject or body | +1 | Once total, not per word |
| 8 | Attachment with an extension in `RISKY_EXTS` | +3 each | |

**Verdict thresholds:** `>= 6` HIGH, `>= 3` MEDIUM, otherwise LOW.

`score_email` returns a dict: file, headers, auth, from_root, link_domains, total_urls,
attachments, findings (list of (points, reason)), score, verdict.

**Output**

| Function | What it does |
|---|---|
| `c(text, code)` | Wraps text in ANSI color codes. Turns off when output isn't a terminal or `NO_COLOR` is set. `os.system("")` enables colors on older Windows terminals |
| `clean(text, limit)` | Removes non-printable characters, optionally truncates with `…` |
| `print_card(r)` | One boxed card per email: verdict, subject, from, reply-to, auth badges (✓ ✗ ?), reasons, top 5 link domains, attachments |
| `print_summary()` | Counts per verdict, sorted list, skipped files, path to saved report |
| `md(text)` | Safe markdown: clean, HTML escape (`quote=False`), escape markdown symbols, defang links |
| `build_markdown()` | Full report with summary table and a section per email, 🔴🟠🟢 icons |
| `looks_like_email()`, `find_emails()` | Content-based detection described in section 5 |
| `main()` | Sets stdout to UTF-8 (needed on Windows for ✓ and emoji), runs everything |

### vt_client.py (not connected yet)

- Looks up URLs, sender domains, and attachment hashes on VirusTotal API v3.
- `url_id()`: VT identifies URLs by unpadded base64url of the URL.
- Caches results in `vt_cache.json` so the same thing is never looked up twice.
- Waits 15 seconds between live calls. **Free tier limit is 4 requests per minute and 500
  per day.** Respect this.
- **Currently uses `requests` and `python-dotenv`, which breaks the zero dependency rule.**
  Must be rewritten with `urllib.request` and a tiny manual `.env` reader before connecting.

---

## 7. Decisions already made (don't reopen without a good reason)

| Decision | Why |
|---|---|
| Zero dependencies | Supply chain risk, and it's an interview talking point |
| Terminal output + markdown file | Looks professional, nothing auto-opens, no attacker content rendered as HTML |
| HTML report rejected | Pop-ups are bad behaviour for a security tool, rendering attacker content is risky |
| `rich` library rejected | Dependency |
| Detect emails by content, not filename | Real users won't rename files, tool must handle messy input |
| Compare root domains, not full domains | Subdomains of one company were flagged as mismatches |
| Return-Path only counts without DMARC pass | Newsletters legitimately bounce through mail services |
| Subject brand check only without DMARC pass | Legit newsletters mention other brands |
| Defang links in reports | Standard SOC practice |
| Public test data from `rf-peixoto/phishing_pot` | Owner's Gmail has little spam, and these are real phishing samples |

---

## 8. Current results

Tested on 6 emails:

| Email | Type | Verdict | Score |
|---|---|---|---|
| sample-10 | Fake Microsoft sign-in alert | HIGH | 12 |
| sample-10000 | Casino scam, broken sender | HIGH | 8 |
| sample-100 | Solar spam, mismatched reply | HIGH | 6 |
| sample-10001 | Casino scam from onmicrosoft.com | MEDIUM | 5 |
| sample-1 | Fake Brazilian bank (Bradesco) | MEDIUM | 3 |
| newsletter1 | Legit Brain.fm newsletter | LOW | 0 |

**Phishing caught: 5/5. False positives: 0/1.**

**Be honest about this:** only 1 legit email has been tested. The "no DKIM + no DMARC" rule
(+2) could flag small legit senders like a local business or personal mail server. Testing
more legit email is the top priority.

History worth keeping for the README:
- First version caught 3/5 as MEDIUM, 0 as HIGH, and gave the legit newsletter 2 false
  positive flags (subdomain mismatch).
- Fixed by comparing root domains, adding sender, authentication, brand, and bait rules.

---

## 9. Known gaps

1. **Lookalike domains.** `paypal-help.com` or `paypa1.com` sending as "PayPal Support"
   doesn't get brand points, because the brand name appears in the domain or the check
   is too literal. Idea: flag a domain that *contains* a brand name but isn't in that
   brand's real domain list, and look for digit swaps like 1 for l, 0 for o.
2. **Only 1 legit email tested.** False positive rate is unknown.
3. **No VirusTotal in the report yet.**
4. **`root_domain` is simple.** It doesn't know every two-part ending. Fine for now,
   mention it as a limitation.
5. **Word lists are English only.** Phishing in Portuguese, Dutch, etc. is caught by
   header rules but not language rules.
6. **Link text vs real destination** isn't checked (text says paypal.com, link goes
   elsewhere). Good future rule.
7. **No tests.** A small `tests/` folder with fake made-up emails would help, and is good
   for interviews. Never use real samples in tests.

---

## 10. Roadmap

Work in this order unless the owner says otherwise.

1. **Test legit email.** Owner adds 5+ normal emails to `samples/`. Run the scan. Any legit
   email at MEDIUM or HIGH is a false positive. Explain the cause, propose the smallest fix,
   re-run everything to make sure phishing is still caught.
2. **Lookalike domain detection** (gap 1).
3. **Rewrite vt_client.py** with `urllib.request`, read `.env` manually, keep cache and rate
   limit. Then add an optional flag to report.py, like `--vt`, that adds VirusTotal results
   to findings (example: +3 if any vendor flags a URL as malicious). Only look up unique
   link domains and hashes, not all 30 tracking URLs, to save quota.
4. **Measure at scale.** Run on ~50 phishing samples and ~50 legit emails. Record catch
   rate and false positive rate. These numbers go on the resume.
5. **README.** What it does, why zero dependencies, screenshot of terminal output, how
   scoring works, measured results, limitations. Written in a human tone, not AI-sounding.
6. **ML classifier.** Train on Nazario phishing corpus vs Enron legit emails using
   scikit-learn. Compare against the rule-based score. **Ask before adding dependencies.**

---

## 11. Things NOT to do

- Don't add packages.
- Don't open browsers or create HTML.
- Don't visit URLs from emails.
- Don't commit or read out contents of `samples/` beyond what's needed to debug scoring.
- Don't rewrite working code just to restyle it.
- Don't make big multi-file changes in one go.
- Don't claim results that weren't measured. If you didn't run it, say so.
- Don't use em dashes, semicolons, or colons in prose written for the README or resume
  bullets. The owner wants those to sound human-written, using periods and commas.
