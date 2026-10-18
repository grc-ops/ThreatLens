# ThreatLens

Multi-source IOC lookup and bulk triage for SOC analysts.

## Run
```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # add the keys you have
python app.py               # http://127.0.0.1:5000
```

## What it does
- Paste or upload indicators (IP, domain, URL, MD5/SHA1/SHA256, CVE). Defanged input is auto-cleaned, duplicates removed, private IPs skipped.
- Queries every relevant source in parallel and normalises each to a 0-100 score.
- Shows one consolidated score per indicator and a chip per source. Clicking a chip (for example `VT 12/94`) opens that indicator's page on that source (the VirusTotal GUI page for VT).
- Filters: type, score range, minimum sources flagging, verdict (click the stat cards), text search. Sort, copy the filtered list for blocklists, export CSV/JSON.
- Expand a row for per-source details plus extra pivot links (Talos, X-Force, Censys, Hybrid Analysis, ANY.RUN, Triage, crt.sh, NVD, Exploit-DB and more).

## News, IOC extraction and MITRE ATT&CK (second tab)
- **Search news** across 17 security feeds (BleepingComputer, The Hacker News, CISA, Unit 42, Talos, Microsoft, Google Threat Intel, The DFIR Report, SANS ISC and more) by keyword and time window. Tick "Include wider web news" to add a Bing News search. Edit `data/feeds.json` to add, remove or fix feeds.
- **OTX pulses:** with `OTX_API_KEY` set, "AlienVault OTX pulses" appears as a feed. A keyword search queries all public pulses; with no keyword it shows pulses you subscribe to (or recent public ones if you follow none). Analysing a pulse uses its own indicators and ATT&CK tags directly. Tags with retired or renumbered IDs are listed separately, and TLP:AMBER/RED pulses show a warning before you send their indicators to outside services.
- **Analyse** any article, a pasted URL, or pasted report text:
  - **Indicators:** IPs, domains, URLs, hashes and CVEs are pulled out. Defanged text is handled. File names (`payload.exe`, `setup.py`), vendor and reference domains, private IPs and the article's own site are filtered out. Each indicator gets a confidence: *high* (defanged in the text, or a hash/CVE), *medium* (near words like C2 or payload), *low* (just appears in the text).
  - **ATT&CK map:** built from the official MITRE ATT&CK dataset (bundled in `data/attack_index.json`, currently v20). Evidence is of three kinds: explicit technique IDs in the text, technique names, and about 125 curated behaviour rules (for example "scheduled task" or "mimikatz"). Click any technique to see the sentence that triggered it.
  - **Actors and malware** named in the text are matched to ATT&CK groups and software. You can overlay the techniques they are known for as dashed cells. Those were not seen in the report, so treat them as hunting ideas.
  - **Send to IOC check:** tick the indicators you want and send them straight to the first tab for scoring.
  - **Export** an ATT&CK Navigator layer (JSON) to open at mitre-attack.github.io/attack-navigator.
- Update the ATT&CK data with `POST /api/attack/refresh` or `python -c "import intel; intel.refresh_attack()"`.
- Limits: PDFs are not read (paste the text). The mapping is based on wording, not understanding, so it can miss techniques or over-match. Review before acting.
- Article fetching blocks private addresses and only follows http(s) on ports 80/443, so the app cannot be used to probe your network.

## Context, history and housekeeping
- **Context line under each indicator:** domain registration age (RDAP, flagged when under 30 days), first and last seen across the sources, "may be stale" when a malicious-looking indicator has had no activity for over 180 days, ASN and holder for IPs (RIPEstat), registrar, and CVEs linked to the IP's open ports (Shodan InternetDB, with a button to check them).
- **In news badge:** shown when an indicator appeared (high or medium confidence) in an article you analysed. Click it to open that article.
- **Source health:** each source pill has a status dot (working, some recent errors, last call failed, not used yet). Open "Source health" for calls today, remaining quota where the source reports it, and the last error. Daily counts are kept by this app, so they reset on restart.
- **History:** every completed check is saved. Load shows the stored results without querying the sources again; Check again re-queries. The last 50 batches are kept.
- **Light and dark theme** (remembered), and **Print report** for the indicator table or an article analysis.

## News tab extras
- **Saved searches** show a "new" badge counting matching articles published since you last opened that search.
- **Hide analysed** removes articles you have already analysed. Analysed articles are kept for 90 days (`RETENTION_DAYS`).
- **Daily digest** analyses the newest unread articles from the last 24 hours, ranked by your saved searches, threat keywords (ransomware, zero-day, APT and so on) and high-signal sources, then merges them. Good for a 30-minute morning routine: run it, review the new indicators, send the ones you want to the check tab.
- **Analyse together:** tick two or more articles to merge their indicators and techniques. Technique cells show how many articles support them, and the exported Navigator layer scores them higher when several articles agree.
- Everything above is stored in `data/threatlens.db` (SQLite). It is safe to delete.

## Sources
| Source | Types | Key needed |
|---|---|---|
| VirusTotal | ip, domain, url, hash | yes |
| AbuseIPDB | ip | yes |
| AlienVault OTX | ip, domain, url, hash | yes |
| GreyNoise Community | ip | yes |
| URLhaus, ThreatFox, MalwareBazaar | ip, domain, url, hash | one abuse.ch Auth-Key |
| Pulsedive | ip, domain, url | yes |
| Shodan InternetDB | ip | no |
| urlscan.io | ip, domain, url | optional |
| CIRCL hashlookup | hash | no |
| FIRST EPSS, CISA KEV, NVD | cve | no (NVD key optional) |

## Scoring
Each source maps to 0-100 (VirusTotal: 8 points per malicious engine and 3 per suspicious, capped at 100; AbuseIPDB and ThreatFox use their own confidence; Pulsedive maps its risk label; and so on).
Consolidated score = the larger of (weighted average of scored sources) and (80% of the highest single score), so one strong hit from a high-fidelity source is not diluted by sources that have never seen the indicator.
Weights: VT 3, KEV 3, AbuseIPDB / URLhaus / ThreatFox / MalwareBazaar 2, GreyNoise / Pulsedive / urlscan 1.5, OTX / EPSS / NVD 1, Shodan / CIRCL 0.5. Edit them in `app.py`.
Verdict bands: 70+ malicious, 40-69 suspicious, 10-39 low, under 10 clean. "No data" means no source returned a score; it does not mean safe.

## Handle with care
- Indicators you submit are sent to third-party services. Do not paste internal hostnames, customer URLs or anything under NDA. Check your policy before adding to VT/urlscan (urlscan results can be public).
- There is no login. Keep `HOST=127.0.0.1`, or put it behind your VPN / reverse proxy with SSO before sharing.
- Malicious indicators are always shown as text, never as clickable links. Output is defanged by default.
- Add a new source by writing one function with the `@provider(...)` decorator in `app.py`.
