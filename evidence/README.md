# Evidence

- `ledger.csv` — every factual claim used anywhere in the project.
  Columns: `id,claim,harness,label,source_url,publisher,source_date,accessed,verified_by,confidence`
  - `label`: verified-by-test | from-official-docs | third-party-report | unverified
  - `confidence`: high | medium | low
  - `verified_by`: who/what checked it (e.g. `phase1:G1 web-fetch`, `phase5:E5 test`)
- `incidents.csv` — RQ3 incident & CVE timeline.
  Columns: `id,date_disclosed,harness,vendor,title,cve,ghsa,kind,taxonomy_class,root_cause_class,affected_versions,fixed_version,fix_date,patch_latency_days,primary_source,secondary_source,reporter,verified,notes`
  - `kind`: vulnerability | design-weakness | supply-chain | misuse | incident
  - `taxonomy_class`: T01–T16 (MISSION §3)
  - `root_cause_class` (draft): RC1 untrusted content treated as instructions with a capability path ·
    RC2 config/workspace content executed before consent · RC3 permission/allowlist/path check flaw ·
    RC4 unauthenticated local service/endpoint · RC5 package/extension supply-chain compromise ·
    RC6 insecure default / over-privileged mode · RC7 secret/data exposure or leak ·
    RC8 sandbox escape · RC9 output-rendering or tool-based exfiltration channel
  - `verified`: yes (CVE on NVD/GHSA or primary advisory read) | no
- `sources.bib` — BibTeX for every cited source, with `urldate`.
- `ledger.d/`, `incidents.d/`, `research/` — per-research-group fragments merged into the files above.
