# Prioritisation method

> This is CyberSentinel's own, transparent heuristic for ordering remediation work.
> It is **not** an industry standard and not an authoritative risk score. Its value is that every
> point can be traced to a public signal and every weight can be changed in `config/scoring.yaml`.

## Why not sort by CVSS?

CVSS measures how bad a flaw would be *if exploited*. It says nothing about whether anyone exploits
it. In our live data, 756 vulnerabilities rated CVSS "CRITICAL" end up "Medium" because they are not
in KEV, have a low EPSS and do not touch our inventory — while medium-severity flaws that CISA has
seen exploited move up to High or Critical. The Overview page shows this cross-table.

## Signals and points (default configuration)

| Signal | Source | Rule | Max points | Rationale |
|---|---|---|---|---|
| Technical severity | NVD CVSS base score (v3.1 > v3.0 > v4.0 > v2, NVD primary score preferred) | `score / 10 × 30`. If NVD has no score yet, the OSV advisory label is used (CRITICAL 9.0, HIGH 7.5, MODERATE 5.0, LOW 2.5) and the explanation says so | 30 | Severity still matters, but it is only one third of the decision |
| Confirmed exploitation | CISA KEV | +30 if listed, +5 more if CISA reports ransomware use | 35 | The strongest evidence available: it is happening |
| Predicted exploitation | FIRST EPSS probability | ≥ 0.50 → 20 · ≥ 0.10 → 14 · ≥ 0.01 → 6 · else 0 | 20 | Bands rather than linear, because EPSS is very skewed (most CVEs are < 0.01) |
| Exposure | Watchlist + OSV, version re-checked | +15 if at least one watched package version is affected | 15 | A flaw in software we run matters more than one we do not |
| Actionability | OSV `fixed` version | +5 if every affected watched package has a fixed version | 5 | A fix exists, so the work can be scheduled now. Unknown is never treated as "fixed" |

Score = sum, capped at 100.

## Tiers and floors

| Tier | Score | Meaning |
|---|---|---|
| Critical | ≥ 65 | act now |
| High | ≥ 45 | plan this cycle |
| Medium | ≥ 25 | track |
| Low | < 25 | no action unless context changes |

Floors override the points when they would give a lower tier:

- in KEV **and** affects a watched package → at least **Critical**;
- in KEV → at least **High** (CISA's own guidance is that KEV entries must be remediated).

These rules are also enforced by a dbt test (`assert_kev_is_at_least_high`).

## Worked examples (real data from a live run)

| CVE | Signals | Points | Result |
|---|---|---|---|
| CVE-2021-44228 (Log4Shell) | CVSS 10.0, KEV + ransomware, EPSS ≈ 1.0, affects `log4j-core 2.14.1`, fixed in 2.15.0 | 30 + 35 + 20 + 15 + 5 = 105 → 100 | Critical |
| CVE-2022-22965 (Spring4Shell) | CVSS 9.8, KEV, EPSS 99.6 %, affects `spring-beans 5.3.17`, fix 5.3.18 | 29.4 + 30 + 20 + 15 + 5 | Critical (99.4) |
| CVE-2021-44832 (Log4j, not in KEV) | CVSS 6.6, EPSS 97.9 %, affects watchlist, fix 2.17.1 | 19.8 + 0 + 20 + 15 + 5 | High (59.8) |
| A CVSS 9.8 CVE, EPSS 0.2 %, not in KEV, not in watchlist | | 29.4 + 0 + 0 + 0 + 0 | Medium (29.4) |

## How it is implemented and tested

- `cybersentinel/prioritization/rules.py` loads and validates `config/scoring.yaml` (wrong tier
  names, missing EPSS zero band, unknown floor signals → error, so a typo cannot silently change
  priorities).
- `cybersentinel/prioritization/scoring.py` is a pure function: signals in, points + tier +
  explanation out. Tested in `tests/unit/test_scoring.py`.
- dbt runs it in `int_vulnerability_priority.py` (a dbt Python model), so the warehouse and the
  tests use the same code. dbt tests check the score range, that points add up to the score, and
  the KEV floors.

## Known limitations

- Weights are expert judgement, not fitted to outcome data. A natural extension is to calibrate
  them against historical KEV additions (did the score rank future KEV entries high?).
- Exposure is only as good as the watchlist: packages not listed, or not covered by OSV
  (e.g. operating systems, appliances), get no exposure points.
- "Fix available" uses OSV's `fixed` events only; NVD "Patch" reference tags are stored but not
  scored because they do not say *which* version fixes the issue.
