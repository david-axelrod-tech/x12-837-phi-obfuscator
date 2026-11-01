# x12-837-phi-obfuscator

[![CI](https://github.com/USERNAME/x12-837-phi-obfuscator/actions/workflows/ci.yml/badge.svg)](https://github.com/USERNAME/x12-837-phi-obfuscator/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Strip Protected Health Information (PHI) out of **ANSI X12 837 claim files** (837P
professional and 837I institutional) while leaving every other byte exactly where it was,
so the output still validates, still loads into a clearinghouse or test system, and still
looks like a real claim batch.

Three levels of de-identification, one command (or one window):

| Mode | What it is for | Standard |
|---|---|---|
| `basic` | Realistic **test data**. Patient identity is replaced; service dates, claim numbers, providers and ZIPs are kept so the file behaves identically in a test system. | - |
| `expert` | The usual input for an **Expert Determination**. Basic, plus shifted dates, scrambled claim/line/auth numbers, renamed NPI-less providers, 3-digit ZIP. Pseudonyms are a keyed hash so the same patient maps the same way across files and runs. | 45 CFR 164.514(b)(1) |
| `safe-harbor` | **HIPAA Safe Harbor** applied literally: all 18 identifier classes handled, year-only dates, ages over 89 collapsed, free text redacted, random (not derived) pseudonyms. | 45 CFR 164.514(b)(2) |

## Why this exists

RCM, EDI and integration teams constantly need real-shaped 837 files: to reproduce a payer
rejection, to load a test clearinghouse, to train staff, to hand a sample to a vendor.
Production claims are full of PHI, and the usual answers (hand-edit a file, regex-replace a
few names, or write a throw-away script) break the file, miss identifiers hiding in notes
and `REF` segments, or produce something no compliance officer will sign off on.

This tool is the answer I wanted on hand: a single standard-library Python file that an
analyst can double-click, that knows where PHI lives in an 837, that proves what it
changed, and that explains the regulatory basis for each choice.

## Quick start

```bash
# realistic test data from a folder of claims (layout reproduced under ./scrubbed)
python obfuscate_837.py ./837_files -o ./scrubbed

# expert-determination input; the seed is the hash key, keep it secret
python obfuscate_837.py ./837_files -o ./expert --mode expert --seed "my secret"

# Safe Harbor; the mapping CSV is the re-identification key under 164.514(c)
python obfuscate_837.py ./837_files -o ./deid --mode safe-harbor --map key.csv

# overwrite in place, writing *_scrubbed copies beside the originals
python obfuscate_837.py claim.dat --in-place --suffix _scrubbed
```

Run with **no arguments** (or double-click `obfuscate_837.pyw` on Windows) and a window
opens with the same choices, a progress bar and a live log. Dropping a file or folder onto
the icon opens the window pre-filled. Run `-h` for the full option list and a
side-by-side table of what each mode changes.

Try it on the included synthetic sample:

```bash
python obfuscate_837.py samples/sample_837p.x12 -o out --mode expert --seed demo
```

## Before and after (expert mode, synthetic data)

```text
NM1*IL*1*DOE*JANE*Q***MI*ZZ12345A~            NM1*IL*1*ANDREWS*ROXANNE*V***MI*LP79399B~
N3*123 MAPLE ST*APT 4~                        N3*2218 ALDER LN*APT 914~
N4*SPRINGDALE*NY*12345~                       N4*GRANITE FALLS*NY*12300~
DMG*D8*19500614*F~                            DMG*D8*19490430*F~
REF*SY*123456789~                             REF*SY*185377865~
CLM*37-104625*480.00***12:B:1*Y*A*Y*Y~        CLM*37-525651*480.00***12:B:1*Y*A*Y*Y~
DTP*434*RD8*20250203-20250207~                DTP*434*RD8*20250124-20250128~
REF*EA*MRN0004471~                            REF*EA*XNA2629797~
NTE*ADD*NAME: JOHN DOE REL: SPOUSE ...~       NTE*ADD*NAME: LULA AUSTIN REL: SPOUSE ...~
HI*ABK:I10*ABF:E119~                          HI*ABK:I10*ABF:E119~          (unchanged)
NM1*82*1*SMITH*MARY****XX*1888888886~         NM1*82*1*SMITH*MARY****XX*1888888886~  (NPI provider: unchanged)
SV1*HC:T1019:U1*120.00*UN*4***1~              SV1*HC:T1019:U1*120.00*UN*4***1~       (unchanged)
```

Every replacement keeps the **shape** of the original (length, letter/digit pattern, date
format, office prefix on account numbers), so segment counts, control totals and payer
edits are unaffected.

## What each mode changes

```text
                               basic           expert           safe-harbor
  patient / subscriber names   fake            fake             fake
  member ID, MRN, SSN          pseudonym       pseudonym        random
  street, city, county         fake / dropped  fake / dropped   fake / dropped
  state                        kept            kept             kept
  ZIP                          kept            first 3 digits   first 3 digits*
  date of birth                shifted +-2 yr  shifted +-2 yr   year, 90+ cap
  service / admit / stmt dates kept            shifted 1..N d   year only
  envelope dates (ISA/GS/BHT)  kept            kept             year only
  CLM01, line/auth/trace/PWK # kept            pseudonym **     random
  NPI-less person providers    kept            fake             fake
  NTE / K3 free text           names scrubbed  names scrubbed   REDACTED
  group number (SBR03)         kept ***        kept ***         random
  gender, dx/px codes, charges, NPIs, provider orgs, payers: kept in every mode

    *  000 for the HHS restricted 3-digit ZIP areas (< 20,000 people)
    ** office prefix before the hyphen is kept, e.g. 37-104625 -> 37-684996
    *** replaced only when it repeats the member ID
```

Fine-tuning flags (`--shift-service-dates`, `--date-shift-days N`, `--scramble-claim-ids`,
`--scramble-provider-names`, `--zip-mode keep|zip3|random`, `--id-keep-tail N`) let you
turn individual expert-mode behaviours on in basic mode. Safe Harbor ignores them all, by
design.

## Design notes

**Delimiter-preserving parser.** The file is split on the terminators declared in the ISA
header and re-joined with the original whitespace, line endings and trailing separators.
Nothing is re-serialised, so a file that round-trips through the tool with no PHI in it
comes out byte-identical.

**Context-aware, not regex-based.** Transformations only fire inside the subscriber /
patient hierarchy (`HL*..*22` and `*23`). The billing provider's address, the payer, the
submitter and every entity carrying an NPI are never touched. Address segments are only
scrubbed when they follow a patient, ambulance pick-up/drop-off, or NPI-less facility
`NM1` (a service facility without an NPI in home care is the patient's home).

**Keyed pseudonyms (basic / expert).** Each fake value is derived from
`HMAC-SHA256(seed, category || real)`, so the same real patient gets the same fake
identity in every file and every run that shares a seed, with no mapping table to protect.
HHS permits this under Expert Determination provided the key is not disclosed.

**Random pseudonyms (safe-harbor).** HHS treats any code derived from PHI, including an
unkeyed hash, as an identifier. Safe Harbor mode therefore draws from `os.urandom` and
offers `--map` / `--map-in` for the (rare) case where cross-run consistency is needed.

**Two name tables.** Patients and everyone else (relatives named in `NTE` notes, aides,
contact persons) draw from separate pools, so a spouse who really shares the patient's
surname never shares the patient's *fake* surname, and a note can never leak the fake
patient's name. Free-text scrubbing understands the common `NAME: ... REL: ...` pattern.

**Per-patient date shifting.** One offset per patient (keyed on name + DOB, not member ID,
so a patient billed to two payers shifts consistently) is applied to every `DTP`, `HI`
occurrence/span date and `PAT` date, preserving intervals within a claim. DOBs are
clamped so no fake age exceeds 89.

**Built-in leak check.** After writing, every patient element the tool is responsible for
is compared position-by-position against the input. Anything that survived unchanged is
reported with its segment number and the process exits with status 2.

**Payer quirks handled.** `SBR03` repeating the member ID (Indiana Medicaid), fixed member
ID tails (`--id-keep-tail 2` for IHCP RIDs ending in 99), member IDs with plan suffixes
(`1234/CHOICE`), `<office>-<sequence>` account numbers.

## Options

```text
usage: obfuscate_837.py INPUT [INPUT ...] (-o OUTDIR | --in-place) [options]

output:
  -o, --out OUTDIR          write results under OUTDIR, keeping the input folder layout
  --in-place                overwrite the input files (or, with --suffix, write beside them)
  --suffix SFX              insert SFX before the file extension, e.g. _scrubbed
  -q, --quiet               print only warnings and errors

mode:
  --mode basic|expert|safe-harbor
  --seed SECRET             key for the pseudonym hash (basic and expert)

fine-tuning (expert turns the first three on; safe-harbor ignores all of them):
  --shift-service-dates     shift every claim date back 1..N days, one offset per patient
  --scramble-claim-ids      replace CLM01, line control, prior-auth, referral, payer claim
                            control, trace and attachment numbers
  --scramble-provider-names rename person providers that have no NPI
  --date-shift-days N       window for the date shift (default 60)
  --zip-mode keep|zip3|random
  --id-keep-tail N          keep the last N characters of member IDs

mapping:
  --map CSV                 write the real -> fake table (contains PHI)
  --map-in CSV              load a table written by --map so this run reuses the same fakes

exit status: 0 done, 1 nothing written, 2 leak check found an unchanged patient element
```

## Building a stand-alone Windows executable

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name obfuscate_837 obfuscate_837.pyw
```

The resulting `dist/obfuscate_837.exe` needs no Python install and opens the GUI on
double-click. Attach it to a GitHub Release rather than committing it.

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite runs every mode against the synthetic sample in `samples/` and checks structure
preservation, shape-preserving replacement, determinism, leak detection, date-shift
consistency, Safe Harbor year-only dates and mapping round-trips.

## Compliance notes

- This tool applies de-identification **techniques**. Only a qualified expert's written
  determination makes a data set de-identified under 164.514(b)(1), and Safe Harbor
  additionally requires that the covered entity has **no actual knowledge** that the
  remaining data (diagnosis codes, NPIs, state, year, charges) could identify someone
  (164.514(b)(2)(ii)). Review the output before releasing it.
- The `--seed` (expert) and the `--map` file (safe-harbor) are re-identification keys.
  Keep them inside the covered entity.
- The restricted 3-digit ZIP list is the one published by HHS OCR from the 2000 Census.
  Check hhs.gov for a newer list before relying on it.
- Nothing here is legal advice.

## Requirements

Python 3.9 or newer. Standard library only; `tkinter` ships with the standard Windows and
macOS installers. Optional: `pip install tkinterdnd2` enables drag-and-drop into the
window.

## License

MIT. See [LICENSE](LICENSE).

## Author

David Axelrod. Healthcare revenue-cycle and EDI technology.
[LinkedIn](https://www.linkedin.com/in/david-axelrod-tech/)
