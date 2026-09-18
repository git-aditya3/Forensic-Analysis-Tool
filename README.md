# Sentinel Forensic Analysis Tool

Sentinel is a dependency-free core system for the forensic examination of
Digital Video Recorder (DVR) and Network Video Recorder (NVR) storage. It is
built around the problem in this repository: recorder vendors such as Dahua,
CP Plus, Hikvision, Honeywell, TP-Link, Godrej, Uniview, and Matrix can write
proprietary storage layouts that appear raw or unformatted to a normal
operating system.

> **Important:** Sentinel is an examination aid, not a legal admissibility
> determination. A signature hit or carved video range is reported as an
> observation and must be independently validated against the source device,
> acquisition procedure, and applicable law.

## What is implemented

- **Read-only acquisition** — streams an image into case storage while
  calculating MD5 and SHA-256; the acquired copy is chmod read-only on systems
  that support it.
- **Vendor and family detection** — bounded signature detection for Hikvision,
  Dahua, Honeywell, CP Plus, Uniview, TP-Link, Godrej, Matrix, plus an honest
  unknown/generic route when no vendor signature is present.
- **Vendor routes**
  - Dahua: bounded DHAV-family block parsing with safe length and timestamp
    sanity checks, followed by Annex-B carving when deeper recovery is chosen.
  - Hikvision: HIKVISION/HIKBTREE detection, MPEG program-stream pack leads,
    and raw Annex-B carving.
  - Honeywell: signature routing, raw carving, and an explicit expired-index
    lead when media bytes are adjacent.
  - CP Plus, Uniview, TP-Link, Godrej, Matrix: signature-only routing to the
    generic recovery tier in this release.
- **Three recovery postures** — indexed/normal, deleted candidates, and
  lost/corrupted. Each result retains the source byte offsets, codec hint,
  recovery state, confidence, physical-range SHA-256, and limitations.
- **Native evidence export** — copies the exact source range without
  transcoding. Optional MP4 remuxing is used only when an `ffmpeg` executable
  is installed; the native artifact is retained alongside it.
- **Chain of custody** — SQLite audit events are hash-linked from a GENESIS
  value. Acquisition, identification, recovery, and report generation are
  recorded and the chain can be verified.
- **Reports** — JSON, HTML, and a small dependency-free PDF containing the
  evidence inventory, hashes, recovered ranges, interpretation notes, and
  audit-chain status.
- **Browser workstation and CLI** — both use the same engine and storage
  layer. The web UI is served by Python's standard library HTTP server.

## Quick start

Python 3.10 or newer is the only runtime requirement.

```bash
# Start the local workstation. Bind to 0.0.0.0 for a LAN/container preview.
python3 -m forensic_tool serve --host 0.0.0.0 --port 8000 --data-dir data
```

Open <http://localhost:8000>. The browser workflow is:

1. Create an examination.
2. Acquire an image from the **Acquire evidence** tab.
3. Select the source under **Analyze & recover** and run identification.
4. Choose normal, deleted-candidate, or lost/corrupted recovery.
5. Download native ranges or generate the report package.

No source image is included in this repository. The tests use small in-memory
byte fixtures; they are not claims of field validation against every recorder
firmware variant.

## CLI workflow

```bash
# Create a case and copy the source into immutable case storage.
python3 -m forensic_tool --data-dir data case create "Station road incident" \
  --investigator "Examiner 07"
python3 -m forensic_tool --data-dir data case list
python3 -m forensic_tool --data-dir data acquire ./seized-drive.img --case CASE-XXXXXXXXXX

# Use the IDs printed by the preceding commands.
python3 -m forensic_tool --data-dir data identify EVD-XXXXXXXXXXXX
python3 -m forensic_tool --data-dir data recover EVD-XXXXXXXXXXXX --mode deleted
python3 -m forensic_tool --data-dir data timeline EVD-XXXXXXXXXXXX
python3 -m forensic_tool --data-dir data export SEG-XXXXXXXXXXXX --format native
python3 -m forensic_tool --data-dir data report CASE-XXXXXXXXXX
```

`data/` contains the SQLite database, acquired evidence, native exports, and
report artifacts. It is ignored by Git. Use a separate, access-controlled
volume for real examinations.

## API surface

The web server exposes a small JSON API used by the UI:

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Engine health/version |
| `GET/POST` | `/api/cases` | List or create cases |
| `GET` | `/api/cases/{case_id}` | Case bundle, evidence, findings, audit |
| `POST` | `/api/cases/{case_id}/evidence` | Stream raw bytes; pass `X-Filename` |
| `GET` | `/api/evidence/{evidence_id}` | Source metadata and results |
| `POST` | `/api/evidence/{evidence_id}/identify` | Run bounded identification |
| `POST` | `/api/evidence/{evidence_id}/recover` | JSON `{ "mode": "normal" }` |
| `GET` | `/api/evidence/{evidence_id}/timeline` | Ordered recovered ranges |
| `GET` | `/api/segments/{segment_id}/export?format=native` | Download exact bytes |
| `POST` | `/api/cases/{case_id}/report` | Build report artifacts |
| `GET` | `/api/cases/{case_id}/report.html/.pdf/.json` | Download a report |

The default upload limit is intentionally large for disk images but can be
changed by constructing `SentinelApp(max_upload_bytes=...)` when embedding the
server.

## Architecture

```text
Browser / CLI
     │
     ▼
SentinelApp ── EvidenceStore (SQLite + immutable byte copies)
     │
     ├── Detector ── vendor profiles and confidence/limitations
     ├── Parser registry ── DHAV / Hikvision / Honeywell / generic routes
     ├── Annex-B carver ── bounded H.264/H.265 physical ranges
     ├── Exporter ── exact native range, optional ffmpeg remux
     └── Reporter ── JSON / HTML / PDF + verified custody chain
```

The `EvidenceReader` uses random-access and chunked reads. It never mounts an
image, writes to the source, or treats a raw signature as a timestamp. Unknown
or partially understood formats remain explicit in the output rather than
being silently labelled as recovered truth.

## Verification

Run the standard-library test suite from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

The tests cover cross-chunk signature detection, acquisition hashes, vendor
routing, bounded DHAV parsing, the three recovery states, exact native export,
report creation, and tamper detection in the custody chain.
