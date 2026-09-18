# Sentinel Forensic Analysis Tool

Sentinel is a forensic examination system for Digital Video Recorder (DVR)
and Network Video Recorder (NVR) storage. Its acquisition and recovery core
uses the Python standard library; the default install also includes OpenCV
and NumPy so post-acquisition analytics work without a separate model runtime.
It can also provision verified OpenCV Zoo detection models on first analytics
use, while retaining deterministic offline fallbacks. It is built around the
problem in this repository: recorder vendors such as Dahua,
CP Plus, Hikvision, Honeywell, TP-Link, Godrej, Uniview, and Matrix can write
proprietary storage layouts that appear raw or unformatted to a normal
operating system.

> **Important:** Sentinel is an examination aid, not a legal admissibility
> determination. A signature hit or carved video range is reported as an
> observation and must be independently validated against the source device,
> acquisition procedure, and applicable law.

## What is implemented

- **Read-only bit-stream acquisition** — streams an image or readable block
  device into case storage while calculating MD5 and SHA-256; sector size,
  source kind, acquisition method, and read-only state are persisted. The
  acquired copy is chmod read-only on systems that support it, and integrity
  can be re-verified later.
- **Vendor, model, and firmware identification** — bounded vendor signatures
  plus evidence-derived model/firmware candidates from ASCII/UTF-16 metadata;
  candidates are explicitly not hardware attestation.
- **Vendor and family detection** — bounded signature detection for Hikvision,
  Dahua, Honeywell, CP Plus, Uniview, TP-Link, Godrej, Matrix, plus an honest
  unknown/generic route when no vendor signature is present.
- **Vendor routes**
  - Dahua: bounded DHAV-family block parsing with safe length and timestamp
    sanity checks, followed by Annex-B carving when deeper recovery is chosen.
  - Hikvision: HIKVISION/HIKBTREE detection, MPEG program-stream pack leads,
    and raw Annex-B carving.
  - Honeywell: signature routing, bounded parsing of the documented custom
    H.264 frame header (resolution, NAL length, Unix-microsecond timestamp),
    raw carving, and explicit index/deletion limitations when channel metadata
    is absent.
  - CP Plus, Uniview, TP-Link, Godrej, Matrix: signature-only routing to the
    generic recovery tier in this release.
- **Bounded recovery postures** — indexed/normal, deleted, overwritten,
  fragmented/corrupted, and unallocated-space candidate sweeps. Labels are
  explicit hypotheses rather than claims about storage history. Each result
  retains bounded source byte offsets, codec hint, recovery state, confidence,
  physical-range SHA-256, and limitations.
- **Native and demuxed evidence export** — copies the exact source range and,
  where a parser provides offsets, the exact container payload range without
  transcoding. MP4 remuxing and analytics decoding use a system FFmpeg when
  present or the packaged `imageio-ffmpeg` fallback; native and payload
  artifacts are retained, hashed, and logged.
- **Timestamp/correlation workflow** — normalizes known timestamps to UTC with
  explicit timezone assumptions and correlates events across camera channels
  only within a configured tolerance. Untimed candidates remain untimed.
- **Post-acquisition analytics** — motion-region analysis, a verified YuNet
  face detector with bundled Haar fallback, and a verified OpenCV Zoo NanoDet
  COCO detector that is automatically provisioned on first use. This covers
  people, vehicles, animals, objects, and common scene classes without manual
  model configuration. Offline mode falls back to Haar/HOG and records the
  unavailable model provenance explicitly. Missing decoders/models return
  `not_configured` or `unsupported`; no finding is fabricated, and analytics
  records retain source ranges, derived hashes, decoder identity, and model
  hashes.
- **Chain of custody** — SQLite audit events are hash-linked from a GENESIS
  value. Acquisition, identification, recovery, and report generation are
  recorded and the chain can be verified.
- **Reports** — JSON, HTML, and a small dependency-free PDF containing the
  evidence inventory, hashes, physical/payload ranges, normalized timeline,
  analytics status, audit chain, and a jurisdiction-review checklist. The
  report never certifies legal admissibility.
- **Browser workstation and CLI** — both use the same engine and storage
  layer. The web UI is served by Python's standard library HTTP server.

## Quick start

Python 3.10 or newer is required. The standard install includes NumPy,
OpenCV headless, and a packaged FFmpeg fallback. Verified NanoDet and YuNet
models are downloaded automatically on first analytics use when the workstation
has network access; no model path needs to be supplied.

```bash
python3 -m pip install -e .
# Start the local workstation. Bind to 0.0.0.0 for a LAN/container preview.
python3 -m forensic_tool --data-dir data serve --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>. The browser workflow is:

1. Create an examination.
2. Acquire an image from the **Acquire evidence** tab.
3. Select the source under **Analyze & recover** and run identification.
4. Choose normal, deleted, overwritten, fragmented, or unallocated-space recovery.
5. Export exact native bytes or a parser-bounded media payload, synchronize the timeline, and run analytics.
6. Verify source hashes and generate the report package.

No source image is included in this repository. The tests use small in-memory
byte fixtures; they are not claims of field validation against every recorder
firmware variant.

### SIH26150 controlled validation

Run the reproducible end-to-end recorder-image emulator from the repository
root:

```bash
python3 tools/sih26150_emulation.py
```

It creates a temporary evidence image containing a compact Annex-B H.264
sequence inside common-layout DHAV frames, interleaves two channels, includes a
malformed frame and raw deleted candidate, then verifies acquisition hashes,
model/firmware candidates, all recovery postures, exact native/payload export,
timestamps, custody, reporting, and explicit analytics status. This is a
regression gate for the workflow, not a substitute for an authorized physical
image from a named DVR/NVR model. Field validation still requires real images;
unsupported proprietary payloads remain explicit rather than being treated as
decoded footage.

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
python3 -m forensic_tool --data-dir data correlate CASE-XXXXXXXXXX
python3 -m forensic_tool --data-dir data verify EVD-XXXXXXXXXXXX
python3 -m forensic_tool --data-dir data export SEG-XXXXXXXXXXXX --format media
python3 -m forensic_tool --data-dir data capabilities
python3 -m forensic_tool --data-dir data analytics SEG-XXXXXXXXXXXX --kind motion
python3 -m forensic_tool --data-dir data report CASE-XXXXXXXXXX
```

`data/` contains the SQLite database, acquired evidence, native exports, and
report artifacts. It is ignored by Git. Use a separate, access-controlled
volume for real examinations.

### Analytics model and decoder behavior

The first object or face run downloads a fixed, hash-verified model into
`data/models/` (or `SENTINEL_MODEL_DIR` when set). The result records the model
name, source URL, expected and actual SHA-256, license, decoder, and derived
artifact hash. This keeps model provenance separate from immutable evidence.

- Object analytics use OpenCV Zoo NanoDet over the COCO classes by default.
- Face indexing uses YuNet by default, then the OpenCV-bundled Haar cascade if
  the model cannot be fetched or the examination is offline.
- Motion uses frame-difference regions and does not assert what caused a change.
- A packaged FFmpeg fallback broadens decoding beyond OpenCV's native backend;
  system FFmpeg takes precedence when installed.
- Set `SENTINEL_AUTO_DOWNLOAD_MODELS=0` for an offline lab. The deterministic
  fallbacks remain available and the result says exactly which model was not
  used. Set `SENTINEL_MODEL_DIR` to a controlled, pre-approved model cache.

Face results intentionally remain detection/index records. Sentinel does not
perform face recognition, name a person, or make a biometric identity claim.
That boundary is deliberate for forensic accuracy and privacy.

## API surface

The web server exposes a small JSON API used by the UI:

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Engine health/version and optional capability status |
| `GET` | `/api/capabilities` | Decoder/model availability without fabricating findings |
| `GET/POST` | `/api/cases` | List or create cases |
| `GET` | `/api/cases/{case_id}` | Case bundle, evidence, findings, audit |
| `POST` | `/api/cases/{case_id}/evidence` | Stream raw bytes; pass `X-Filename`, optional source-kind/sector query metadata |
| `GET` | `/api/evidence/{evidence_id}` | Source metadata, identification, segments, analytics |
| `POST` | `/api/evidence/{evidence_id}/identify` | Run bounded vendor/model/firmware identification |
| `POST` | `/api/evidence/{evidence_id}/recover` | JSON `{ "mode": "normal" }` or deleted/overwritten/fragmented/unallocated |
| `GET` | `/api/evidence/{evidence_id}/integrity` | Re-hash MD5/SHA-256 and append verification event |
| `GET` | `/api/evidence/{evidence_id}/timeline` | Normalize one source timeline |
| `GET` | `/api/cases/{case_id}/timeline` | Cross-camera correlation; optional `?tolerance=2` |
| `GET` | `/api/segments/{segment_id}/export?format=native|media` | Download exact native or parser-bounded payload |
| `POST` | `/api/segments/{segment_id}/analytics` | JSON `{ "kind": "motion|object|face", "model": "" }` |
| `POST` | `/api/cases/{case_id}/report` | Build JSON, HTML, and PDF report artifacts |
| `GET` | `/api/cases/{case_id}/report.html/.pdf/.json` | Download a report |

The default upload limit is intentionally large for disk images but can be
changed by constructing `SentinelApp(max_upload_bytes=...)` when embedding the
server. Model licenses, sources, and fixed hashes are listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

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
     ├── Exporter ── exact native range, parser-bounded payload, FFmpeg remux fallback
     ├── Timeline ── UTC normalization and conservative cross-camera correlation
     ├── Analytics ── verified COCO/YuNet models, decoder fallback, explicit status
     └── Reporter ── JSON / HTML / PDF + hashes, checklist, verified custody chain
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

The tests cover cross-chunk signature detection, acquisition hashes, source
metadata and migrations, vendor/model/firmware candidates, bounded DHAV
payload parsing, deleted/overwritten/fragmented/unallocated recovery labels,
exact native and demuxed export, timestamp correlation, explicit analytics
availability states, report checklists, and tamper detection in the custody
chain.
