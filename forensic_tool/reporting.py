"""Reproducible HTML, JSON, and dependency-free PDF examination reports."""

from __future__ import annotations

import html
import json
import os
import textwrap
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List

from . import __version__
from .storage import EvidenceStore, utc_now


def build_report(store: EvidenceStore, case_id: str) -> Dict[str, Any]:
    bundle = store.case_bundle(case_id)
    return {
        "report_type": "DVR/NVR forensic examination report",
        "generated_at": utc_now(),
        "tool": {"name": "Sentinel Forensic Analysis Tool", "version": __version__},
        "case": bundle["case"],
        "evidence": bundle["evidence"],
        "chain_of_custody": bundle["chain"],
        "audit_log": bundle["audit"],
        "interpretation": [
            "This report records observations and physical byte ranges produced by the open-source examination engine.",
            "Vendor signatures and carved media are investigative findings; they are not, by themselves, proof of recorder identity, deletion, authorship, or event time.",
            "The original acquired bytes remain unchanged. Native exports are exact source ranges; any optional remux is separately identified.",
        ],
    }


def write_report(store: EvidenceStore, case_id: str) -> Dict[str, Any]:
    store.record_audit(case_id, "report_generated", {"formats": ["json", "html", "pdf"]})
    report = build_report(store, case_id)
    json_path = store.report_path(case_id, ".json")
    html_path = store.report_path(case_id, ".html")
    pdf_path = store.report_path(case_id, ".pdf")
    _atomic_write(json_path, json.dumps(report, indent=2, sort_keys=True).encode("utf-8"))
    _atomic_write(html_path, render_html(report).encode("utf-8"))
    _atomic_write(pdf_path, render_pdf(report))
    return {
        "case_id": case_id,
        "json": str(json_path),
        "html": str(html_path),
        "pdf": str(pdf_path),
        "chain": report["chain_of_custody"],
        "generated_at": report["generated_at"],
    }


def _atomic_write(path: Path, payload: bytes) -> None:
    """Replace a read-only report atomically without opening it for update."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(payload)
        try:
            temporary.chmod(0o440)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def render_html(report: Dict[str, Any]) -> str:
    case = report["case"]
    evidence = report["evidence"]
    rows: List[str] = []
    for item in evidence:
        identity = item.get("identification") or {}
        vendor = identity.get("primary_vendor", "not run")
        confidence = identity.get("confidence")
        label = f"{vendor} ({confidence:.0%})" if isinstance(confidence, (int, float)) else vendor
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['id'])}</td>"
            f"<td>{html.escape(item['original_name'])}</td>"
            f"<td>{item['size']:,}</td>"
            f"<td><code>{html.escape(item['sha256'])}</code></td>"
            f"<td>{html.escape(label)}</td>"
            f"<td>{len(item.get('segments', []))}</td>"
            "</tr>"
        )
    audit_rows = []
    for event in report["audit_log"]:
        audit_rows.append(
            "<tr>"
            f"<td>{event['id']}</td><td>{html.escape(event['occurred_at'])}</td>"
            f"<td>{html.escape(event['action'])}</td>"
            f"<td><code>{html.escape(event['event_hash'])}</code></td></tr>"
        )
    interpretations = "".join(f"<li>{html.escape(line)}</li>" for line in report["interpretation"])
    chain = report["chain_of_custody"]
    chain_label = "VALID" if chain.get("valid") else "BROKEN"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Forensic report — {html.escape(case['id'])}</title>
<style>
body{{font:14px/1.5 Arial,sans-serif;color:#17212b;margin:40px;max-width:1200px}}h1{{margin-bottom:4px}}h2{{border-bottom:2px solid #d8e0e8;padding-bottom:6px;margin-top:32px}}.meta{{color:#52616d}}.badge{{display:inline-block;padding:4px 9px;border-radius:99px;background:{'#dff7ec' if chain.get('valid') else '#ffe4e4'};color:{'#12613d' if chain.get('valid') else '#9b1c1c'};font-weight:700}}table{{border-collapse:collapse;width:100%;margin:12px 0}}th,td{{border:1px solid #d8e0e8;padding:8px;text-align:left;vertical-align:top}}th{{background:#f1f5f8}}code{{font-size:11px;word-break:break-all}}footer{{margin-top:40px;color:#647583;font-size:12px}}
</style></head><body>
<h1>Sentinel forensic examination report</h1>
<div class="meta"><strong>{html.escape(case['id'])}</strong> · {html.escape(case['title'])}<br>
Investigator: {html.escape(case.get('investigator') or 'Not specified')} · Generated: {html.escape(report['generated_at'])}<br>
Chain of custody: <span class="badge">{chain_label}</span> ({chain.get('event_count', 0)} events)</div>
<h2>Scope and interpretation</h2><ul>{interpretations}</ul>
<h2>Evidence inventory</h2><table><thead><tr><th>ID</th><th>Acquired name</th><th>Bytes</th><th>SHA-256</th><th>Identification</th><th>Segments</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="6">No evidence acquired.</td></tr>'}</tbody></table>
<h2>Audit chain</h2><table><thead><tr><th>#</th><th>UTC</th><th>Action</th><th>Event hash</th></tr></thead><tbody>{''.join(audit_rows) or '<tr><td colspan="4">No events.</td></tr>'}</tbody></table>
<footer>Sentinel {html.escape(report['tool']['version'])}. This technical report is a record of tool observations and does not make a legal admissibility determination.</footer>
</body></html>"""


def render_pdf(report: Dict[str, Any]) -> bytes:
    """Write a small valid PDF with text, without requiring reportlab."""

    case = report["case"]
    chain = report["chain_of_custody"]
    lines: List[str] = [
        "SENTINEL FORENSIC EXAMINATION REPORT",
        f"Case: {case['id']}  {case['title']}",
        f"Investigator: {case.get('investigator') or 'Not specified'}",
        f"Generated UTC: {report['generated_at']}",
        f"Chain of custody: {'VALID' if chain.get('valid') else 'BROKEN'} ({chain.get('event_count', 0)} events)",
        "",
        "EVIDENCE INVENTORY",
    ]
    for item in report["evidence"]:
        identity = item.get("identification") or {}
        lines.extend(
            [
                f"{item['id']}  {item['original_name']}  {item['size']} bytes",
                f"MD5    {item['md5']}",
                f"SHA256 {item['sha256']}",
                f"Vendor {identity.get('primary_vendor', 'not run')}  segments={len(item.get('segments', []))}",
                "",
            ]
        )
    lines.extend(["INTERPRETATION", *report["interpretation"], "", "This report records tool observations; it is not a legal opinion."])
    return _pdf_from_lines(lines)


def _pdf_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_from_lines(lines: Iterable[str]) -> bytes:
    # Keep a readable report on multiple pages.  Each page is an independent
    # content stream; the catalog/pages/font objects are assembled manually.
    normalized: List[str] = []
    for line in lines:
        normalized.extend(textwrap.wrap(str(line), width=105) or [""])
    page_lines = 48
    pages = [normalized[index : index + page_lines] for index in range(0, len(normalized), page_lines)] or [[]]
    objects: List[bytes] = []
    # object 1 catalog, 2 pages, 3 font, then page/content pairs
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_object_numbers = []
    content_object_numbers = []
    next_number = 4
    for _page in pages:
        page_object_numbers.append(next_number)
        content_object_numbers.append(next_number + 1)
        next_number += 2
    kids = " ".join(f"{number} 0 R" for number in page_object_numbers)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for index, page in enumerate(pages):
        page_number = page_object_numbers[index]
        content_number = content_object_numbers[index]
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_number} 0 R >>".encode()
        )
        commands = ["BT", "/F1 9 Tf", "48 750 Td", "12 TL"]
        for line in page:
            commands.append(f"({_pdf_escape(line[:180])}) Tj")
            commands.append("0 -12 TD")
        commands.append("ET")
        stream = "\n".join(commands).encode("latin-1", errors="replace")
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(output)
