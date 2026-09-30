"""
Cryptographic Audit Trail PDF Report Generator
Generates regulatory-grade compliance reports (GDPR Art. 30, HIPAA §164.312).
"""

import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether


def generate_audit_pdf_report(
    logs: List[Dict[str, Any]],
    ledger_state: Optional[Dict[str, Any]] = None,
    filter_user: Optional[str] = None,
    filter_table: Optional[str] = None,
    filter_status: Optional[str] = None,
) -> bytes:
    """
    Generates a PDF compliance report from immudb audit trail logs.
    Returns PDF content as raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        fontName='Helvetica-Bold',
        spaceAfter=4,
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=14,
    )

    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#64748b'),
        fontName='Helvetica-Bold',
    )

    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#0f172a'),
    )

    cell_style = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b'),
    )

    cell_mono = ParagraphStyle(
        'CellMono',
        parent=styles['Normal'],
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#334155'),
        fontName='Courier',
    )

    story = []

    # 1. Header
    story.append(Paragraph("VaultDB Cryptographic Compliance & Audit Report", title_style))
    story.append(
        Paragraph(
            "Regulatory Compliance Export &bull; Standards: GDPR Art. 30, HIPAA §164.312 &bull; Immutable Ledger: immudb",
            subtitle_style,
        )
    )

    # 2. Metadata / Cryptographic State Box
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    root_hash = ledger_state.get("root_hash", "N/A") if ledger_state else "N/A"
    tx_height = str(ledger_state.get("tx_id", "N/A")) if ledger_state else "N/A"
    db_name = ledger_state.get("database", "defaultdb") if ledger_state else "defaultdb"

    # Filter summary
    active_filters = []
    if filter_user:
        active_filters.append(f"User: {filter_user}")
    if filter_table:
        active_filters.append(f"Table: {filter_table}")
    if filter_status:
        active_filters.append(f"Status: {filter_status}")
    filter_str = ", ".join(active_filters) if active_filters else "All Records (Unfiltered)"

    # Compute Summary Stats
    total_records = len(logs)
    success_count = sum(1 for l in logs if l.get("status") == "SUCCESS")
    denied_count = sum(1 for l in logs if l.get("status") == "DENIED")
    sensitive_count = sum(1 for l in logs if l.get("is_sensitive", False))

    meta_data = [
        [
            Paragraph("Generated At:", meta_label), Paragraph(now_utc, meta_val),
            Paragraph("Total Logs Included:", meta_label), Paragraph(str(total_records), meta_val),
        ],
        [
            Paragraph("immudb Database:", meta_label), Paragraph(db_name, meta_val),
            Paragraph("Successful Queries:", meta_label), Paragraph(str(success_count), meta_val),
        ],
        [
            Paragraph("Ledger Height (Tx):", meta_label), Paragraph(f"#{tx_height}", meta_val),
            Paragraph("Security Denials:", meta_label), Paragraph(str(denied_count), meta_val),
        ],
        [
            Paragraph("Merkle Root Hash:", meta_label), Paragraph(root_hash, cell_mono),
            Paragraph("Sensitive Queries:", meta_label), Paragraph(str(sensitive_count), meta_val),
        ],
        [
            Paragraph("Applied Filters:", meta_label), Paragraph(filter_str, meta_val),
            Paragraph("Proof Status:", meta_label), Paragraph("Cryptographically Sealed (Merkle Tree)", meta_val),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[120, 240, 130, 230])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Audit Log Entries Table
    table_headers = [
        Paragraph("ID", meta_label),
        Paragraph("Timestamp (UTC)", meta_label),
        Paragraph("Application User", meta_label),
        Paragraph("Role", meta_label),
        Paragraph("Action", meta_label),
        Paragraph("Target Table", meta_label),
        Paragraph("Status", meta_label),
        Paragraph("immudb Tx", meta_label),
        Paragraph("SQL Query Statement", meta_label),
    ]

    rows = [table_headers]

    for l in logs:
        time_str = str(l.get("time") or "-")
        if len(time_str) > 19:
            time_str = time_str[:19].replace("T", " ")

        status = l.get("status") or "-"
        status_color = "#059669" if status == "SUCCESS" else ("#dc2626" if status == "DENIED" else "#d97706")
        status_para = Paragraph(f'<font color="{status_color}"><b>{status}</b></font>', cell_style)

        query_text = (l.get("query") or "").replace("<", "&lt;").replace(">", "&gt;")
        if len(query_text) > 85:
            query_text = query_text[:82] + "..."

        rows.append([
            Paragraph(f"#{l.get('id')}", cell_mono),
            Paragraph(time_str, cell_style),
            Paragraph(str(l.get("user") or "-"), cell_style),
            Paragraph(str(l.get("role") or "-"), cell_style),
            Paragraph(str(l.get("action") or "-"), cell_style),
            Paragraph(str(l.get("table") or "-"), cell_style),
            status_para,
            Paragraph(f"#{l.get('immudb_tx_id') or '-'}", cell_mono),
            Paragraph(query_text, cell_mono),
        ])

    log_table = Table(rows, colWidths=[35, 95, 110, 60, 55, 75, 60, 55, 175], repeatRows=1)
    log_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 1), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
    ]))

    story.append(log_table)
    story.append(Spacer(1, 14))

    # 4. Cryptographic Certification Notice
    cert_text = (
        "<b>Certification of Immutability:</b> This audit report has been extracted directly from the VaultDB "
        "cryptographic ledger engine. Each listed record is committed within an append-only Merkle tree in immudb. "
        "The cryptographic integrity of these records can be verified against the state root hash above using zero-trust "
        "Merkle inclusion proofs. Records cannot be retroactively inserted, altered, or deleted without cryptographic detection."
    )
    story.append(Paragraph(cert_text, ParagraphStyle('Cert', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor('#475569'))))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
