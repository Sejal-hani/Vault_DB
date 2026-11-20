"""
Generates the publication-grade CSE3103 Project Report PDF using ReportLab.
Produces docs/CSE3103_VaultDB_Report.pdf and copies to root CSE3103_VaultDB_Report.pdf.
"""

import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    PageBreak,
    HRFlowable,
)
from reportlab.pdfgen import canvas

BASE_DIR = Path(__file__).resolve().parent.parent
PDF_PATH_DOCS = BASE_DIR / "docs" / "CSE3103_VaultDB_Report.pdf"
PDF_PATH_ROOT = BASE_DIR / "CSE3103_VaultDB_Report.pdf"
DOCX_PATH_DOCS = BASE_DIR / "docs" / "CSE3103_VaultDB_Report.docx"
DOCX_PATH_ROOT = BASE_DIR / "CSE3103_VaultDB_Report.docx"


class NumberedCanvas(canvas.Canvas):
    """Adds running headers and footers with 'Page X of Y' numbering."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "CSE3103 Project Report: VaultDB — Zero-Trust Database Security Middleware")
            self.drawRightString(558, 750, "Development Track")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Running Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, page_str)
        self.drawString(54, 36, "BML Munjal University — School of Engineering and Technology — Release v1.0-report")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 46, 558, 46)

        self.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        str(PDF_PATH_DOCS),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        alignment=1,  # Center
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#334155'),
        alignment=1,
        spaceAfter=10,
    )
    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#475569'),
        alignment=1,
        spaceAfter=14,
    )
    h1_style = ParagraphStyle(
        'H1Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=6,
        alignment=4,  # Justified
    )
    bullet_style = ParagraphStyle(
        'BulletStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#1e293b'),
        leftIndent=12,
        spaceAfter=3,
    )
    th_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white,
    )
    td_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#0f172a'),
    )
    td_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#0f172a'),
    )
    caption_style = ParagraphStyle(
        'CaptionStyle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#334155'),
        spaceBefore=6,
        spaceAfter=4,
        keepWithNext=True,
    )
    callout_box = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#475569'),
    )

    story = []

    # Title & Header
    story.append(Paragraph("CSE3103 Project Report: VaultDB", title_style))
    story.append(Paragraph("An Enterprise Zero-Trust Database Security Middleware and Cryptographically Verifiable Audit Ledger", subtitle_style))
    story.append(Paragraph(
        "<b>Course:</b> CSE3103: Applied Databases & Systems Thinking &nbsp;|&nbsp; <b>Track:</b> Development Track<br/>"
        "<b>Authors:</b> Somya Tomar, Vani Shrivastava, Sejal Patil &nbsp;|&nbsp; <b>Institution:</b> School of Engineering and Technology, BML Munjal University<br/>"
        "<b>Repository:</b> <font color='#2563eb'>https://github.com/Sejal-hani/Vault_DB</font> &nbsp;|&nbsp; <b>Release Tags:</b> v1.0-report / v1.1-report (Release v1.1) &nbsp;|&nbsp; <b>Commit:</b> c20e0ce",
        meta_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

    # Abstract Box
    abs_text = (
        "<b>Abstract—</b> In regulated enterprise environments governed by mandates such as GDPR (Articles 15 & 30), HIPAA (§164.312), and PCI-DSS (Requirement 10.2), "
        "proving the authenticity of database transactions while preventing insider tampering remains a critical systems challenge. "
        "Traditional relational logging mechanisms remain fundamentally vulnerable to rogue administrative tampering (<code>DELETE FROM audit_logs</code>), "
        "client-side identity spoofing, and forensic blind spots during access denials. "
        "To address these vulnerabilities, we design and implement <b>VaultDB</b>, an enterprise-grade, zero-trust database security middleware and cryptographic audit ledger. "
        "Positioned as an inline proxy between client applications and database infrastructure, VaultDB intercepts SQL queries at the Abstract Syntax Tree (AST) level, "
        "derives authenticated caller identities server-side via RFC 7519 HMAC-SHA256 tokens and PBKDF2 hashing, enforces fine-grained Role-Based Access Control (RBAC), "
        "applies dynamic customer Row-Level Security (RLS), redacts sensitive PII in flight, and commits every transaction attempt simultaneously to a PostgreSQL relational mirror "
        "and an append-only immudb Merkle tree ledger. "
        "We conduct a rigorous empirical benchmark over 15,000 queries across 5 repeated runs with a 50-query warmup. Under a mixed enterprise banking workload of 1,000 queries per run, "
        "VaultDB achieves a median (P50) latency of <b>3.22 ms</b> and an average throughput of <b>322.0 queries/second</b>, introducing an average overhead of only <b>0.82 ms</b> over pgAudit "
        "and <b>1.58 ms</b> over uninstrumented PostgreSQL. In exchange for this nominal overhead, VaultDB delivers complete cryptographic tamper-proofing with SHA-256 Merkle inclusion proofs, "
        "automated database corruption detection, and zero false-negative attack interception across 160 automated test cases.<br/><br/>"
        "<i><b>Index Terms—</b>Database Security, Zero-Trust Architecture, Cryptographic Audit Ledger, Merkle Tree, immudb, Row-Level Security, Dynamic Data Masking, pgAudit, Regulatory Compliance.</i>"
    )
    abs_table = Table([[Paragraph(abs_text, body_style)]], colWidths=[504])
    abs_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(abs_table)
    story.append(Spacer(1, 12))

    # 1. Introduction
    story.append(Paragraph("1. Introduction", h1_style))
    story.append(Paragraph(
        "Modern enterprise software architectures increasingly decouple client frontends, microservices, and database tiers. "
        "In high-stakes domains such as banking, electronic health records (EHR), and payments, organizational compliance frameworks require an irrefutable audit trail "
        "answering: <i>who accessed what data, at what exact wall-clock timestamp, and under what organizational authority?</i>",
        body_style
    ))
    story.append(Paragraph(
        "Despite extensive database hardening guidelines, traditional relational database management systems (RDBMS) suffer from three fundamental architectural flaws:",
        body_style
    ))
    story.append(Paragraph("<b>1. The Rogue DBA & Insider Threat:</b> Audit tables residing within standard relational engines remain subject to modification by privileged accounts. A database administrator (DBA) or an adversary possessing compromised root credentials can execute <code>DELETE FROM audit_logs</code> or manipulate historical timestamps without leaving an evidentiary trace in the database itself.", bullet_style))
    story.append(Paragraph("<b>2. Client-Side Identity Spoofing:</b> Traditional connection pools connect under a generic service account. When client queries declare user context via application headers or session parameters, malicious actors can spoof identity declarations to evade personal accountability or escalate privileges.", bullet_style))
    story.append(Paragraph("<b>3. Forensic Blind Spots:</b> Relational triggers fire exclusively on successful modifications. Unauthorized reconnaissance attempts, cross-tenant data snooping, and blocked stacked SQL injection attacks are discarded prior to execution, creating forensic blind spots for security teams.", bullet_style))
    story.append(Paragraph(
        "Existing practices like <code>pgAudit</code> write unindexed plaintext statements to operating system syslog files. While fast, pgAudit logs are completely mutable, "
        "lack cryptographic integrity proofs, and cannot actively rewrite queries or mask Personally Identifiable Information (PII) before results reach the client.",
        body_style
    ))
    story.append(Paragraph("<b>Key Technical Contributions:</b>", h2_style))
    story.append(Paragraph("<b>• Dual-Storage Synchronized Ledger:</b> An architecture coupling PostgreSQL for indexable business data with immudb for append-only, cryptographic Merkle tree audit logging.", bullet_style))
    story.append(Paragraph("<b>• Zero-Trust AST Firewall:</b> Pre-execution SQL query inspection that blocks multi-statement stacked injections and unprivileged DDL.", bullet_style))
    story.append(Paragraph("<b>• Server-Derived Identity:</b> Caller identities resolved strictly via signed RFC 7519 JWT tokens and PBKDF2 hashing, ignoring client parameter claims.", bullet_style))
    story.append(Paragraph("<b>• Dynamic Customer RLS & Masking:</b> Automated AST query rewriting isolating customer tenant records and redacting Social Security Numbers (***-**-XXXX) in flight.", bullet_style))
    story.append(Paragraph("<b>• Empirical Performance Benchmarking:</b> Rigorous multi-run testing over 15,000 queries proving that VaultDB introduces an overhead of only 0.82 ms over pgAudit.", bullet_style))

    # 2. Background and Related Work
    story.append(Paragraph("2. Background and Related Work", h1_style))
    story.append(Paragraph(
        "VaultDB builds upon foundational database and cryptographic systems concepts: Write-Ahead Logging (WAL) for ACID durability, "
        "Merkle Trees for cryptographic non-repudiation, and proxy middleware for pre-execution query rewriting.",
        body_style
    ))
    story.append(Paragraph(
        "A <b>Merkle tree</b> is an append-only binary tree where leaf nodes store data hashes and intermediate nodes store hashes of child nodes. "
        "The cryptographic state of the entire ledger is summarized in a single 32-byte <b>Merkle Root Hash</b>. Any unauthorized tampering with a historical leaf record permanently invalidates the root hash, providing $\\mathcal{O}(\\log N)$ mathematical inclusion proofs.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Survey of Existing Solutions:</b><br/>"
        "• <b>pgAudit [1]:</b> Standard PostgreSQL audit extension. Intercepts queries at the executor hook level and appends plaintext records to syslog. Does not provide cryptographic tamper resistance, PII masking, or tenant query rewriting.<br/>"
        "• <b>Debezium [2]:</b> Change Data Capture platform reading from PostgreSQL WAL. Captures committed database mutations but cannot inspect SELECT queries, unauthorized access denials, or blocked injection attempts.<br/>"
        "• <b>Vitess [3]:</b> Database clustering and sharding proxy for MySQL. Provides query routing, but lacks cryptographic non-repudiation and regulatory compliance reporting.<br/>"
        "• <b>immudb [4]:</b> Cryptographic append-only database. VaultDB uniquely bridges immudb with PostgreSQL, serving as an intelligent relational firewall that automatically mirrors and verifies data across both engines.",
        body_style
    ))

    # 3. Requirements Specification
    story.append(Paragraph("3. Requirements Specification", h1_style))
    story.append(Paragraph("Table 1 summarizes the functional requirements mandated for the V1 development scope, while Table 2 outlines the non-functional performance benchmarks.", body_style))

    story.append(Paragraph("Table 1: Functional Requirements (FR) Specification", caption_style))
    t1_data = [
        [Paragraph("Req ID", th_style), Paragraph("Requirement Name", th_style), Paragraph("Technical Specification", th_style), Paragraph("Status", th_style)],
        [Paragraph("FR1", td_bold), Paragraph("Query Interception", td_style), Paragraph("Intercept SQL queries; capture user, query text, timestamp, table, and status.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR2", td_bold), Paragraph("Immutable Ledger", td_style), Paragraph("Commit audit records to append-only store; reject updates/deletes even by admin.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR3", td_bold), Paragraph("Access Control (RBAC)", td_style), Paragraph("Enforce authorization across admin, writer, and reader roles at the proxy tier.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR4", td_bold), Paragraph("Audit Dashboard", td_style), Paragraph("Single-page web workstation displaying query trails with user, table, and date filters.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR5", td_bold), Paragraph("Sensitive Detection", td_style), Paragraph("Detect sensitive fields (SSN, credit card, passwords) and flag in red alert badge.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR6", td_bold), Paragraph("Compliance PDF Export", td_style), Paragraph("Export certified compliance PDF reports with audit history and Merkle state roots.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR7", td_bold), Paragraph("High-Volume Testing", td_style), Paragraph("Validate stability and latency on PostgreSQL under 1,000+ query workloads.", td_style), Paragraph("Complete (100%)", td_bold)],
    ]
    t1 = Table(t1_data, colWidths=[45, 110, 245, 104])
    t1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t1)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Table 2: Non-Functional Requirements (NFR) and Threshold Targets", caption_style))
    t2_data = [
        [Paragraph("NFR ID", th_style), Paragraph("Non-Functional Metric", th_style), Paragraph("Target SLA Threshold", th_style), Paragraph("Realized Performance", th_style)],
        [Paragraph("NFR1", td_bold), Paragraph("Middleware Latency Overhead", td_style), Paragraph("Average overhead < 5.0 ms per query", td_style), Paragraph("1.58 ms overhead (3.13 ms total)", td_bold)],
        [Paragraph("NFR2", td_bold), Paragraph("Throughput Scalability", td_style), Paragraph("Sustained throughput >= 200 QPS", td_style), Paragraph("322.0 QPS sustained", td_bold)],
        [Paragraph("NFR3", td_bold), Paragraph("Tamper Detection Accuracy", td_style), Paragraph("100% detection (zero false negatives)", td_style), Paragraph("100% detection rate", td_bold)],
        [Paragraph("NFR4", td_bold), Paragraph("High-Volume Ledger Scaling", td_style), Paragraph("Support histories > 50,000 records", td_style), Paragraph("Tested up to 100,000+ entries", td_bold)],
    ]
    t2 = Table(t2_data, colWidths=[45, 150, 150, 159])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t2)

    # 4. Architecture and Design
    story.append(Paragraph("4. Architecture and System Design", h1_style))
    story.append(Paragraph(
        "VaultDB operates as a modular, layered security architecture positioned between consumer applications and database engines. "
        "Every incoming query traverses through five decoupled stages: Authentication, AST Parsing & Firewalls, Policy & Governance, "
        "PostgreSQL Relational Execution, and immudb Cryptographic Merkle Sealing.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Key Design Decisions and Alternatives Rejected:</b><br/>"
        "• <b>Dual-Store Ledger vs. PostgreSQL Alone:</b> We paired PostgreSQL with immudb. PostgreSQL provides B-tree indexed searching, sorting, and pagination for dashboard queries. "
        "immudb provides an append-only Merkle tree ledger that mathematically guarantees non-repudiation. Storing audit logs solely in PostgreSQL was rejected because database administrators can bypass relational constraints.<br/>"
        "• <b>Server-Derived Identity vs. Client Session Claims:</b> Client requests are forbidden from declaring identity parameters (e.g. {'user': 'alice'}). All identities are derived server-side from cryptographic signatures, eliminating client identity spoofing.<br/>"
        "• <b>AST Dynamic Scoping vs. Database Views:</b> Dynamic AST query rewriting was chosen over creating separate database views per customer. Creating thousands of views in a multi-tenant banking database introduces catalog lock contention and schema maintenance bloat.",
        body_style
    ))

    # 5. Implementation Details
    story.append(Paragraph("5. Implementation Details", h1_style))
    story.append(Paragraph(
        "VaultDB is built with Python 3.12, FastAPI 0.115, Psycopg 3.3 connection pooling, and immudb 1.5.<br/>"
        "<b>The Three Hardest Engineering Challenges Solved:</b><br/>"
        "1. <b>Atomic Dual-Commit Synchronization:</b> Ensuring that transaction sequence IDs in PostgreSQL strictly matched the linear transaction height of immudb under concurrent writes. Solved by combining the monotonic counter key (<code>audit:counter</code>) and the audit log record in a single atomic immudb transaction (<code>client.setAll</code>).<br/>"
        "2. <b>Boundary-Aware SQL Predicate Injection:</b> Appending tenant boundaries (<code>WHERE user_id = ...</code>) without breaking queries containing existing WHERE conditions, GROUP BY, ORDER BY, and LIMIT clauses. Solved by an AST regex splitter that isolates query suffixes and safely encapsulates conditions: <code>WHERE (existing_condition) AND (scope_clause)</code>.<br/>"
        "3. <b>Dynamic PII Masking and Secret Suppression:</b> Preventing credential leakage (<code>password_hash</code>, <code>api_key</code>) while dynamically decrypting AES-256-GCM ciphertexts and masking SSNs to '***-**-1234' for non-admin personas. Solved via a dual-pass columnar stripping algorithm in <code>src/vault_db/core/masking.py</code>.",
        body_style
    ))

    story.append(Paragraph("Table 3: Feature Implementation Status (V1 and V2 Scope)", caption_style))
    t3_data = [
        [Paragraph("Scope", th_style), Paragraph("Feature Description", th_style), Paragraph("Target Module", th_style), Paragraph("Status", th_style)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Query Interception Proxy", td_style), Paragraph("src/vault_db/core/engine.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Immutable Merkle Ledger", td_style), Paragraph("src/vault_db/storage/immudb_vault.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Database Immutability Triggers", td_style), Paragraph("db/schema.sql", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Role-Based Access Control", td_style), Paragraph("src/vault_db/core/rbac.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Web Workstation Console", td_style), Paragraph("templates/index.html, app.js", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Sensitive Field Detection", td_style), Paragraph("src/vault_db/core/parser.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Compliance PDF Exporter", td_style), Paragraph("src/vault_db/reports/pdf_generator.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("1,000+ Query Benchmark Suite", td_style), Paragraph("scripts/benchmark_1000_queries.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V2 Bonus", td_bold), Paragraph("Dynamic In-Flight Masking", td_style), Paragraph("src/vault_db/core/masking.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V2 Bonus", td_bold), Paragraph("Row-Level Tenant Isolation", td_style), Paragraph("src/vault_db/core/rls.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V2 Bonus", td_bold), Paragraph("24h JIT Privilege Elevation", td_style), Paragraph("src/vault_db/core/approval.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V2 Bonus", td_bold), Paragraph("Behavioral Anomaly Detection", td_style), Paragraph("src/vault_db/core/anomaly.py, alerts.py", td_style), Paragraph("100% Complete", td_bold)],
    ]
    t3 = Table(t3_data, colWidths=[65, 160, 175, 104])
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t3)

    # 6. Testing, Verification, and Evaluation
    story.append(Paragraph("6. Testing, Verification, and Evaluation", h1_style))
    story.append(Paragraph(
        "<b>Adversarial Attack Suite (160 Tests):</b><br/>"
        "VaultDB was tested against an automated suite of 160 unit, integration, and security exploit tests in <code>tests/</code>. "
        "Over 100 adversarial SQL attack strings were executed, verifying complete protection against stacked statement injections (<code>SELECT 1; DROP TABLE users;</code>), "
        "Common Table Expression (CTE) write attacks, shell command injection via <code>COPY TO/FROM PROGRAM</code>, and out-of-band audit trail mutation.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Empirical Benchmark Evaluation (VaultDB vs. pgAudit):</b><br/>"
        "We executed a controlled benchmark comparing Raw PostgreSQL, PostgreSQL with pgAudit, and VaultDB Middleware. "
        "The benchmark processed 1,000 enterprise banking queries per run across 5 repeated runs (15,000 queries total) with a 50-query warmup. "
        "The empirical results are summarized in Table 4.",
        body_style
    ))

    story.append(Paragraph("Table 4: Empirical Benchmark Results (Mean, Percentiles, and Throughput)", caption_style))
    t4_data = [
        [Paragraph("Configuration", th_style), Paragraph("Mean Latency", th_style), Paragraph("Std Dev", th_style), Paragraph("P50 Median", th_style), Paragraph("P95 Tail", th_style), Paragraph("Throughput", th_style), Paragraph("Overhead", th_style)],
        [Paragraph("Raw PostgreSQL (Baseline)", td_bold), Paragraph("1.55 ms", td_style), Paragraph("±0.06 ms", td_style), Paragraph("1.54 ms", td_style), Paragraph("1.67 ms", td_style), Paragraph("641.3 QPS", td_bold), Paragraph("0.00 ms (Base)", td_style)],
        [Paragraph("PostgreSQL + pgAudit", td_bold), Paragraph("2.31 ms", td_style), Paragraph("±0.18 ms", td_style), Paragraph("2.15 ms", td_style), Paragraph("2.74 ms", td_style), Paragraph("431.0 QPS", td_bold), Paragraph("+0.76 ms", td_style)],
        [Paragraph("VaultDB Middleware", td_bold), Paragraph("3.13 ms", td_style), Paragraph("±0.64 ms", td_style), Paragraph("3.22 ms", td_style), Paragraph("4.55 ms", td_style), Paragraph("322.0 QPS", td_bold), Paragraph("+1.58 ms", td_bold)],
    ]
    t4 = Table(t4_data, colWidths=[130, 60, 60, 60, 60, 74, 60])
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t4)
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "<b>Performance & Trade-Off Analysis:</b><br/>"
        "• <b>Overhead of VaultDB vs. pgAudit:</b> <b>0.82 ms</b> average delta.<br/>"
        "• <b>Overhead of VaultDB vs. Raw PostgreSQL:</b> <b>1.58 ms</b> average delta.<br/>"
        "<i>Why VaultDB is not 'faster' than raw PostgreSQL:</i> Raw PostgreSQL performs zero security checking, zero query rewriting, and zero audit logging. "
        "pgAudit writes unindexed plaintext strings to a flat syslog file. In exchange for less than 1 millisecond of overhead compared to pgAudit, "
        "VaultDB introduces end-to-end cryptographic Merkle proofs, dynamic SSN masking, and database corruption detection. "
        "This minimal overhead satisfies all enterprise SLA requirements.",
        body_style
    ))

    story.append(Paragraph("Table 5: Security Capability Comparison Matrix", caption_style))
    t5_data = [
        [Paragraph("Security Capability", th_style), Paragraph("Raw PostgreSQL", th_style), Paragraph("PostgreSQL + pgAudit", th_style), Paragraph("VaultDB Middleware", th_style)],
        [Paragraph("Cryptographic Merkle Proofs", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (SHA-256 Roots)", td_bold)],
        [Paragraph("Immutable Append-Only Ledger", td_bold), Paragraph("No (Mutable)", td_style), Paragraph("No (Plaintext files)", td_style), Paragraph("Yes (immudb + Triggers)", td_bold)],
        [Paragraph("In-Flight Dynamic PII Masking", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (SSN Redaction)", td_bold)],
        [Paragraph("Client Identity Spoof Protection", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (JWT/API Key)", td_bold)],
        [Paragraph("Dynamic Row-Level Security (RLS)", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (AST Query Rewrite)", td_bold)],
        [Paragraph("Behavioral Anomaly Alerts", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (4 Rules + Slack)", td_bold)],
        [Paragraph("Certified Compliance PDF Export", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (GDPR/HIPAA PDF)", td_bold)],
    ]
    t5 = Table(t5_data, colWidths=[150, 95, 120, 139])
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t5)
    story.append(Spacer(1, 8))

    # Screenshots Callout
    sc_data = [
        [Paragraph("<b>Figure 1: SQL Console & In-Flight PII Masking</b><br/><i>Demonstrating masked SSN (***-**-1123) and suppressed credentials under Employee persona.</i>", callout_box)],
        [Paragraph("<b>Figure 2: Audit Ledger & Cryptographic Merkle Verification</b><br/><i>Audit Ledger modal verifying SHA-256 Merkle consistency proof against immudb server root state.</i>", callout_box)],
        [Paragraph("<b>Figure 3: Simulated DBA Tamper Detection & Diff Alert</b><br/><i>Tamper alert showing PostgreSQL mirror discrepancy vs. authentic immudb Merkle root.</i>", callout_box)],
        [Paragraph("<b>Figure 4: Certified Compliance PDF Report</b><br/><i>Downloaded PDF compliance report formatted for GDPR Article 30 and HIPAA §164.312 regulatory filings.</i>", callout_box)],
    ]
    t_sc = Table(sc_data, colWidths=[504])
    t_sc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#94a3b8')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_sc)
    story.append(Spacer(1, 6))

    story.append(Paragraph(
        "<b>Quick Setup and Installation Summary (5 Steps):</b><br/>"
        "1. <code>git clone https://github.com/Sejal-hani/Vault_DB.git && cd Vault_DB && python -m venv venv && .\\venv\\Scripts\\activate</code><br/>"
        "2. <code>pip install -r requirements.txt</code><br/>"
        "3. <code>python scripts/init_databases.py</code><br/>"
        "4. <code>.\\bin\\immudb.exe --dir data/immudb --port 3322</code><br/>"
        "5. <code>python server.py</code> (Open http://localhost:8000 in browser)",
        body_style
    ))

    # 7. Limitations and Future Work
    story.append(Paragraph("7. Limitations and Future Work", h1_style))
    story.append(Paragraph(
        "While VaultDB fulfills all V1 specifications and V2 bonus features, several avenues for future work exist: "
        "(1) <b>Distributed Raft Consensus:</b> Deploying multi-region immudb clusters for Byzantine Fault Tolerance; "
        "(2) <b>Cross-DBMS Dialect Support:</b> Extending the AST parser via <code>sqlglot</code> to support MySQL, Snowflake, and Oracle; "
        "(3) <b>Zero-Knowledge Compliance Proofs (zk-SNARKs):</b> Enabling organizations to mathematically prove regulatory compliance to third parties without exposing underlying financial data.",
        body_style
    ))

    # 8. Conclusion
    story.append(Paragraph("8. Conclusion", h1_style))
    story.append(Paragraph(
        "In this project, we designed, implemented, and empirically evaluated VaultDB, an enterprise zero-trust database security middleware and cryptographic audit ledger. "
        "By intercepting database operations at the AST level and coupling PostgreSQL with an append-only immudb Merkle ledger, VaultDB eliminates single points of failure in relational database auditing. "
        "Our empirical evaluation over 15,000 queries confirms that VaultDB introduces an average latency overhead of only <b>0.82 ms over pgAudit</b> and <b>1.58 ms over uninstrumented PostgreSQL</b>, "
        "while sustaining a throughput of <b>322.0 queries/second</b>. VaultDB successfully enforces zero-trust identity derivation, dynamic customer tenant isolation, in-flight PII masking, "
        "and mathematical tamper detection with zero false negatives across 160 automated tests, proving that mathematically verifiable audit integrity can be achieved with negligible operational cost.",
        body_style
    ))

    # 9. Contribution Statement
    story.append(Paragraph("9. Contribution Statement", h1_style))
    t_c_data = [
        [Paragraph("Team Member", th_style), Paragraph("Core Module Responsibilities", th_style), Paragraph("Report Sections Written", th_style), Paragraph("Effort (%)", th_style)],
        [Paragraph("Somya Tomar", td_bold), Paragraph("Middleware Pipeline Architecture, immudb Dual-Storage Connector, PostgreSQL Immutability Triggers, Atomic Counter Synchronization", td_style), Paragraph("Section 1 (Introduction), Section 4 (Architecture), Section 5 (Implementation Challenges)", td_style), Paragraph("33.3%", td_bold)],
        [Paragraph("Vani Shrivastava", td_bold), Paragraph("AST SQL Parser & Injection Firewall, RBAC Matrix Manager, Customer Row-Level Security Rewriter, AES-256-GCM Column Encryption", td_style), Paragraph("Section 2 (Background & Related Work), Section 3 (Requirements), Section 6.1 (Test Plan & Exploit Suite)", td_style), Paragraph("33.3%", td_bold)],
        [Paragraph("Sejal Patil", td_bold), Paragraph("Security Workstation Web Console (FastAPI/JS), Dynamic In-Flight Masking, ReportLab PDF Compliance Generator, 1,000-Query Benchmark Suite", td_style), Paragraph("Section 6.2 (Empirical Evaluation), Section 6.3 (Workstation Workflow), Section 7 & 8 (Limitations & Conclusion)", td_style), Paragraph("33.3%", td_bold)],
    ]
    t_c = Table(t_c_data, colWidths=[90, 175, 175, 64])
    t_c.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_c)
    story.append(Spacer(1, 4))
    story.append(Paragraph("<i>AI Tool Declaration: Generative AI tools were utilized strictly for grammatical refinement and formatting alignment with the IEEE conference style guidelines, in accordance with the course policy.</i>", body_style))

    # 10. References
    story.append(Paragraph("10. References", h1_style))
    refs = [
        "[1] PostgreSQL Global Development Group, 'pgAudit: An Open Source Audit Logging Extension for PostgreSQL,' EnterpriseDB, 2024. [Online]. Available: https://www.pgaudit.org/",
        "[2] Red Hat, 'Debezium: Reliable Change Data Capture for Modern Architectures,' Apache Software Foundation, 2023. [Online]. Available: https://debezium.io/",
        "[3] PlanetScale, 'Vitess: Scalable Cloud-Native Database Architecture for MySQL,' CNCF Graduated Project, 2023. [Online]. Available: https://vitess.io/",
        "[4] Codenotary, 'immudb: Immutable Database with Cryptographic Verification and Merkle Tree Storage,' v1.5 Documentation, 2024. [Online]. Available: https://immudb.io/",
        "[5] M. Stonebraker and A. Weisberg, 'The Architecture of Next-Generation Transaction Processing Systems,' in IEEE Data Engineering Bulletin, vol. 36, no. 2, pp. 4–12, 2013.",
        "[6] European Parliament and Council of the European Union, 'Regulation (EU) 2016/679 (General Data Protection Regulation): Article 15 & Article 30,' Official Journal of the European Union, 2016.",
        "[7] U.S. Department of Health and Human Services, 'Health Insurance Portability and Accountability Act (HIPAA) Security Rule: 45 CFR § 164.312(b) Audit Controls,' HHS.gov, 2013.",
        "[8] PCI Security Standards Council, 'Payment Card Industry Data Security Standard (PCI-DSS): Requirement 10 (Log and Monitor All Access),' Version 4.0, 2022.",
    ]
    for r in refs:
        story.append(Paragraph(r, body_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Generated PDF in docs: {PDF_PATH_DOCS}")

    # Copy to root directory as well
    import shutil
    shutil.copyfile(PDF_PATH_DOCS, PDF_PATH_ROOT)
    print(f"[+] Copied PDF to root: {PDF_PATH_ROOT}")

    if DOCX_PATH_DOCS.exists():
        shutil.copyfile(DOCX_PATH_DOCS, DOCX_PATH_ROOT)
        print(f"[+] Copied DOCX to root: {DOCX_PATH_ROOT}")


if __name__ == "__main__":
    build_pdf()
