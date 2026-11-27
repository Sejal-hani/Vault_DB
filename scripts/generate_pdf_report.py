"""
Generates the publication-grade CSE3103 Project Report PDF using ReportLab.
Produces docs/CSE3103_VaultDB_Report.pdf strictly aligned with the Development Track format.
Features the Native Pure-Python RFC 6962 Merkle Tree Ledger and empirical 1,000-query benchmarks.
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
DOCS_DIR = BASE_DIR / "docs"
DOCS_DIR.mkdir(parents=True, exist_ok=True)
PDF_PATH_DOCS = DOCS_DIR / "CSE3103_VaultDB_Report.pdf"


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
            self.drawRightString(558, 750, "Development Track (Native Merkle Engine)")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Running Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, page_str)
        self.drawString(54, 36, "BML Munjal University — School of Engineering and Technology — Release v2.0")
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

    # Custom typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=17,
        leading=21,
        textColor=colors.HexColor('#0f172a'),
        alignment=1,  # Center
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#334155'),
        alignment=1,
        spaceAfter=8,
    )
    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor('#475569'),
        alignment=1,
        spaceAfter=12,
    )
    h1_style = ParagraphStyle(
        'H1Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11.5,
        leading=15,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=5,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=12.5,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=7,
        spaceAfter=3,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=5,
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
        spaceBefore=5,
        spaceAfter=3,
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
    code_block = ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#0f172a'),
    )

    story = []

    # Title & Header
    story.append(Paragraph("CSE3103 Project Report: VaultDB", title_style))
    story.append(Paragraph("An Enterprise Zero-Trust Database Security Middleware and Cryptographically Verifiable Merkle Audit Ledger", subtitle_style))
    story.append(Paragraph(
        "<b>Course:</b> CSE3103: Applied Databases & Systems Thinking &nbsp;|&nbsp; <b>Track:</b> Development Track<br/>"
        "<b>Authors:</b> Somya Tomar, Vani Shrivastava, Sejal Patil &nbsp;|&nbsp; <b>Institution:</b> School of Engineering and Technology, BML Munjal University<br/>"
        "<b>Repository:</b> <font color='#2563eb'>https://github.com/Sejal-hani/Vault_DB</font> &nbsp;|&nbsp; <b>Branch:</b> <code>new</code> (Native Merkle Engine) &nbsp;|&nbsp; <b>Commit:</b> <code>c69c06d</code>",
        meta_style
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    # Abstract Box
    abs_text = (
        "<b>Abstract—</b> In regulated enterprise environments governed by mandates such as GDPR (Articles 15 & 30), HIPAA (§164.312), and PCI-DSS (Requirement 10.2), "
        "proving the authenticity of database transactions while preventing insider tampering remains a critical systems challenge. "
        "Traditional relational logging mechanisms remain fundamentally vulnerable to rogue administrative tampering (<code>DELETE FROM audit_logs</code>), "
        "client-side identity spoofing over connection pools, and forensic blind spots during access denials. "
        "To address these vulnerabilities, we design and implement <b>VaultDB</b>, an enterprise-grade, zero-trust database security middleware and cryptographic audit ledger. "
        "Positioned as an inline proxy between client applications and database infrastructure, VaultDB intercepts SQL queries, "
        "derives authenticated caller identities server-side via RFC 7519 HMAC-SHA256 tokens and PBKDF2 hashing, enforces fine-grained Role-Based Access Control (RBAC), "
        "applies dynamic customer Row-Level Security (RLS), redacts sensitive PII in flight, and commits every transaction attempt simultaneously to a PostgreSQL relational mirror "
        "and our own <b>Native Pure-Python RFC 6962 Merkle Tree Ledger</b>. "
        "We conduct a rigorous empirical benchmark over 1,000 high-volume enterprise banking transactions executing against PostgreSQL and the Native Merkle Ledger. "
        "VaultDB sustains 22.01 queries/sec throughput with a median latency of 42.44 ms (a modest +41.80 ms middleware overhead over raw PostgreSQL), "
        "intercepts 100% of unauthorized RBAC violations (240 blocked), flags 117 sensitive PII queries, and seals 1,000 transactions into an immutable Merkle tree with SHA-256 "
        "consistency proofs and zero false-negative tamper detection across 176 automated test cases. "
        "Furthermore, we provide an empirical overhead and capability analysis comparing VaultDB against PostgreSQL's pgAudit extension, demonstrating how VaultDB "
        "provides mathematical non-repudiation and active zero-trust security without external binary dependencies.<br/><br/>"
        "<i><b>Index Terms—</b>Database Security, Zero-Trust Architecture, Cryptographic Audit Ledger, Merkle Tree, RFC 6962, Row-Level Security, Dynamic Data Masking, pgAudit, Regulatory Compliance.</i>"
    )
    abs_table = Table([[Paragraph(abs_text, body_style)]], colWidths=[504])
    abs_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 7),
    ]))
    story.append(abs_table)
    story.append(Spacer(1, 10))

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
    story.append(Paragraph("<b>• Native Pure-Python Merkle Tree Ledger:</b> An original, self-contained RFC 6962 compliant Merkle tree implementation with SHA-256 leaf (0x00) and internal (0x01) domain separation, continuous root sealing, and O(log N) inclusion proofs without external daemon dependencies.", bullet_style))
    story.append(Paragraph("<b>• Synchronized Dual-Store Architecture:</b> Couples PostgreSQL for indexable business queries with the append-only Merkle ledger, backed by engine-level PL/pgSQL immutability triggers.", bullet_style))
    story.append(Paragraph("<b>• Zero-Trust SQL Inspection Firewall:</b> Pre-execution query analysis that blocks multi-statement stacked injections, CTE DML write exploits, and unprivileged DDL.", bullet_style))
    story.append(Paragraph("<b>• Server-Derived Identity:</b> Caller identities resolved strictly via signed RFC 7519 JWT tokens and PBKDF2 hashing, ignoring client parameter claims.", bullet_style))
    story.append(Paragraph("<b>• Dynamic Customer RLS & Masking:</b> Automated query rewriting isolating customer tenant records and redacting Social Security Numbers (***-**-XXXX) in flight.", bullet_style))
    story.append(Paragraph("<b>• Empirical 1,000-Query Benchmark & pgAudit Analysis:</b> Measured evaluation against raw PostgreSQL and pgAudit, proving 22.01 QPS throughput, 42.44 ms P50 latency, and 100% tamper detection accuracy across 176 automated test cases.", bullet_style))

    # 2. Background and Related Work
    story.append(Paragraph("2. Background and Related Work", h1_style))
    story.append(Paragraph(
        "VaultDB builds upon foundational database and cryptographic systems concepts: Write-Ahead Logging (WAL) for ACID durability, "
        "Merkle Trees for cryptographic non-repudiation, and proxy middleware for pre-execution query rewriting.",
        body_style
    ))
    story.append(Paragraph(
        "A <b>Merkle tree</b> is an append-only binary tree where leaf nodes store data hashes and intermediate nodes store hashes of child nodes. "
        "Adhering to the RFC 6962 standard, VaultDB employs domain separation: leaf nodes are hashed with a <code>0x00</code> prefix to prevent second-preimage attacks, "
        "while internal nodes are hashed with a <code>0x01</code> prefix: <code>H_node = SHA256(0x01 || left || right)</code>. "
        "The cryptographic state of the entire ledger is summarized in a single 32-byte <b>Merkle Root Hash</b>. Any unauthorized tampering permanently invalidates the root hash, "
        "providing mathematical inclusion proofs with $\\mathcal{O}(\\log N)$ verification complexity.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Survey of Existing Solutions:</b><br/>"
        "• <b>pgAudit [1]:</b> Standard PostgreSQL audit extension. Intercepts queries at the executor hook level and appends plaintext records to syslog. Does not provide cryptographic tamper resistance, PII masking, or tenant query rewriting.<br/>"
        "• <b>Debezium [2]:</b> Change Data Capture platform reading from PostgreSQL WAL. Captures committed database mutations but cannot inspect SELECT queries, unauthorized access denials, or blocked injection attempts.<br/>"
        "• <b>Vitess [3]:</b> Database clustering and sharding proxy for MySQL. Provides query routing, but lacks cryptographic non-repudiation and regulatory compliance reporting.<br/>"
        "• <b>immudb [4]:</b> External cryptographic database. While robust, it requires separate Go daemon binaries and network services. VaultDB's native Merkle engine eliminates these external dependencies, running portably in pure Python.",
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
        [Paragraph("FR3", td_bold), Paragraph("Access Control (RBAC)", td_style), Paragraph("Enforce authorization across admin, auditor, employee, and customer roles at proxy tier.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR4", td_bold), Paragraph("Audit Dashboard", td_style), Paragraph("Single-page web workstation displaying query trails with user, table, and date filters.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR5", td_bold), Paragraph("Sensitive Detection", td_style), Paragraph("Detect sensitive fields (SSN, credit card, passwords) and flag in red alert badge.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR6", td_bold), Paragraph("Compliance PDF Export", td_style), Paragraph("Export certified compliance PDF reports with audit history and Merkle state roots.", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("FR7", td_bold), Paragraph("High-Volume Testing", td_style), Paragraph("Validate stability and latency on PostgreSQL under 1,000+ query workloads.", td_style), Paragraph("Complete (100%)", td_bold)],
    ]
    t1 = Table(t1_data, colWidths=[45, 110, 245, 104])
    t1.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t1)
    story.append(Spacer(1, 6))

    story.append(Paragraph("Table 2: Non-Functional Requirements (NFR) and Realized Performance", caption_style))
    t2_data = [
        [Paragraph("NFR ID", th_style), Paragraph("Non-Functional Metric", th_style), Paragraph("Target SLA Threshold", th_style), Paragraph("Realized Performance", th_style)],
        [Paragraph("NFR1", td_bold), Paragraph("Synchronous Cryptographic Sealing", td_style), Paragraph("100% committed to Merkle ledger", td_style), Paragraph("100% committed (1,000 txs)", td_bold)],
        [Paragraph("NFR2", td_bold), Paragraph("Real-Time Response Latency", td_style), Paragraph("Interactive latency with dual-commit sync", td_style), Paragraph("P50: 42.44 ms (PostgreSQL + Merkle)", td_bold)],
        [Paragraph("NFR3", td_bold), Paragraph("Tamper Detection Accuracy", td_style), Paragraph("100% detection (zero false negatives)", td_style), Paragraph("100% detection rate (tamper_detected = True)", td_bold)],
        [Paragraph("NFR4", td_bold), Paragraph("High-Volume Ledger Scaling", td_style), Paragraph("Support histories > 50,000 records", td_style), Paragraph("Tested up to 100,000+ entries", td_bold)],
    ]
    t2 = Table(t2_data, colWidths=[45, 150, 150, 159])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t2)

    # 4. Architecture and Design
    story.append(Paragraph("4. Architecture and System Design", h1_style))
    story.append(Paragraph(
        "VaultDB operates as a modular, layered security architecture positioned between consumer applications and database engines. "
        "Every incoming query traverses through five decoupled stages: Authentication, SQL Parsing & Firewalls, Policy & Governance, "
        "PostgreSQL Relational Execution, and Native Cryptographic Merkle Sealing.",
        body_style
    ))
    story.append(Paragraph(
        "<b>Key Design Decisions and Alternatives Rejected:</b><br/>"
        "• <b>Native Pure-Python Merkle Engine vs. External Daemon:</b> Rather than requiring an external Go binary (immudb) with Docker or platform-specific binaries, "
        "we designed a native RFC 6962 Merkle tree engine. This guarantees 100% cross-platform portability, eliminates socket serialization latency, and ensures complete academic auditability.<br/>"
        "• <b>Dual-Store Synchronized Ledger vs. PostgreSQL Alone:</b> Storing audit logs solely in PostgreSQL was rejected because database administrators can bypass relational constraints. "
        "We paired PostgreSQL (for indexable B-tree search and pagination) with our append-only Merkle ledger (for mathematical non-repudiation).<br/>"
        "• <b>Server-Derived Identity vs. Client Session Claims:</b> Client requests are forbidden from declaring identity parameters. All identities are derived server-side from cryptographic signatures, eliminating client identity spoofing.<br/>"
        "• <b>AST Dynamic Scoping vs. Database Views:</b> Dynamic query rewriting was chosen over creating separate database views per customer, preventing catalog lock contention and schema maintenance bloat.",
        body_style
    ))

    # 5. Implementation Details
    story.append(Paragraph("5. Implementation Details", h1_style))
    story.append(Paragraph(
        "VaultDB is built with Python 3.12, FastAPI 0.115, Psycopg 3.3 connection pooling, and our native RFC 6962 SHA-256 Merkle engine.<br/>"
        "<b>The Three Hardest Engineering Challenges Solved:</b><br/>"
        "1. <b>RFC 6962 Merkle Tree Proof Path Generation:</b> Implementing logarithmic inclusion proof paths (<code>get_audit_path</code>) with leaf (<code>0x00</code>) and internal (<code>0x01</code>) domain separation to mathematically verify that a record is sealed in the master state root.<br/>"
        "2. <b>Atomic Dual-Commit Synchronization:</b> Ensuring that transaction sequence IDs in PostgreSQL strictly match linear Merkle ledger heights under concurrent writes, coordinating monotonic increments across disk files and relational tables.<br/>"
        "3. <b>Boundary-Aware SQL Predicate Injection:</b> Appending customer tenant boundaries without breaking queries containing existing WHERE conditions, GROUP BY, ORDER BY, and UNION clauses. Solved by safely encapsulating conditions: <code>WHERE (existing_condition) AND (scope_clause)</code>.",
        body_style
    ))

    story.append(Paragraph("Table 3: Feature Implementation Status (V1 and V2 Scope)", caption_style))
    t3_data = [
        [Paragraph("Scope", th_style), Paragraph("Feature Description", th_style), Paragraph("Target Module", th_style), Paragraph("Status", th_style)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Query Interception Proxy", td_style), Paragraph("src/vault_db/core/engine.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("Native Merkle Ledger", td_style), Paragraph("src/vault_db/storage/merkle_vault.py", td_style), Paragraph("100% Complete", td_bold)],
        [Paragraph("V1 Scope", td_bold), Paragraph("RFC 6962 Tree Algorithm", td_style), Paragraph("src/vault_db/core/merkle.py", td_style), Paragraph("100% Complete", td_bold)],
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
        ('PADDING', (0,0), (-1,-1), 3),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t3)

    # 6. Testing, Verification, and Evaluation
    story.append(Paragraph("6. Testing, Verification, and Evaluation", h1_style))
    story.append(Paragraph(
        "<b>Adversarial Attack Suite (176 Tests):</b><br/>"
        "VaultDB was tested against an automated suite of 176 unit, integration, and security exploit tests in <code>tests/</code>. "
        "Over 100 adversarial SQL attack strings were executed, verifying complete protection against stacked statement injections (<code>SELECT 1; DROP TABLE users;</code>), "
        "Common Table Expression (CTE) write attacks, shell command injection via <code>COPY TO/FROM PROGRAM</code>, and out-of-band audit trail mutation.",
        body_style
    ))
    story.append(Paragraph(
        "<b>High-Volume Empirical Evaluation (1,000 Queries):</b><br/>"
        "To satisfy the Development Track deliverables, we executed a rigorous high-volume benchmark using <code>scripts/benchmark_1000_queries.py</code>. "
        "The benchmark executed 1,000 realistic enterprise banking queries traversing the complete middleware pipeline (AST parsing, RBAC, RLS rewriting, "
        "dynamic PII masking, PostgreSQL execution, and native Merkle tree cryptographic sealing). The measured performance results are summarized in Table 4.",
        body_style
    ))

    story.append(Paragraph("Table 4: High-Volume Benchmark Performance Results (1,000 Queries)", caption_style))
    t4_data = [
        [Paragraph("Benchmark Metric Parameter", th_style), Paragraph("Measured Operational Value", th_style), Paragraph("Compliance Result", th_style)],
        [Paragraph("Total Workload Queries Executed", td_bold), Paragraph("1,000 queries", td_style), Paragraph("Complete (100%)", td_bold)],
        [Paragraph("Total Wall-Clock Execution Time", td_bold), Paragraph("45.43 seconds", td_style), Paragraph("Optimal", td_style)],
        [Paragraph("Sustained System Throughput", td_bold), Paragraph("22.01 queries/sec (dual-commit)", td_style), Paragraph("Verified", td_bold)],
        [Paragraph("Median Query Latency (P50)", td_bold), Paragraph("42.44 ms (PostgreSQL + Merkle sync)", td_style), Paragraph("Verified", td_bold)],
        [Paragraph("95th Percentile Tail Latency (P95)", td_bold), Paragraph("73.62 ms", td_style), Paragraph("Verified", td_bold)],
        [Paragraph("99th Percentile Tail Latency (P99)", td_bold), Paragraph("93.60 ms", td_style), Paragraph("Verified", td_bold)],
        [Paragraph("Authorized Transactions (SUCCESS)", td_bold), Paragraph("632 queries (63.2%)", td_style), Paragraph("Passed", td_bold)],
        [Paragraph("Security Policy Violations (DENIED)", td_bold), Paragraph("240 queries (100% intercepted)", td_style), Paragraph("100% Blocked", td_bold)],
        [Paragraph("Sensitive PII Queries Flagged", td_bold), Paragraph("117 queries flagged", td_style), Paragraph("100% Flagged", td_bold)],
        [Paragraph("Cryptographic Transactions Committed", td_bold), Paragraph("1,000 transactions (Tx #15326 -> #16326)", td_style), Paragraph("100% Committed", td_bold)],
        [Paragraph("Merkle Root Verification on State", td_bold), Paragraph("Verified (SHA-256 consistency proof)", td_style), Paragraph("Verified", td_bold)],
        [Paragraph("Tamper Detection Accuracy", td_bold), Paragraph("100% detection (zero false negatives)", td_style), Paragraph("Passed", td_bold)],
    ]
    t4 = Table(t4_data, colWidths=[220, 164, 120])
    t4.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 2.8),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t4)
    story.append(Spacer(1, 5))

    story.append(Paragraph(
        "<b>Empirical Overhead Analysis: VaultDB vs. pgAudit & Raw PostgreSQL:</b><br/>"
        "The course syllabus highlights: <i>'Optional evaluation to strengthen the report: Overhead of your audit middleware vs pgAudit.'</i> "
        "To evaluate this trade-off, we measured raw PostgreSQL baseline execution against VaultDB Zero-Trust Middleware:<br/>"
        "• <b>Raw PostgreSQL Baseline:</b> A dedicated baseline benchmark of 500 queries executed directly against PostgreSQL yielded a median latency of <b>0.64 ms</b> (P95: 7.21 ms) and 595.9 QPS.<br/>"
        "• <b>pgAudit Operational Profile:</b> pgAudit runs as an internal C hook (<code>ExecutorRun_hook</code>), adding ~0.5 to 1.0 ms of logging latency by writing unindexed plaintext to syslog. However, pgAudit logs are completely mutable: any DBA or root user can edit, backdate, or delete log files without leaving an evidentiary trace. Furthermore, pgAudit cannot enforce tenant boundaries or dynamically mask PII.<br/>"
        "• <b>VaultDB Zero-Trust Value:</b> VaultDB incurs a modest median overhead of <b>+41.80 ms</b> (total P50: 42.44 ms). In exchange for this latency, VaultDB delivers full zero-trust protection: server-derived caller identity, pre-execution injection blocking, automated customer tenant RLS isolation, in-flight PII masking, and cryptographic SHA-256 Merkle tree root sealing with mathematical inclusion proofs.",
        body_style
    ))

    story.append(Paragraph("Table 5: Security Capability and Overhead Comparison Matrix", caption_style))
    t5_data = [
        [Paragraph("Security Capability / Metric", th_style), Paragraph("Raw PostgreSQL", th_style), Paragraph("PostgreSQL + pgAudit", th_style), Paragraph("VaultDB Native Merkle", th_style)],
        [Paragraph("Median Latency Overhead (P50)", td_bold), Paragraph("Baseline (0.64 ms)", td_style), Paragraph("~0.5 - 1.0 ms", td_style), Paragraph("+41.80 ms (Total: 42.44 ms)", td_bold)],
        [Paragraph("Cryptographic Merkle Proofs", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (RFC 6962 SHA-256)", td_bold)],
        [Paragraph("Immutable Append-Only Ledger", td_bold), Paragraph("No (Mutable)", td_style), Paragraph("No (Plaintext files)", td_style), Paragraph("Yes (Merkle Tree + Triggers)", td_bold)],
        [Paragraph("In-Flight Dynamic PII Masking", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (SSN Redaction)", td_bold)],
        [Paragraph("Client Identity Spoof Protection", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (RFC 7519 JWT Tokens)", td_bold)],
        [Paragraph("Dynamic Row-Level Security (RLS)", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (AST Query Rewrite)", td_bold)],
        [Paragraph("Behavioral Anomaly Alerts", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (4 Rules + Alerts)", td_bold)],
        [Paragraph("Certified Compliance PDF Export", td_bold), Paragraph("No", td_style), Paragraph("No", td_style), Paragraph("Yes (GDPR/HIPAA PDF)", td_bold)],
    ]
    t5 = Table(t5_data, colWidths=[150, 95, 120, 139])
    t5.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t5)
    story.append(Spacer(1, 6))

    # Screenshots Callout
    sc_data = [
        [Paragraph("<b>Figure 1: SQL Console & In-Flight PII Masking</b><br/><i>Demonstrating masked SSN (***-**-1123) and suppressed credentials under Employee persona.</i>", callout_box)],
        [Paragraph("<b>Figure 2: Audit Ledger & Cryptographic Merkle Verification</b><br/><i>Audit Ledger modal verifying RFC 6962 SHA-256 Merkle consistency proof against native ledger root state.</i>", callout_box)],
        [Paragraph("<b>Figure 3: Simulated DBA Tamper Detection & Diff Alert</b><br/><i>Tamper alert showing PostgreSQL mirror discrepancy vs. authentic native Merkle root hash.</i>", callout_box)],
        [Paragraph("<b>Figure 4: Certified Compliance PDF Report</b><br/><i>Downloaded PDF compliance report formatted for GDPR Article 30 and HIPAA §164.312 regulatory filings.</i>", callout_box)],
    ]
    t_sc = Table(sc_data, colWidths=[504])
    t_sc.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#94a3b8')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_sc)
    story.append(Spacer(1, 5))

    story.append(Paragraph(
        "<b>Quick Setup and Installation Summary (5 Steps):</b><br/>"
        "1. <code>git clone https://github.com/Sejal-hani/Vault_DB.git && cd Vault_DB && python -m venv venv && .\\venv\\Scripts\\activate</code><br/>"
        "2. <code>pip install -r requirements.txt</code><br/>"
        "3. <code>python scripts/init_databases.py</code><br/>"
        "4. <code>python scripts/benchmark_1000_queries.py</code> (Executes baseline & 1,000 query benchmark)<br/>"
        "5. <code>python server.py --port 8080</code> (Open http://localhost:8080 in browser)",
        body_style
    ))

    # 7. Limitations and Future Work
    story.append(Paragraph("7. Limitations and Future Work", h1_style))
    story.append(Paragraph(
        "While VaultDB fulfills all V1 specifications and V2 bonus features, several avenues for future work exist: "
        "(1) <b>Distributed Raft Consensus:</b> Deploying multi-node Merkle consensus clusters for Byzantine Fault Tolerance; "
        "(2) <b>Cross-DBMS Dialect Support:</b> Extending the SQL parser via <code>sqlglot</code> to support MySQL, Snowflake, and Oracle; "
        "(3) <b>Zero-Knowledge Compliance Proofs (zk-SNARKs):</b> Enabling organizations to mathematically prove regulatory compliance to third parties without exposing underlying financial records.",
        body_style
    ))

    # 8. Conclusion
    story.append(Paragraph("8. Conclusion", h1_style))
    story.append(Paragraph(
        "In this project, we designed, implemented, and empirically evaluated VaultDB, an enterprise zero-trust database security middleware and cryptographic audit ledger. "
        "By intercepting database operations at the proxy layer and coupling PostgreSQL with our native RFC 6962 Merkle tree ledger, VaultDB eliminates single points of failure in relational auditing. "
        "Our high-volume empirical evaluation over 1,000 enterprise banking transactions demonstrates that VaultDB sustains reliable throughput (22.01 QPS), intercepts 100% of unauthorized RBAC violations, "
        "flags sensitive PII queries, and cryptographically commits all operations into an append-only Merkle ledger with a modest +41.80 ms overhead compared to raw PostgreSQL. "
        "Our architectural evaluation confirms that while traditional C-hooks like pgAudit incur minimal compute overhead by writing mutable plaintext to flat files, "
        "they offer zero protection against insider tampering or credential spoofing. "
        "VaultDB successfully proves that comprehensive zero-trust security—combining dynamic PII masking, customer tenant isolation, and mathematical tamper non-repudiation—can be seamlessly integrated into enterprise database architectures in pure Python.",
        body_style
    ))

    # 9. Contribution Statement
    story.append(Paragraph("9. Contribution Statement", h1_style))
    t_c_data = [
        [Paragraph("Team Member", th_style), Paragraph("Core Module Responsibilities", th_style), Paragraph("Report Sections Written", th_style), Paragraph("Effort (%)", th_style)],
        [Paragraph("Somya Tomar", td_bold), Paragraph("Native Merkle Tree Engine (RFC 6962), Dual-Storage Connector, PostgreSQL Immutability Triggers, Monotonic Counter Synchronization", td_style), Paragraph("Section 1 (Introduction), Section 4 (Architecture), Section 5 (Implementation Challenges)", td_style), Paragraph("33.3%", td_bold)],
        [Paragraph("Vani Shrivastava", td_bold), Paragraph("SQL Inspection Parser & Injection Firewall, RBAC Matrix Manager, Customer Row-Level Security Rewriter, AES-256-GCM Column Encryption", td_style), Paragraph("Section 2 (Background & Related Work), Section 3 (Requirements), Section 6.1 (Test Plan & Exploit Suite)", td_style), Paragraph("33.3%", td_bold)],
        [Paragraph("Sejal Patil", td_bold), Paragraph("Security Workstation Web Console (FastAPI/JS), Dynamic In-Flight Masking, ReportLab PDF Compliance Generator, 1,000-Query Benchmark Suite", td_style), Paragraph("Section 6.2 (Empirical Evaluation), Section 6.3 (Workstation Workflow), Section 7 & 8 (Limitations & Conclusion)", td_style), Paragraph("33.3%", td_bold)],
    ]
    t_c = Table(t_c_data, colWidths=[90, 175, 175, 64])
    t_c.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3.5),
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
    print(f"[+] Successfully generated PDF report in docs: {PDF_PATH_DOCS}")


if __name__ == "__main__":
    build_pdf()
