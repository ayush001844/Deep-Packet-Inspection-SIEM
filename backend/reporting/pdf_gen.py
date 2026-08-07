"""
PDF Reporting Engine
====================
Generates PDF reports of incidents and system status.
"""

from __future__ import annotations

import os
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from backend.db.database import get_session, Incident, Alert

def generate_incident_report(incident_id: str) -> str:
    """Generate a PDF report for a specific incident."""
    session = get_session()
    try:
        incident = session.query(Incident).filter(Incident.incident_id == incident_id).first()
        if not incident:
            return ""

        filename = f"/tmp/{incident_id}_report.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        heading_style = styles['Heading2']
        normal_style = styles['Normal']

        story = []
        
        # Header
        story.append(Paragraph("SOC/SIEM Incident Report", title_style))
        story.append(Paragraph(f"<b>Incident ID:</b> {incident.incident_id}", normal_style))
        story.append(Paragraph(f"<b>Title:</b> {incident.title}", normal_style))
        story.append(Paragraph(f"<b>Severity:</b> {incident.severity.upper()}", normal_style))
        story.append(Paragraph(f"<b>Status:</b> {incident.status.upper()}", normal_style))
        story.append(Paragraph(f"<b>Generated At:</b> {time.ctime()}", normal_style))
        story.append(Spacer(1, 20))
        
        # Description
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(Paragraph(incident.description, normal_style))
        story.append(Spacer(1, 20))

        # Alerts Table
        story.append(Paragraph("Correlated Alerts", heading_style))
        
        alerts = session.query(Alert).filter(Alert.id.in_(incident.alert_ids)).order_by(Alert.timestamp.asc()).all()
        
        data = [["Time", "Severity", "Source", "Target", "MITRE"]]
        for a in alerts:
            dt = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a.timestamp))
            data.append([
                dt,
                a.severity.upper(),
                a.src_ip or "N/A",
                a.dst_ip or "N/A",
                a.mitre_technique or "N/A"
            ])
            
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        story.append(table)
        
        # Build PDF
        doc.build(story)
        return filename
        
    finally:
        session.close()
